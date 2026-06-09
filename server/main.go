// Command server is the user-side secrets endpoint for the example-secret-keys
// POC. It listens on /fetch, verifies the booting workload's SEV-SNP attestation
// against the sigstore-attested measurement of this repo, checks the shared POC
// password, and HPKE-seals the requested secrets to the workload's per-boot
// public key (which the SNP quote vouches for via REPORTDATA).
//
// Run locally, expose via ngrok (or similar), and put the public URL into
// ../external-config.yml's `vault.url`. See ./README.md.
package main

import (
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
	"github.com/tinfoilsh/tinfoil-go/verifier/github"
	"github.com/tinfoilsh/tinfoil-go/verifier/sigstore"
)

// pocPassword must match cvmimage/tinfoil/cmd/boot/vault.go's constant.
// Anyone with cvmimage source can read this — that's the POC tradeoff; the
// real version moves it to per-account injection by tinfoild.
const pocPassword = "poc-shared-secret-do-not-use"

// fetchInfo is the HPKE info string bound into both seal and open; must match
// cvmimage's vault.go.
const fetchInfo = "tinfoil-secrets-vault/fetch/v1"

// workloadRepo is the only repo this server releases secrets for. Hardcoded
// because this server is the trust anchor for one workload's deployment.
const workloadRepo = "tinfoilsh/example-secret-keys"

type fetchRequest struct {
	Repo       string              `json:"repo"`
	SecretRefs []string            `json:"secret_refs"`
	Bundle     *attestation.Bundle `json:"bundle"`
	Password   string              `json:"password"`
}

type fetchResponse struct {
	Enc        []byte `json:"enc"`
	Ciphertext []byte `json:"ciphertext"`
}

func main() {
	addr := flag.String("addr", ":8099", "listen address")
	secretsPath := flag.String("secrets", "secrets.json", `path to a JSON map of secrets, e.g. {"EXAMPLE_KEY":"value"}`)
	flag.Parse()

	secrets, err := loadSecrets(*secretsPath)
	if err != nil {
		log.Fatalf("loading secrets: %v", err)
	}

	sigClient, err := sigstore.NewClient()
	if err != nil {
		log.Fatalf("sigstore client: %v", err)
	}

	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	http.HandleFunc("/fetch", handleFetch(secrets, sigClient))

	log.Printf("example-secret-keys server listening on %s (repo=%s)", *addr, workloadRepo)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

func loadSecrets(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var secrets map[string]string
	if err := json.Unmarshal(data, &secrets); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return secrets, nil
}

func handleFetch(secrets map[string]string, sigClient *sigstore.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req fetchRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.Password != pocPassword {
			log.Printf("rejected: bad password")
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if req.Repo != workloadRepo {
			log.Printf("rejected: claimed repo %q != %q", req.Repo, workloadRepo)
			http.Error(w, "forbidden: repo not served", http.StatusForbidden)
			return
		}
		if req.Bundle == nil || req.Bundle.EnclaveAttestationReport == nil {
			http.Error(w, "missing attestation", http.StatusBadRequest)
			return
		}

		pkW, err := verifyEnclave(sigClient, req.Repo, req.Bundle)
		if err != nil {
			log.Printf("rejected: %v", err)
			http.Error(w, "forbidden: "+err.Error(), http.StatusForbidden)
			return
		}

		released := filterSecrets(secrets, req.SecretRefs)
		plaintext, err := json.Marshal(released)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		enc, ct, err := sealTo(pkW, plaintext)
		if err != nil {
			http.Error(w, "internal error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("released %d/%d secret(s) for %s: %v", len(released), len(req.SecretRefs), req.Repo, req.SecretRefs)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fetchResponse{Enc: enc, Ciphertext: ct})
	}
}

// verifyEnclave mirrors SecureClient.VerifyFromBundle's chain but on the small
// Bundle cvmimage sends (just the SNP report + optional digest): sigstore
// proves the repo built to measurement M; the SNP quote proves the enclave is
// running M and holds pk_W in REPORTDATA. Returns the hardware-attested pk_W.
func verifyEnclave(sigClient *sigstore.Client, repo string, bundle *attestation.Bundle) (string, error) {
	digest := bundle.Digest
	var err error
	if digest == "" {
		digest, err = github.FetchLatestDigest(repo)
		if err != nil {
			return "", fmt.Errorf("latest digest: %w", err)
		}
	}
	sigBundle := bundle.SigstoreBundle
	if len(sigBundle) == 0 || string(sigBundle) == "null" {
		sigBundle, err = github.FetchAttestationBundle(repo, digest)
		if err != nil {
			return "", fmt.Errorf("fetch sigstore bundle: %w", err)
		}
	}
	codeMeasurement, err := sigClient.VerifyAttestation(sigBundle, repo, digest)
	if err != nil {
		return "", fmt.Errorf("sigstore: %w", err)
	}

	enclaveVerification, err := bundle.EnclaveAttestationReport.VerifyWithVCEK(nil)
	if err != nil {
		return "", fmt.Errorf("snp quote: %w", err)
	}

	if err := codeMeasurement.Equals(enclaveVerification.Measurement); err != nil {
		return "", fmt.Errorf("measurement mismatch: %w", err)
	}
	if enclaveVerification.HPKEPublicKey == "" {
		return "", fmt.Errorf("quote carries no HPKE key in REPORTDATA")
	}
	return enclaveVerification.HPKEPublicKey, nil
}

func filterSecrets(all map[string]string, names []string) map[string]string {
	out := make(map[string]string, len(names))
	for _, n := range names {
		if v, ok := all[n]; ok {
			out[n] = v
		}
	}
	return out
}

// sealTo HPKE-seals plaintext to the workload's per-boot public key (raw X25519,
// hex-encoded). Suite: RFC 9180 X25519 / HKDF-SHA256 / AES-256-GCM — matches
// the circl-based receiver in cvmimage's vault.go.
func sealTo(pkHex string, plaintext []byte) (enc, ct []byte, err error) {
	pkBytes, err := hex.DecodeString(pkHex)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding pk_w: %w", err)
	}
	pk, err := hpke.DHKEM(ecdh.X25519()).NewPublicKey(pkBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing pk_w: %w", err)
	}
	enc, sender, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(fetchInfo))
	if err != nil {
		return nil, nil, err
	}
	ct, err = sender.Seal(nil, plaintext)
	if err != nil {
		return nil, nil, err
	}
	return enc, ct, nil
}
