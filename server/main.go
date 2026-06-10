// Command server is the user-side secrets endpoint. It listens on /fetch,
// verifies the bearer token, looks up the requesting workload's repo in the
// server-side allowlist, verifies the booting workload's SEV-SNP attestation
// against the sigstore-attested measurement of that repo, and HPKE-seals the
// requested secrets to the workload's per-boot public key (which the SNP
// quote vouches for via REPORTDATA).
//

package main

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
	"github.com/tinfoilsh/tinfoil-go/verifier/github"
	"github.com/tinfoilsh/tinfoil-go/verifier/sigstore"
)

// fetchInfo is the HPKE info string bound into both seal and open; must match
// cvmimage's vault.go.
const fetchInfo = "tinfoil-secrets-vault/fetch/v1"

type fetchRequest struct {
	Repo       string              `json:"repo"`
	SecretRefs []string            `json:"secret_refs"`
	Bundle     *attestation.Bundle `json:"bundle"`
	Token      string              `json:"token"`
}

type fetchResponse struct {
	Enc        []byte `json:"enc"`
	Ciphertext []byte `json:"ciphertext"`
}

func main() {
	addr := flag.String("addr", ":8099", "listen address")
	secretsPath := flag.String("secrets", "secrets.json", `path to a JSON map keyed by repo, e.g. {"tinfoilsh/example-secret-keys": {"EXAMPLE_KEY": "value"}}`)
	tokenFlag := flag.String("token", "", "shared bearer token (or set VAULT_TOKEN env)")
	insecureSkipAttestation := flag.Bool("insecure-skip-attestation", false,
		"DEV ONLY: skip sigstore code-identity check. SNP quote + HPKE seal are still verified, "+
			"but the booted enclave is not bound to a published release of any repo.")
	flag.Parse()

	token := *tokenFlag
	if token == "" {
		token = os.Getenv("VAULT_TOKEN")
	}
	if token == "" {
		log.Fatalf("--token flag or VAULT_TOKEN env required")
	}

	repos, err := loadSecrets(*secretsPath)
	if err != nil {
		log.Fatalf("loading secrets: %v", err)
	}
	if len(repos) == 0 {
		log.Fatalf("no repos configured in %s", *secretsPath)
	}

	sigClient, err := sigstore.NewClient()
	if err != nil {
		log.Fatalf("sigstore client: %v", err)
	}

	if *insecureSkipAttestation {
		log.Printf("WARNING: --insecure-skip-attestation set; releasing secrets to ANY SNP-attested enclave (dev only)")
	}

	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	http.HandleFunc("/fetch", handleFetch(repos, token, sigClient, *insecureSkipAttestation))

	log.Printf("vault server listening on %s", *addr)
	for repo, secrets := range repos {
		log.Printf("  serving %s (%d secrets)", repo, len(secrets))
	}
	log.Fatal(http.ListenAndServe(*addr, nil))
}

func loadSecrets(path string) (map[string]map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var repos map[string]map[string]string
	if err := json.Unmarshal(data, &repos); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return repos, nil
}

func handleFetch(repos map[string]map[string]string, token string, sigClient *sigstore.Client, skipAttestation bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		from := r.RemoteAddr
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			from = xff + " (via " + r.RemoteAddr + ")"
		}
		log.Printf("/fetch %s from %s", r.Method, from)

		if r.Method != http.MethodPost {
			log.Printf("  rejected: method %s not allowed", r.Method)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			log.Printf("  rejected: read body: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		log.Printf("  body: %d bytes", len(body))

		var req fetchRequest
		if err := json.Unmarshal(body, &req); err != nil {
			log.Printf("  rejected: decode body: %v (first 200 bytes: %s)", err, snippet(body, 200))
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		log.Printf("  claim: repo=%q secret_refs=%v token=%q", req.Repo, req.SecretRefs, req.Token)
		if req.Bundle == nil {
			log.Printf("  bundle: <nil>")
		} else {
			sigstorePresent := len(req.Bundle.SigstoreBundle) > 0 && string(req.Bundle.SigstoreBundle) != "null"
			reportPresent := req.Bundle.EnclaveAttestationReport != nil
			reportFormat := ""
			if reportPresent {
				reportFormat = string(req.Bundle.EnclaveAttestationReport.Format)
			}
			log.Printf("  bundle: digest=%q sigstore=%t vcek=%t report=%t report_format=%q",
				req.Bundle.Digest, sigstorePresent, req.Bundle.VCEK != "", reportPresent, reportFormat)
		}

		if subtle.ConstantTimeCompare([]byte(req.Token), []byte(token)) != 1 {
			log.Printf("  rejected: bad token")
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		repoSecrets, ok := repos[req.Repo]
		if !ok {
			log.Printf("  rejected: repo %q not served", req.Repo)
			http.Error(w, "forbidden: repo not served", http.StatusForbidden)
			return
		}
		if req.Bundle == nil || req.Bundle.EnclaveAttestationReport == nil {
			log.Printf("  rejected: missing attestation bundle / report")
			http.Error(w, "missing attestation", http.StatusBadRequest)
			return
		}

		pkW, err := verifyEnclave(sigClient, req.Repo, req.Bundle, skipAttestation)
		if err != nil {
			log.Printf("  rejected: verify: %v", err)
			http.Error(w, "forbidden: "+err.Error(), http.StatusForbidden)
			return
		}

		released := filterSecrets(repoSecrets, req.SecretRefs)
		plaintext, err := json.Marshal(released)
		if err != nil {
			log.Printf("  rejected: marshal: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		enc, ct, err := sealTo(pkW, plaintext)
		if err != nil {
			log.Printf("  rejected: seal: %v", err)
			http.Error(w, "internal error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("  released %d/%d secret(s): %v", len(released), len(req.SecretRefs), req.SecretRefs)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fetchResponse{Enc: enc, Ciphertext: ct})
	}
}

// verifyEnclave mirrors SecureClient.VerifyFromBundle's chain but on the small
// Bundle cvmimage sends (just the SNP report + optional digest): sigstore
// proves the repo built to measurement M; the SNP quote proves the enclave is
// running M and holds pk_W in REPORTDATA. Returns the hardware-attested pk_W.
func verifyEnclave(sigClient *sigstore.Client, repo string, bundle *attestation.Bundle, skipAttestation bool) (string, error) {
	// SNP path runs in both modes — proves the report came from a real AMD CPU
	// in confidential mode and binds REPORTDATA to the per-boot HPKE pubkey.
	// Use local verifyReport (vcek.go) instead of tinfoil-go's VerifyWithVCEK,
	// which only ships the Genoa AMD cert chain — box2's CPU is Turin.
	vcekDER, err := bundleVCEK(bundle)
	if err != nil {
		return "", fmt.Errorf("vcek: %w", err)
	}
	enclaveMeasurement, hpkeKey, err := verifyReport(bundle.EnclaveAttestationReport, vcekDER)
	if err != nil {
		return "", fmt.Errorf("snp quote: %w", err)
	}
	log.Printf("  verify: snp quote measurement=%s hpke_pk=%s", enclaveMeasurement, hpkeKey)
	if hpkeKey == "" {
		return "", fmt.Errorf("quote carries no HPKE key in REPORTDATA")
	}

	if skipAttestation {
		log.Printf("  verify: SKIPPING sigstore code-identity check (insecure-skip-attestation); releasing to enclave=%s", enclaveMeasurement)
		return hpkeKey, nil
	}

	digest := bundle.Digest
	if digest == "" {
		digest, err = github.FetchLatestDigest(repo)
		if err != nil {
			return "", fmt.Errorf("latest digest: %w", err)
		}
		log.Printf("  verify: fetched latest digest from github: %s", digest)
	} else {
		log.Printf("  verify: using request-pinned digest: %s", digest)
	}
	sigBundle := bundle.SigstoreBundle
	if len(sigBundle) == 0 || string(sigBundle) == "null" {
		sigBundle, err = github.FetchAttestationBundle(repo, digest)
		if err != nil {
			return "", fmt.Errorf("fetch sigstore bundle: %w", err)
		}
		log.Printf("  verify: fetched sigstore bundle from github: %d bytes", len(sigBundle))
	} else {
		log.Printf("  verify: using request-supplied sigstore bundle: %d bytes", len(sigBundle))
	}
	codeMeasurement, err := sigClient.VerifyAttestation(sigBundle, repo, digest)
	if err != nil {
		return "", fmt.Errorf("sigstore: %w", err)
	}
	log.Printf("  verify: sigstore code measurement: type=%s registers=%v", codeMeasurement.Type, codeMeasurement.Registers)

	if len(codeMeasurement.Registers) == 0 || !strings.EqualFold(codeMeasurement.Registers[0], enclaveMeasurement) {
		return "", fmt.Errorf("code/enclave measurement mismatch: code=%v enclave=%s", codeMeasurement.Registers, enclaveMeasurement)
	}
	log.Printf("  verify: code/enclave measurements bind ✓")
	return hpkeKey, nil
}

// snippet returns up to n bytes of b as a string, for log previews of malformed bodies.
func snippet(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return string(b)
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
