// Command server is the user-side secrets endpoint. It listens on /fetch,
// verifies the bearer token, looks up the requesting workload's repo in the
// server-side allowlist, verifies the booting workload's SEV-SNP attestation
// against the sigstore-attested measurement of that repo, and releases the
// requested secrets
//

package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
	"github.com/tinfoilsh/tinfoil-go/verifier/github"
	"github.com/tinfoilsh/tinfoil-go/verifier/sigstore"
)

type fetchRequest struct {
	Repo       string              `json:"repo"`
	SecretRefs []string            `json:"secret_refs"`
	Bundle     *attestation.Bundle `json:"bundle"`
	Token      string              `json:"token"`
	Nonce      string              `json:"nonce"`
}

// nonceTTL bounds how long a challenge stays redeemable.
const nonceTTL = 2 * time.Minute

// nonceStore issues single-use challenge nonces (KBS RCAR-style): /challenge
// hands one out, /fetch burns it. A fetch only succeeds with a quote whose
// REPORTDATA carries a nonce we issued — proof the requester is a live
// enclave, not a replayed quote and a leaked token.
type nonceStore struct {
	mu     sync.Mutex
	nonces map[string]time.Time // hex nonce → expiry
}

func newNonceStore() *nonceStore {
	return &nonceStore{nonces: map[string]time.Time{}}
}

func (s *nonceStore) issue() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	for n, exp := range s.nonces {
		if time.Now().After(exp) {
			delete(s.nonces, n)
		}
	}
	s.nonces[nonce] = time.Now().Add(nonceTTL)
	return nonce, nil
}

// redeem burns the nonce. It is single-use whether or not the fetch that
// carries it ends up succeeding.
func (s *nonceStore) redeem(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.nonces[nonce]
	if !ok {
		return false
	}
	delete(s.nonces, nonce)
	return time.Now().Before(exp)
}

func main() {
	addr := flag.String("addr", ":8099", "listen address")
	secretsPath := flag.String("secrets", "secrets.json", `path to a JSON map keyed by repo, e.g. {"tinfoilsh/example-secret-keys": {"EXAMPLE_KEY": "value"}}`)
	tokenFlag := flag.String("token", "", "shared bearer token (or set VAULT_TOKEN env)")
	insecureSkipAttestation := flag.Bool("insecure-skip-attestation", false,
		"DEV ONLY: skip sigstore code-identity check. The SNP quote is still verified, "+
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

	nonces := newNonceStore()

	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	http.HandleFunc("/challenge", handleChallenge(nonces))
	http.HandleFunc("/fetch", handleFetch(repos, token, sigClient, nonces, *insecureSkipAttestation))

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

func handleChallenge(nonces *nonceStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nonce, err := nonces.issue()
		if err != nil {
			log.Printf("/challenge: issuing nonce: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		log.Printf("/challenge from %s: issued %s…", r.RemoteAddr, nonce[:8])
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"nonce": nonce})
	}
}

func handleFetch(repos map[string]map[string]string, token string, sigClient *sigstore.Client, nonces *nonceStore, skipAttestation bool) http.HandlerFunc {
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

		nonce, err := hex.DecodeString(req.Nonce)
		if err != nil || len(nonce) != 32 {
			log.Printf("  rejected: malformed nonce %q", req.Nonce)
			http.Error(w, "malformed nonce (GET /challenge first)", http.StatusBadRequest)
			return
		}
		if !nonces.redeem(req.Nonce) {
			log.Printf("  rejected: unknown, expired, or already-used nonce %s…", req.Nonce[:8])
			http.Error(w, "forbidden: invalid nonce (GET /challenge first)", http.StatusForbidden)
			return
		}

		if err := verifyEnclave(sigClient, req.Repo, req.Bundle, nonce, skipAttestation); err != nil {
			log.Printf("  rejected: verify: %v", err)
			http.Error(w, "forbidden: "+err.Error(), http.StatusForbidden)
			return
		}

		released := filterSecrets(repoSecrets, req.SecretRefs)
		log.Printf("  released %d/%d secret(s): %v", len(released), len(req.SecretRefs), req.SecretRefs)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(released)
	}
}

// verifyEnclave mirrors SecureClient.VerifyFromBundle's chain but on the small
// Bundle cvmimage sends (just the SNP report + optional digest): sigstore
// proves the repo built to measurement M; the SNP quote proves a live enclave
// running M produced it for this exchange (our nonce in REPORTDATA).
func verifyEnclave(sigClient *sigstore.Client, repo string, bundle *attestation.Bundle, nonce []byte, skipAttestation bool) error {
	// SNP verification runs in both modes — tinfoil-go checks the Genoa AMD
	// cert chain and fetches the VCEK through kds-proxy.tinfoil.sh.
	verification, err := bundle.EnclaveAttestationReport.Verify()
	if err != nil {
		return fmt.Errorf("snp quote: %w", err)
	}
	// The vault quote carries the challenge nonce in REPORTDATA[:32], the
	// slot tinfoil-go surfaces as TLSPublicKeyFP.
	if verification.TLSPublicKeyFP != hex.EncodeToString(nonce) {
		return fmt.Errorf("quote REPORTDATA does not carry the challenge nonce")
	}
	log.Printf("  verify: snp quote measurement=%v nonce bound ✓", verification.Measurement.Registers)

	if skipAttestation {
		log.Printf("  verify: SKIPPING sigstore code-identity check (insecure-skip-attestation); releasing to enclave=%v", verification.Measurement.Registers)
		return nil
	}

	digest := bundle.Digest
	if digest == "" {
		digest, err = github.FetchLatestDigest(repo)
		if err != nil {
			return fmt.Errorf("latest digest: %w", err)
		}
		log.Printf("  verify: fetched latest digest from github: %s", digest)
	} else {
		log.Printf("  verify: using request-pinned digest: %s", digest)
	}
	sigBundle := bundle.SigstoreBundle
	if len(sigBundle) == 0 || string(sigBundle) == "null" {
		sigBundle, err = github.FetchAttestationBundle(repo, digest)
		if err != nil {
			return fmt.Errorf("fetch sigstore bundle: %w", err)
		}
		log.Printf("  verify: fetched sigstore bundle from github: %d bytes", len(sigBundle))
	} else {
		log.Printf("  verify: using request-supplied sigstore bundle: %d bytes", len(sigBundle))
	}
	codeMeasurement, err := sigClient.VerifyAttestation(sigBundle, repo, digest)
	if err != nil {
		return fmt.Errorf("sigstore: %w", err)
	}
	log.Printf("  verify: sigstore code measurement: type=%s registers=%v", codeMeasurement.Type, codeMeasurement.Registers)

	if err := codeMeasurement.Equals(verification.Measurement); err != nil {
		return fmt.Errorf("code/enclave measurement mismatch: %w", err)
	}
	log.Printf("  verify: code/enclave measurements bind ✓")
	return nil
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
