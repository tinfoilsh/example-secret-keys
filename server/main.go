// Command server is the user-side secrets endpoint. It serves plain HTTP and
// sits behind a TLS-terminating reverse proxy (Caddy) that requests the
// enclave's client certificate and forwards it in a header. On /fetch it
// verifies the booting workload's SEV-SNP attestation against the
// sigstore-attested measurement of its repo, pins the forwarded TLS client
// certificate to the key that attestation binds, checks the bearer token, and
// releases the requested secrets.
//
// The TLS key fingerprint in the SNP REPORTDATA and the fingerprint of the
// client certificate on the live connection must match: the handshake proves
// the requester holds that key right now, so a leaked token plus the public
// attestation document is not enough.
package main

import (
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
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

// clientCertHeader carries the enclave's mTLS client certificate (DER,
// base64-encoded) that the TLS-terminating proxy (Caddy) forwards. Caddy sets
// this from {http.request.tls.client.certificate_der_base64}, overwriting any
// value a client tried to send, so it cannot be spoofed past the proxy.
const clientCertHeader = "X-Tinfoil-Client-Cert"

type fetchRequest struct {
	Repo       string              `json:"repo"`
	SecretRefs []string            `json:"secret_refs"`
	Bundle     *attestation.Bundle `json:"bundle"`
	Token      string              `json:"token"`
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address (plain HTTP; terminate TLS at the reverse proxy)")
	secretsPath := flag.String("secrets", "secrets.json", `path to a JSON map keyed by repo, e.g. {"tinfoilsh/example-secret-keys": {"EXAMPLE_KEY": "value"}}`)
	tokenFlag := flag.String("token", "", "shared bearer token (or set VAULT_TOKEN env)")
	skipAttestation := flag.Bool("insecure-skip-attestation", false,
		"DEV ONLY: skip the sigstore code-identity check. The SNP quote and the "+
			"client-certificate binding are still verified, but the enclave is not "+
			"bound to a published release of any repo.")
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
	if *skipAttestation {
		log.Printf("WARNING: --insecure-skip-attestation set; not binding releases to a published repo measurement (dev only)")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/fetch", handleFetch(repos, token, sigClient, *skipAttestation))

	for repo, secrets := range repos {
		log.Printf("  serving %s (%d secrets)", repo, len(secrets))
	}
	log.Printf("vault server listening on %s (plain HTTP; expects TLS termination + client cert from the proxy)", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
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
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		var req fetchRequest
		if err := json.Unmarshal(body, &req); err != nil {
			log.Printf("  rejected: decode body: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		log.Printf("  claim: repo=%q secret_refs=%v", req.Repo, req.SecretRefs)

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
			log.Printf("  rejected: missing attestation report")
			http.Error(w, "missing attestation", http.StatusBadRequest)
			return
		}

		clientFP := clientCertFP(r)
		if clientFP == "" {
			log.Printf("  rejected: no TLS client certificate forwarded by the proxy")
			http.Error(w, "forbidden: TLS client certificate required", http.StatusForbidden)
			return
		}

		if err := verifyEnclave(sigClient, req.Repo, req.Bundle, clientFP, skipAttestation); err != nil {
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

// clientCertFP returns the tinfoil-go key fingerprint of the client
// certificate the proxy forwarded, or "" when none was presented (the
// placeholder resolves to empty, and a non-TLS or spoofed value won't parse).
func clientCertFP(r *http.Request) string {
	b64 := r.Header.Get(clientCertHeader)
	if b64 == "" {
		return ""
	}
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return ""
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return ""
	}
	fp, err := attestation.CertPubkeyFP(cert)
	if err != nil {
		return ""
	}
	return fp
}

// verifyEnclave reuses tinfoil-go's verification primitives to authenticate the
// requester: the attestation report proves an enclave running measurement M generated
// the TLS key in REPORTDATA; the forwarded client certificate proves the
// requester holds that key on this connection; and sigstore proves the repo
// built to M. The three together release secrets to exactly the attested code.
func verifyEnclave(sigClient *sigstore.Client, repo string, bundle *attestation.Bundle, clientFP string, skipAttestation bool) error {
	// SNP verification: tinfoil-go checks the AMD cert chain and fetches the
	// VCEK through kds-proxy.tinfoil.sh.
	verification, err := bundle.EnclaveAttestationReport.Verify()
	if err != nil {
		return fmt.Errorf("snp quote: %w", err)
	}

	// Pin the live TLS client key to the attested key (REPORTDATA[:32]).
	if verification.TLSPublicKeyFP != clientFP {
		return fmt.Errorf("TLS client key (%s) does not match attested key (%s)", clientFP, verification.TLSPublicKeyFP)
	}
	log.Printf("  verify: snp quote measurement=%v, TLS client key bound to attestation ✓", verification.Measurement.Registers)

	if skipAttestation {
		log.Printf("  verify: SKIPPING sigstore code-identity check (insecure-skip-attestation)")
		return nil
	}

	// The enclave pins its release digest in the bundle; fall back to the
	// latest published release only if it didn't.
	digest := bundle.Digest
	if digest == "" {
		digest, err = github.FetchLatestDigest(repo)
		if err != nil {
			return fmt.Errorf("latest digest: %w", err)
		}
	}
	sigBundle, err := github.FetchAttestationBundle(repo, digest)
	if err != nil {
		return fmt.Errorf("fetch sigstore bundle: %w", err)
	}
	codeMeasurement, err := sigClient.VerifyAttestation(sigBundle, repo, digest)
	if err != nil {
		return fmt.Errorf("sigstore: %w", err)
	}
	if err := codeMeasurement.Equals(verification.Measurement); err != nil {
		return fmt.Errorf("code/enclave measurement mismatch: %w", err)
	}
	log.Printf("  verify: code/enclave measurements bind ✓")
	return nil
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
