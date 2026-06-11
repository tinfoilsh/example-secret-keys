// Command server is the user-side secrets endpoint. It listens on /fetch,
// verifies the bearer token, looks up the requesting workload's repo in the
// server-side allowlist, verifies the booting workload's SEV-SNP attestation
// against the sigstore-attested measurement of that repo, pins the request's
// TLS client certificate to the attested TLS key, and releases the requested
// secrets
//

package main

import (
	"crypto/subtle"
	"crypto/tls"
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
	"golang.org/x/crypto/acme/autocert"
)

type fetchRequest struct {
	Repo       string              `json:"repo"`
	SecretRefs []string            `json:"secret_refs"`
	Bundle     *attestation.Bundle `json:"bundle"`
	Token      string              `json:"token"`
}

func main() {
	addr := flag.String("addr", ":8099", "listen address (plain HTTP or --tls-cert/--tls-key mode)")
	secretsPath := flag.String("secrets", "secrets.json", `path to a JSON map keyed by repo, e.g. {"tinfoilsh/example-secret-keys": {"EXAMPLE_KEY": "value"}}`)
	tokenFlag := flag.String("token", "", "shared bearer token (or set VAULT_TOKEN env)")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file; serve HTTPS and request client certificates")
	tlsKey := flag.String("tls-key", "", "TLS key file (with --tls-cert)")
	acmeDomain := flag.String("acme-domain", "", "serve HTTPS on :443 with an automatic Let's Encrypt certificate for this domain")
	acmeCache := flag.String("acme-cache", "acme-cache", "directory for cached ACME certificates (with --acme-domain)")
	insecureSkipAttestation := flag.Bool("insecure-skip-attestation", false,
		"DEV ONLY: skip sigstore code-identity check. The SNP quote is still verified, "+
			"but the booted enclave is not bound to a published release of any repo.")
	insecureSkipClientCert := flag.Bool("insecure-skip-client-cert", false,
		"DEV ONLY: release secrets without binding the request to the enclave's TLS client "+
			"certificate. Required in plain-HTTP mode or behind a TLS-terminating proxy (e.g. ngrok).")
	flag.Parse()

	token := *tokenFlag
	if token == "" {
		token = os.Getenv("VAULT_TOKEN")
	}
	if token == "" {
		log.Fatalf("--token flag or VAULT_TOKEN env required")
	}

	if (*tlsCert == "") != (*tlsKey == "") {
		log.Fatalf("--tls-cert and --tls-key must be set together")
	}
	servingTLS := *acmeDomain != "" || *tlsCert != ""
	if !servingTLS && !*insecureSkipClientCert {
		log.Fatalf("plain HTTP cannot see the enclave's TLS client certificate: " +
			"serve TLS with --acme-domain or --tls-cert/--tls-key, or acknowledge with --insecure-skip-client-cert (dev only)")
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
	if *insecureSkipClientCert {
		log.Printf("WARNING: --insecure-skip-client-cert set; NOT binding requests to the enclave's attested TLS key (dev only)")
	}

	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	http.HandleFunc("/fetch", handleFetch(repos, token, sigClient, *insecureSkipAttestation, *insecureSkipClientCert))

	for repo, secrets := range repos {
		log.Printf("  serving %s (%d secrets)", repo, len(secrets))
	}

	switch {
	case *acmeDomain != "":
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(*acmeCache),
			HostPolicy: autocert.HostWhitelist(*acmeDomain),
		}
		cfg := m.TLSConfig()
		cfg.ClientAuth = tls.RequestClientCert
		srv := &http.Server{Addr: ":443", TLSConfig: cfg}
		log.Printf("vault server listening on :443 (ACME cert for %s, cache %s)", *acmeDomain, *acmeCache)
		log.Fatal(srv.ListenAndServeTLS("", ""))
	case *tlsCert != "":
		srv := &http.Server{Addr: *addr, TLSConfig: &tls.Config{ClientAuth: tls.RequestClientCert}}
		log.Printf("vault server listening on %s (TLS cert %s)", *addr, *tlsCert)
		log.Fatal(srv.ListenAndServeTLS(*tlsCert, *tlsKey))
	default:
		log.Printf("vault server listening on %s (plain HTTP)", *addr)
		log.Fatal(http.ListenAndServe(*addr, nil))
	}
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

func handleFetch(repos map[string]map[string]string, token string, sigClient *sigstore.Client, skipAttestation, skipClientCert bool) http.HandlerFunc {
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

		// The requester proof: the key that instantiated this TLS connection
		// must be the key the attestation binds (checked in verifyEnclave).
		connFP := ""
		if !skipClientCert {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				log.Printf("  rejected: no TLS client certificate on connection")
				http.Error(w, "forbidden: TLS client certificate required", http.StatusForbidden)
				return
			}
			connFP, err = attestation.ConnectionCertFP(*r.TLS)
			if err != nil {
				log.Printf("  rejected: client certificate fingerprint: %v", err)
				http.Error(w, "forbidden: unreadable client certificate", http.StatusForbidden)
				return
			}
		}

		if err := verifyEnclave(sigClient, req.Repo, req.Bundle, connFP, skipAttestation); err != nil {
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
// proves the repo built to measurement M; the SNP quote proves an enclave
// running M generated the TLS key in REPORTDATA; the client certificate on
// this very connection proves the requester holds that key right now.
func verifyEnclave(sigClient *sigstore.Client, repo string, bundle *attestation.Bundle, connFP string, skipAttestation bool) error {
	// SNP verification runs in both modes — tinfoil-go checks the Genoa AMD
	// cert chain and fetches the VCEK through kds-proxy.tinfoil.sh.
	verification, err := bundle.EnclaveAttestationReport.Verify()
	if err != nil {
		return fmt.Errorf("snp quote: %w", err)
	}
	if connFP != "" {
		if verification.TLSPublicKeyFP != connFP {
			return fmt.Errorf("TLS client key (%s) does not match attested key (%s)", connFP, verification.TLSPublicKeyFP)
		}
		log.Printf("  verify: snp quote measurement=%v tls key bound to connection ✓", verification.Measurement.Registers)
	} else {
		log.Printf("  verify: snp quote measurement=%v (client binding SKIPPED)", verification.Measurement.Registers)
	}

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
