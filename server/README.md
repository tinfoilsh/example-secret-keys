# example-secret-keys local server

A user-side secrets endpoint for the `example-secret-keys` workload. Holds the
secrets in memory (from `secrets.json`) and releases them only to a workload
whose SEV-SNP quote matches the sigstore-attested measurement of this repo,
whose TLS client certificate carries the key that quote binds, and which
presents the shared POC token.

This server is `dockerignore`d out of the workload image — it never runs in
the CVM. It runs on your machine; the workload's vault-secrets boot stage
dials out to it at the `vault-url` in the measured config.

## Setup

1. Create `secrets.json` (gitignored), keyed by repo:

   ```json
   {
     "tinfoilsh/example-secret-keys": {
       "EXAMPLE_KEY": "your-real-key-value"
     }
   }
   ```

2. Build and run (token via flag or `VAULT_TOKEN` env). The server must
   terminate TLS itself to see the enclave's client certificate; pick one:

   ```bash
   go mod tidy

   # public box, automatic Let's Encrypt cert on :443
   go run . -acme-domain vault.example.com -secrets secrets.json -token <random-bearer-token>

   # bring your own cert
   go run . -addr :8443 -tls-cert cert.pem -tls-key key.pem -secrets secrets.json -token <random-bearer-token>

   # DEV ONLY: plain HTTP behind a TLS-terminating tunnel (ngrok http) — the
   # client certificate is stripped, so the requester binding is skipped
   go run . -addr :8099 -insecure-skip-client-cert -secrets secrets.json -token <random-bearer-token>
   ngrok http 8099
   ```

3. Make sure the public URL matches `vault-url` in the released
   `tinfoil-config.yml` (it's measured — changing it means a new tag).

## Outbound network the server needs

- `api.github.com` — to fetch the sigstore attestation bundle for
  `tinfoilsh/example-secret-keys`
- `kds-proxy.tinfoil.sh` — to fetch the VCEK cert for the CPU that signed the
  workload's SNP quote
- TUF mirror — sigstore trust root, fetched once at startup
- Let's Encrypt — only with `-acme-domain`

## Notes

- The server serves whichever repos appear as keys in `secrets.json`. Requests
  whose `repo` claim isn't in the map get 403.
- The shared bearer token is supplied via `-token` / `VAULT_TOKEN` and applies
  to every served repo (one operator, one server, one token).
- The requester proof is mutual TLS pinned to the attestation: `/fetch` only
  releases when the request's client certificate carries the TLS key the boot
  quote binds in REPORTDATA. The handshake proves live possession of that
  key, so a leaked token plus the (public) boot quote is not enough.
- Secrets are released over the same connection once the SNP quote, the
  client-key binding, and the sigstore code identity verify. The CVM
  terminates TLS inside the enclave, so with the server terminating its own
  TLS no intermediary ever sees a value.
