# example-secret-keys local server

A user-side secrets endpoint for the `example-secret-keys` workload. Holds the
secrets in memory (from `secrets.json`) and releases them only to a workload
whose SEV-SNP quote matches the sigstore-attested measurement of this repo and
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

2. Build and run (token via flag or `VAULT_TOKEN` env):

   ```bash
   go mod tidy
   go run . -addr :8099 -secrets secrets.json -token <random-bearer-token>
   ```

3. Expose via ngrok (or any reverse proxy with a public HTTPS URL):

   ```bash
   ngrok http 8099
   ```

4. Make sure the public URL matches `vault-url` in the released
   `tinfoil-config.yml` (it's measured — changing it means a new tag).

## Outbound network the server needs

- `api.github.com` — to fetch the sigstore attestation bundle for
  `tinfoilsh/example-secret-keys`
- `kds-proxy.tinfoil.sh` — to fetch the VCEK cert for the CPU that signed the
  workload's SNP quote
- TUF mirror — sigstore trust root, fetched once at startup

## Notes

- The server serves whichever repos appear as keys in `secrets.json`. Requests
  whose `repo` claim isn't in the map get 403.
- The shared bearer token is supplied via `-token` / `VAULT_TOKEN` and applies
  to every served repo (one operator, one server, one token).
- Secrets are released over the TLS channel once the SNP quote and sigstore
  code identity verify. The CVM terminates TLS inside the enclave; with ngrok
  in the dev path, ngrok terminates the public leg and can see released
  values — a production vault serves TLS itself.
