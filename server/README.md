# example-secret-keys local server

A user-side secrets endpoint for the `example-secret-keys` workload. Holds the
secrets in memory (from `secrets.json`) and releases them only to a workload
whose SEV-SNP quote matches the sigstore-attested measurement of this repo and
presents the shared POC token.

This server is `dockerignore`d out of the workload image — it never runs in
the CVM. It runs on your machine; the workload's boot stage 3b dials out to it.

## Setup

1. Create `secrets.json` (gitignored):

   ```json
   {"EXAMPLE_KEY": "your-real-key-value"}
   ```

2. Build and run:

   ```bash
   go mod tidy
   go run . -addr :8099 -secrets secrets.json
   ```

3. Expose via ngrok (or any reverse proxy with a public HTTPS URL):

   ```bash
   ngrok http 8099
   ```

4. Pass the public URL to `../dev-launch.sh` as `VAULT_URL`.

## Outbound network the server needs

- `api.github.com` — to fetch the sigstore attestation bundle for
  `tinfoilsh/example-secret-keys`
- `kds-proxy.tinfoil.sh` — to fetch the VCEK cert for the CPU that signed the
  workload's SNP quote
- TUF mirror — sigstore trust root, fetched once at startup

## Notes

- The server only serves one repo (`tinfoilsh/example-secret-keys`), hardcoded.
- The shared POC token is hardcoded in `server/main.go` — anyone reading the
  source can see it. That's the POC tradeoff. The real version would have
  tinfoild inject a per-account token at deploy time so it never lives in
  public source.
- Secrets are sealed to the workload's per-boot HPKE public key (X25519 /
  HKDF-SHA256 / AES-256-GCM, RFC 9180), bound to the enclave by REPORTDATA in
  the AMD-signed SNP report. Nothing on the wire is plaintext.
