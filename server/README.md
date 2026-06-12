# example-secret-keys vault

A user-side secrets endpoint for the `example-secret-keys` workload. Holds the
secrets in memory (from `secrets.json`) and releases them only to a workload
whose SEV-SNP quote matches the sigstore-attested measurement of its repo,
whose TLS client certificate carries the key that quote binds, and which
presents the shared bearer token.

This server is `dockerignore`d out of the workload image — it never runs in the
CVM. It runs on a host you control; the workload's vault-secrets boot stage
dials out to it at the `vault-url` in the measured config.

## How the requester is authenticated

The vault never has to dial into the enclave or re-implement attestation. It
reuses `tinfoil-go` and pins the connection to the attestation:

1. **Transport.** Caddy terminates public TLS with a Let's Encrypt certificate
   and requests the enclave's client certificate (`client_auth mode: request`).
   It forwards that certificate to the vault as `X-Tinfoil-Client-Cert`
   (DER, base64). The enclave, for its part, verifies Caddy's certificate
   against the public web PKI, so it can't be MITM'd onto a different vault.
2. **SNP quote.** `bundle.EnclaveAttestationReport.Verify()` checks the AMD
   chain and surfaces the TLS key fingerprint the enclave bound in REPORTDATA.
3. **Binding.** The forwarded client certificate's key fingerprint
   (`attestation.CertPubkeyFP`) must equal that attested fingerprint. The TLS
   handshake proves the requester holds the private key right now, so a leaked
   token plus the public quote is not enough.
4. **Code identity.** sigstore (`VerifyAttestation`) proves the repo built to
   the measurement in the quote (`Measurement.Equals`).

There is no HPKE and no challenge nonce: TLS provides confidentiality, and the
client-certificate handshake provides the liveness/anti-relay property.

## Provisioning a vault host (Caddy + Ansible)

`dev-vault.tinfoil.sh` is the reference deployment. The vault runs as a
plain-HTTP systemd service on `127.0.0.1:8080`; Caddy fronts it on `:443`.

1. Create local config (gitignored — never committed):

   ```bash
   cp .env.example .env
   cp server/ansible/inventory.example.yml server/ansible/inventory.yml
   # edit both with your vault host, VAULT_TOKEN, and EXAMPLE_KEY
   ```

   For the reference `dev-vault.tinfoil.sh` deployment, keep token and secret
   values only in `.env` and `inventory.yml` on your machine.

2. Deploy the vault:

   ```bash
   cd server
   make deploy                       # binary + secrets + Caddy + LE cert
   make deploy-secrets               # refresh token + secrets only
   ```

   `make deploy` reads `../.env`, builds `secrets.json` from `EXAMPLE_KEY`,
   and passes `VAULT_TOKEN` to Ansible. Never commit `.env`.

3. Make sure the host matches `vault-url` in the released `tinfoil-config.yml`
   (it's measured — changing it means a new tag).

## Running locally (without Caddy)

The vault expects a TLS-terminating proxy to forward the client certificate, so
it has no TLS code of its own. For a quick local smoke test, run it directly
and supply the header yourself (see `make build`):

```bash
make run-local   # reads ../.env, runs ./gen/tinfoil-vault on :8080
```

`/health` returns 200. `/fetch` requires a real SNP quote whose REPORTDATA key
matches the forwarded client certificate, so it only succeeds end-to-end from a
booting enclave.

## Outbound network the vault needs

- `api.github.com` — sigstore attestation bundle for the served repo
- `kds-proxy.tinfoil.sh` — VCEK cert for the CPU that signed the SNP quote
- TUF mirror — sigstore trust root, fetched once at startup
- Let's Encrypt — Caddy, for the public certificate

## Flags

- `-addr` (default `127.0.0.1:8080`) — plain-HTTP listen address
- `-secrets` (default `secrets.json`) — repo→secrets map
- `-token` / `VAULT_TOKEN` — shared bearer token
- `-insecure-skip-attestation` — DEV ONLY: skip the sigstore code-identity
  check. The SNP quote and the client-certificate binding are still enforced.
