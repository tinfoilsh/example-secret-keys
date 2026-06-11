# example-secret-keys

POC of a Tinfoil workload whose secrets come from a **user-controlled** local
server rather than Tinfoil's secret custody (KMS). At boot, the CVM's
vault-secrets stage dials the vault-url declared in the **measured** config
over mutual TLS, presenting a client certificate over the TLS key its boot
attestation binds in REPORTDATA; the server verifies the quote + the
sigstore-attested measurement of this repo + that the key on this very
connection is the attested one, then releases the requested secret(s) over
that same connection. Plaintext never touches Tinfoil's infrastructure.

The requester proof is pinned TLS in reverse: the same key-binding check
Tinfoil clients run against an enclave's *server* certificate, applied by the
vault to the enclave's *client* certificate.

```
tag this repo ─▶ measure-image-action ─▶ sigstore attestation (under this repo)
                                                  │
  cvmimage vault stage on boot                    │
            (vault-url measured)                  │
                  │                               │
                  ─▶ POST /fetch {boot quote, repo, token}
                     mutual TLS: client certificate over the
                     enclave's attested TLS key
                                                  │
                     verify(sigstore, SNP quote, token,
                            client key on connection == key in REPORTDATA)
                                                  │
                  ◀── EXAMPLE_KEY over the same connection
                  container starts with EXAMPLE_KEY in env
```

## Files

- [`tinfoil-config.yml`](./tinfoil-config.yml) — **measured** workload config (nginx container that
  echoes `EXAMPLE_KEY` length and serves `/secret-check`).
- [`server/`](./server/) — the user-side secrets endpoint. `dockerignore`d out of the
  workload image. See [`server/README.md`](./server/README.md) for run instructions.
- [`.github/workflows/release.yml`](./.github/workflows/release.yml) — on tag push, runs
  [`tinfoilsh/measure-image-action`](https://github.com/tinfoilsh/measure-image-action) to publish a sigstore attestation under this repo.

## Prereqs

- A cvmimage release that includes the vault-fetch boot stage (`secret-management`
  branch in `tinfoilsh/cvmimage`, eventually a prerelease tag). Pin it in
  `tinfoil-config.yml`'s `cvm-version`.

## End-to-end (dev-launch on box2)

1. **Publish the workload attestation**

   ```bash
   git tag v0.0.1 && git push origin v0.0.1
   ```

   `release.yml` runs, attests the deployment under this repo via sigstore.

2. **Run the secrets server**

   The server must terminate TLS itself for the client-certificate binding to
   be real — client certificates cannot cross a TLS-terminating proxy. On a
   public box with the DNS name in `vault-url`:

   ```bash
   cd server
   cat > secrets.json <<'EOF'
   {"tinfoilsh/example-secret-keys": {"EXAMPLE_KEY":"my-real-key-value"}}
   EOF
   go run . -acme-domain vault.example.com -secrets secrets.json -token <bearer-token>
   ```

   For quick smoke tests behind a TLS-terminating tunnel (ngrok http), plain
   HTTP still works but loses the requester binding:

   ```bash
   go run . -addr :8099 -secrets secrets.json -token <bearer-token> -insecure-skip-client-cert &
   ngrok http 8099
   ```

   Either way the public URL must match the `vault-url` in the released
   `tinfoil-config.yml` — changing it means a new tag (step 1).

3. **Dev-launch the CVM**
   Same shape as `secrets-demo/confidential-secret-demo`'s runbook — non-debug,
   exact cmdline (`tinfoil-config-hash = sha256(tinfoil-config.yml)`,
   `roothash = manifest.root`), pointing tinfoild at this `tinfoil-config.yml`.
   The vault URL is part of the measured config (`vault-url:`), so it arrives
   exactly as released. The token flows as `vault_token` on the `/dev-launch`
   body; tinfoild writes it into the external-config the CVM sees as
   `vault-token`.

4. **Verify through the shim**
   ```bash
   curl -k https://localhost:<http_port>/secret-check  # → EXAMPLE_KEY len=N
   ```
   Host only saw secret **names** + a release count, never any value.

## In real deploys

The vault URL ships in the repo's `tinfoil-config.yml`, so it's covered by
the measurement — neither Tinfoil nor the host provider can repoint a
deployment at another vault. Controlplane stores only the token against the
deployment and forwards it to tinfoild as `vault_token` on `/deployments`;
tinfoild writes it into the external-config slot the CVM sees. `dev-launch.sh`
is the dev-time shortcut for the same slot — it takes `VAULT_TOKEN` as an
env var.

Same logic for the POC token — eventually injected per-account by tinfoild, not hardcoded.

## Threat model — what this POC does and doesn't cover

**Covered.** Tinfoil never sees `EXAMPLE_KEY`. Secrets travel over TLS from
the user's server to the enclave, where the TLS session terminates inside the
CVM, and the AMD-signed quote proves the enclave is running the code this
repo attested to before anything is released.

The client certificate makes the request a *requester* proof, not just an
existence proof: published boot quotes + a leaked token are not enough to
fetch secrets, because completing the TLS handshake requires the private key
the quote binds in REPORTDATA — a key that never leaves the measured enclave.
The boot quote can be old; the handshake is the liveness proof, so no nonce
or fresh quote is needed.

**Not covered (yet).** A different user could clone this repo, build the same
workload, and present the shared POC token (which is in this repo's source).
The real fix is the per-account token injection by tinfoild — `cvmimage`
keeps the field, but the value comes from tinfoild at deploy time, scoped to
the account that deployed.

Also dev-setup-only: behind a TLS-terminating tunnel (ngrok http) the client
certificate is stripped, so the server needs `-insecure-skip-client-cert` and
release decisions rest on token + quote alone. A production vault terminates
TLS itself, which also means no intermediary ever sees released values.
