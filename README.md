# example-secret-keys

POC of a Tinfoil workload whose secrets come from a **user-controlled** local
server rather than Tinfoil's secret custody (KMS). At boot, the CVM fetches from the
vault server over mutual TLS, presenting a client certificate over the TLS key its boot
attestation binds in REPORTDATA; the server verifies the quote + the
sigstore-attested measurement of this repo + that the key on this very
connection is the attested one, then releases the requested secret(s) over
that same connection. Plaintext never touches Tinfoil's infrastructure.

The requester proof is pinned TLS in reverse: the same key-binding check
Tinfoil clients run against an enclave's _server_ certificate, applied by the
vault to the enclave's _client_ certificate.

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

## Setup

1. **Publish the workload attestation**

   Run `release.yml` to build a new tag from the config.

2. **Run the secrets server**

   The vault runs as a plain-HTTP service behind Caddy, which terminates public
   TLS (Let's Encrypt), requests the enclave's client certificate, and forwards
   it as a header. `server/ansible/` provisions a host end to end:

   ```bash
   cp .env.example .env   # set VAULT_TOKEN (+ optional EXAMPLE_KEY for vault deploy)
   cp server/ansible/inventory.example.yml server/ansible/inventory.yml
   cd server && make deploy
   ./dev-launch.sh    # reads .env for VAULT_TOKEN
   ```

   The reference host is `dev-vault.tinfoil.sh`. Its DNS name must match the
   `vault-url` in the released `tinfoil-config.yml` — changing it means a new
   tag (step 1). See [`server/README.md`](./server/README.md) for details.

**Proxy trust.** Caddy terminates TLS and forwards the verified client
certificate to the vault over loopback (`X-Tinfoil-Client-Cert`). The vault
binds to `127.0.0.1` and trusts that header only because nothing else can reach
it; Caddy overwrites any client-supplied value. A hardened deployment would put
the vault and Caddy in the same trust boundary (same host, as here) so the
loopback hop is not attackable.
