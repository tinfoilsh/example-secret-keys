# example-secret-keys

POC of a Tinfoil workload whose secrets come from a **user-controlled** local
server rather than Tinfoil's secret custody (KMS). At boot, the CVM's stage 3b
sends its SEV-SNP quote to the user's server; the server verifies the quote +
the sigstore-attested measurement of this repo, then HPKE-seals the requested
secret(s) to the workload's per-boot public key. Plaintext never touches
Tinfoil's infrastructure.

```
tag this repo ─▶ measure-image-action ─▶ sigstore attestation (under this repo)
                                                  │
  cvmimage stage 3b on boot ─▶ POST /fetch ─▶ user's server (./server)
                              {quote, repo, password}
                                                  │
                              verify(sigstore, SNP quote, password) → pk_W from REPORTDATA
                                                  │
                              ◀── HPKE-sealed EXAMPLE_KEY
                              container starts with EXAMPLE_KEY in env
```

## Files

- [`tinfoil-config.yml`](./tinfoil-config.yml) — **measured** workload config (nginx container that
  echoes `EXAMPLE_KEY` length and serves `/secret-check`).
- [`external-config.yml`](./external-config.yml) — host-authored, **not measured**. Carries the
  per-deployment vault URL (your ngrok / public endpoint to `./server`).
- [`server/`](./server/) — the user-side secrets endpoint. `dockerignore`d out of the
  workload image. See [`server/README.md`](./server/README.md) for run instructions.
- [`.github/workflows/release.yml`](./.github/workflows/release.yml) — on tag push, runs
  [`tinfoilsh/measure-image-action`](https://github.com/tinfoilsh/measure-image-action) to publish a sigstore attestation under this repo.

## Prereqs

- A cvmimage release that includes the vault-fetch boot stage (`secret-management`
  branch in `tinfoilsh/cvmimage`, eventually a prerelease tag). Pin it in
  `tinfoil-config.yml`'s `cvm-version`.
- The shared POC password in `server/main.go` matches the value in
  `cvmimage/tinfoil/cmd/boot/vault.go`. Both are hardcoded for the POC; the
  real version moves this to per-account injection by tinfoild.

## End-to-end (dev-launch on box2)

1. **Publish the workload attestation**

   ```bash
   git tag v0.0.1 && git push origin v0.0.1
   ```

   `release.yml` runs, attests the deployment under this repo via sigstore.

2. **Run the local secrets server**

   ```bash
   cd server
   echo '{"EXAMPLE_KEY":"my-real-key-value"}' > secrets.json
   go run . -addr :8099 -secrets secrets.json &
   ngrok http 8099
   ```

   Put the public URL into `external-config.yml`'s `vault.url`.

3. **Dev-launch the CVM**
   Same shape as `secrets-demo/confidential-secret-demo`'s runbook — non-debug,
   exact cmdline (`tinfoil-config-hash = sha256(tinfoil-config.yml)`,
   `roothash = manifest.root`), pointing tinfoild at this `tinfoil-config.yml`
   - `external-config.yml`.

4. **Verify through the shim**
   ```bash
   curl -k https://localhost:<http_port>/secret-check  # → EXAMPLE_KEY len=N
   ```
   Host only saw secret **names** + a release count, never any value.

## In real deploys

`external-config.yml` is per-deployment data tinfoild gets at launch: this is just here since we don't have another way to do this yet.

In the future, we should do: User fills a form, controlplane stores it against the deployment, tinfoild writes those fields into the external-config slot at launch. The yaml is just the dev-launch shortcut for the same slot.

Same logic for the POC password — eventually injected per-account by tinfoild, not hardcoded.

## Threat model — what this POC does and doesn't cover

**Covered.** Tinfoil never sees `EXAMPLE_KEY`. Secrets are sealed end-to-end
from the user's server into the enclave's `sk_W`, and the AMD-signed quote
proves the enclave is running the code this repo attested to.

**Not covered (yet).** A different user could clone this repo, build the same
workload, and present the shared POC password (which is in this repo's source).
The real fix is the per-account password injection by tinfoild — `cvmimage`
keeps the field, but the value comes from tinfoild at deploy time, scoped to
the account that deployed.
