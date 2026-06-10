#!/usr/bin/env bash
# Dev-launch this workload on box2 via the SSH tunnel.
#
# Prereqs:
#   1. ssh -L 8080:localhost:8080 box2.tinfoil.sh  (in another shell)
#   2. tinfoilsh/example-secret-keys has been tagged + released, so its sigstore
#      attestation exists (the cmdline + config we use here come from there)
#
# Usage: ./dev-launch.sh [name]
#
# Flow: GET /deployments/preview to pull the canonical config + cmdline (these
# are mutually consistent — the cmdline contains tinfoil-config-hash = sha256
# of the config). Then POST /dev-launch with a top-level vault block so stage
# 3b knows which vault to call — tinfoild merges it into external-config under
# `vault:` (same way controlplane will once merged).

set -euo pipefail

cd "$(dirname "$0")"

NAME="${1:-example-secret-keys-$(date +%s)}"
TINFOILD="${TINFOILD:-http://localhost:8080}"
REPO="tinfoilsh/example-secret-keys"
# DOMAIN is set in external-config's env: section for the cvmimage's identity
# stage. It's *not* sent as the top-level deploy `domain` field because that
# would trigger tinfoild's fallback CERT_AUTH_TOKEN fetch from controlplane's
# /api/tinfoild/cert-token. That endpoint is gated by an IP allowlist
# (CF-Connecting-IP), and a box3 → controlplane direct call doesn't go through
# Cloudflare, so it 401s. In prod controlplane mints the token itself and
# pre-injects it into additional_data, so the fallback never runs.
DOMAIN="${DOMAIN:-example-secret-keys.dev-launch.tinfoil.dev}"
VAULT_URL="${VAULT_URL:-https://unfilled-elective-ecosphere.ngrok-free.dev}"
VAULT_PASSWORD="${VAULT_PASSWORD:-poc-shared-secret-do-not-use}"

# Box3-side path to the locally-built cvmimage. Must contain
# tinfoilcvm.{vmlinuz,initrd,raw,hash}.
CVMIMAGE_DIR="${CVMIMAGE_DIR:-/home/ubuntu/daniel-workspace/cvmimage}"

echo "GET $TINFOILD/deployments/preview?repo=$REPO" >&2
PREVIEW=$(curl -sS -m 10 "$TINFOILD/deployments/preview?repo=$REPO")
CONFIG_B64=$(echo "$PREVIEW" | jq -r '.config')
CMDLINE=$(echo "$PREVIEW" | jq -r '.cmdline')
RESOLVED_TAG=$(echo "$PREVIEW" | jq -r '.tag')

if [ -z "$CMDLINE" ] || [ "$CMDLINE" = "null" ]; then
  echo "error: preview returned no cmdline. response:" >&2
  echo "$PREVIEW" | jq . >&2
  exit 1
fi

# Pull the verity roothash of the locally-built cvmimage and swap it into the
# cmdline so the VM mounts our branch build (not the released roothash that
# came back from preview).
echo "GET $TINFOILD/dev-launch/hash?path=$CVMIMAGE_DIR" >&2
LOCAL_HASH=$(curl -sS -m 10 --get --data-urlencode "path=$CVMIMAGE_DIR" "$TINFOILD/dev-launch/hash" | jq -r '.hash')
if [ -z "$LOCAL_HASH" ] || [ "$LOCAL_HASH" = "null" ]; then
  echo "error: no roothash at $CVMIMAGE_DIR/tinfoilcvm.hash" >&2
  exit 1
fi
CMDLINE=$(echo "$CMDLINE" | sed -E "s/roothash=[a-f0-9]+/roothash=$LOCAL_HASH/")

EXTERNAL=$(printf 'env:\n  DOMAIN: "%s"\n' "$DOMAIN")

PAYLOAD=$(jq -n \
  --arg name "$NAME" \
  --arg config "$CONFIG_B64" \
  --arg external "$EXTERNAL" \
  --arg cmdline "$CMDLINE" \
  --arg repo "$REPO" \
  --arg tag "$RESOLVED_TAG" \
  --arg vault_url "$VAULT_URL" \
  --arg vault_password "$VAULT_PASSWORD" \
  --arg kernel "$CVMIMAGE_DIR/tinfoilcvm.vmlinuz" \
  --arg initrd "$CVMIMAGE_DIR/tinfoilcvm.initrd" \
  --arg disk "$CVMIMAGE_DIR/tinfoilcvm.raw" \
  '{
    name: $name,
    debug: true,
    config: $config,
    external_config: $external,
    custom_cmdline: $cmdline,
    repo: $repo,
    tag: $tag,
    kernel_file: $kernel,
    initrd_file: $initrd,
    disk_file: $disk,
    skip_manifest: true,
    vault: {url: $vault_url, password: $vault_password}
  }')

echo "POST $TINFOILD/dev-launch  name=$NAME repo=$REPO tag=$RESOLVED_TAG roothash=$LOCAL_HASH" >&2
curl -sS -X POST "$TINFOILD/dev-launch" \
  -H "Content-Type: application/json" \
  --data-binary "$PAYLOAD" \
| jq .
