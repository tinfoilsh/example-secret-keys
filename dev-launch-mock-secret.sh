#!/usr/bin/env bash
# Sibling of dev-launch.sh that tests the *pre-existing* path:
# secrets are baked into external_config (as controlplane does in prod),
# no vault token sent. Proves our branch changes don't break the
# established flow.
#
# Prereqs: same as dev-launch.sh — ssh tunnel up, cvmimage built on box3.
#
# Usage: ./dev-launch-mock-secret.sh [name]

set -euo pipefail

cd "$(dirname "$0")"

NAME="${1:-mock-secret-$(date +%s)}"
TINFOILD="${TINFOILD:-http://localhost:8080}"
REPO="tinfoilsh/example-secret-keys"
DOMAIN="${DOMAIN:-mock-secret.dev-launch.tinfoil.dev}"
EXAMPLE_KEY_VALUE="${EXAMPLE_KEY_VALUE:-mock-value-from-dev-launch-mock}"

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

echo "GET $TINFOILD/dev-launch/hash?path=$CVMIMAGE_DIR" >&2
LOCAL_HASH=$(curl -sS -m 10 --get --data-urlencode "path=$CVMIMAGE_DIR" "$TINFOILD/dev-launch/hash" | jq -r '.hash')
if [ -z "$LOCAL_HASH" ] || [ "$LOCAL_HASH" = "null" ]; then
  echo "error: no roothash at $CVMIMAGE_DIR/tinfoilcvm.hash" >&2
  exit 1
fi
CMDLINE=$(echo "$CMDLINE" | sed -E "s/roothash=[a-f0-9]+/roothash=$LOCAL_HASH/")

# Bake EXAMPLE_KEY directly into external_config.secrets — mimics what
# controlplane does when no vault is attached. DOMAIN stays in env: for the
# cvmimage identity stage; not sent top-level (same cert-fetch dodge as
# dev-launch.sh).
EXTERNAL=$(cat <<EOF
env:
  DOMAIN: "$DOMAIN"
secrets:
  EXAMPLE_KEY: "$EXAMPLE_KEY_VALUE"
EOF
)

PAYLOAD=$(jq -n \
  --arg name "$NAME" \
  --arg config "$CONFIG_B64" \
  --arg external "$EXTERNAL" \
  --arg cmdline "$CMDLINE" \
  --arg repo "$REPO" \
  --arg tag "$RESOLVED_TAG" \
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
    skip_manifest: true
  }')

echo "POST $TINFOILD/dev-launch  name=$NAME repo=$REPO tag=$RESOLVED_TAG roothash=$LOCAL_HASH" >&2
curl -sS -X POST "$TINFOILD/dev-launch" \
  -H "Content-Type: application/json" \
  --data-binary "$PAYLOAD" \
| jq .
