#!/usr/bin/env bash
# Dev-launch this workload on box2 via the SSH tunnel.
#
# Prereqs:
#   1. ssh -L 8080:localhost:8080 box2.tinfoil.sh  (in another shell)
#   2. tinfoilsh/example-secret-keys has been tagged + released, so its sigstore
#      attestation exists (the cmdline + config we use here come from there)
#   3. external-config.yml's vault.url is set (not the REPLACE-ME placeholder)
#
# Usage: ./dev-launch.sh [name]
#
# Flow: GET /deployments/preview to pull the canonical config + cmdline (these
# are mutually consistent — the cmdline contains tinfoil-config-hash = sha256
# of the config). Then POST /dev-launch with our external-config.yml so
# stage 3b knows which vault to call.

set -euo pipefail

cd "$(dirname "$0")"

NAME="${1:-example-secret-keys-$(date +%s)}"
TINFOILD="${TINFOILD:-http://localhost:8080}"
REPO="tinfoilsh/example-secret-keys"
DOMAIN="${DOMAIN:-example-secret-keys.tinfoil.containers.tinfoil.dev}"

if grep -q "REPLACE-ME" external-config.yml; then
  echo "error: external-config.yml still has REPLACE-ME — set vault.url first" >&2
  exit 1
fi

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

EXTERNAL=$(printf 'env:\n  DOMAIN: "%s"\n%s\n' "$DOMAIN" "$(cat external-config.yml)")

PAYLOAD=$(jq -n \
  --arg name "$NAME" \
  --arg domain "$DOMAIN" \
  --arg config "$CONFIG_B64" \
  --arg external "$EXTERNAL" \
  --arg cmdline "$CMDLINE" \
  --arg repo "$REPO" \
  --arg tag "$RESOLVED_TAG" \
  '{
    name: $name,
    domain: $domain,
    debug: false,
    config: $config,
    external_config: $external,
    custom_cmdline: $cmdline,
    repo: $repo,
    tag: $tag
  }')

echo "POST $TINFOILD/dev-launch  name=$NAME domain=$DOMAIN repo=$REPO tag=$RESOLVED_TAG" >&2
curl -sS -X POST "$TINFOILD/dev-launch" \
  -H "Content-Type: application/json" \
  --data-binary "$PAYLOAD" \
| jq .
