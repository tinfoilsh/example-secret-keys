#!/usr/bin/env bash
# Dev-launch this workload on box2 via the SSH tunnel.
#
# Prereqs:
#   1. ssh -L 8080:localhost:8080 box2.tinfoil.sh  (in another shell)
#   2. tinfoil-config.yml's cvm-version points at a published cvmimage release
#   3. external-config.yml's vault.url is set (not the REPLACE-ME placeholder)
#   4. example-secret-keys has been tagged + released so the sigstore
#      attestation exists for the secrets server to verify against
#
# Usage: ./dev-launch.sh [name]
#
# tinfoild handles cmdline/roothash/config-hash derivation from cvm-version's
# manifest — we just send config + external-config + repo hint.

set -euo pipefail

cd "$(dirname "$0")"

NAME="${1:-example-secret-keys-$(date +%s)}"
TINFOILD="${TINFOILD:-http://localhost:8080}"
REPO="tinfoilsh/example-secret-keys"

if grep -q "REPLACE-ME" external-config.yml; then
  echo "error: external-config.yml still has REPLACE-ME — set vault.url first" >&2
  exit 1
fi

CONFIG_B64=$(base64 < tinfoil-config.yml | tr -d '\n')
EXTERNAL=$(cat external-config.yml)

PAYLOAD=$(jq -n \
  --arg name "$NAME" \
  --arg config "$CONFIG_B64" \
  --arg external "$EXTERNAL" \
  --arg repo "$REPO" \
  '{
    name: $name,
    debug: false,
    config: $config,
    external_config: $external,
    repo: $repo
  }')

echo "POST $TINFOILD/dev-launch  name=$NAME repo=$REPO" >&2
curl -sS -X POST "$TINFOILD/dev-launch" \
  -H "Content-Type: application/json" \
  --data-binary "$PAYLOAD" \
| jq .
