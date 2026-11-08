#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
SIG=$(printf '%s' '{"alert":{"rule":{"id":100100,"level":10},"data":{"srcip":"198.51.100.7"}}}' \
  | openssl dgst -sha256 -hmac "$(grep ^HMAC_SECRET .env | cut -d= -f2)" | sed 's/^.* //')
curl -fsS -X POST localhost:8080/ingest/wazuh \
  -H "X-Signature: sha256=$SIG" -H 'Content-Type: application/json' \
  -d '{"alert":{"rule":{"id":100100,"level":10},"data":{"srcip":"198.51.100.7"}}}'
echo
