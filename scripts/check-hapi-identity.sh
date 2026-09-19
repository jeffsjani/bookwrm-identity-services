#!/usr/bin/env bash

set -euo pipefail

read -r -s -p "HAPI bridge service key: " HAPI_BRIDGE_KEY
printf '\n'

if [[ -z "$HAPI_BRIDGE_KEY" ]]; then
  printf 'A service key is required.\n' >&2
  exit 1
fi

trap 'unset HAPI_BRIDGE_KEY' EXIT

printf 'url = "https://bookwrm-identity-services-production.up.railway.app/internal/hapi/identity/context"\nrequest = "POST"\nheader = "Authorization: Bearer %s"\nheader = "Content-Type: application/json"\ndata = "{\\"userId\\":\\"test\\"}"\nwrite-out = "\\nHTTP %%{http_code}\\n"\n' "$HAPI_BRIDGE_KEY" \
  | curl --silent --show-error --config -