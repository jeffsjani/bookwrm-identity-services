#!/bin/sh
set +x
if [ -n "${NODE_OPTIONS-}" ]; then
  printf '%s\n' 'WORKER_FAIL: NODE_OPTIONS is not allowed' >&2
  exit 1
fi
exec node hapi-5c4-worker/launcher.mjs --serve