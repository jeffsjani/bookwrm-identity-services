#!/bin/sh
set +x
if [ -n "${NODE_OPTIONS-}" ]; then
  printf '%s\n' 'WORKER_FAIL: NODE_OPTIONS is not allowed' >&2
  exit 1
fi
if [ "$#" -ne 1 ]; then
  printf '%s\n' 'WORKER_FAIL: manual action required' >&2
  exit 1
fi
case "$1" in
  --execute-once|--inspect) exec node hapi-5c4-worker/launcher.mjs "$1" ;;
  *) printf '%s\n' 'WORKER_FAIL: unsupported action' >&2; exit 1 ;;
esac