#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Checks a running compose deployment the way an operator would, from outside:
#
#   ./verify.sh ready        the proxy completes mTLS and answers an unsigned request with a
#                            refusal (403): it is up, and it fails closed
#   ./verify.sh closed       a connection with no client certificate is refused
#
# Needs the evaluation material from ./dev-pki.sh (or the same file names from your own CA)
# and curl. `ready` retries for up to 60 seconds, since the proxy waits on Redis.
set -euo pipefail
cd "$(dirname "$0")"
NAME="${MCP_RE_SERVER_NAME:-mcp-re-proxy}"
PORT=8600
CURL=(curl -sS --max-time 10 --resolve "$NAME:$PORT:127.0.0.1" --cacert secrets/server/client-ca.pem
  -X POST -H 'content-type: application/json' -d '{}' -o /dev/null -w '%{http_code}')
URL="https://$NAME:$PORT/mcp"

case "${1:-}" in
  ready)
    code=""
    for _ in $(seq 30); do
      code="$("${CURL[@]}" --cert secrets/client/client-tls.pem --key secrets/client/client-tls.key "$URL" 2>/dev/null || true)"
      if [[ "$code" == 403 ]]; then echo "ready: unsigned request refused with HTTP 403"; exit 0; fi
      sleep 2
    done
    echo "verify: proxy not ready (last status '${code:-none}')" >&2
    exit 1 ;;
  closed)
    if "${CURL[@]}" "$URL" >/dev/null 2>&1; then
      echo "verify: a connection without a client certificate was accepted" >&2
      exit 1
    fi
    echo "closed: connection without a client certificate refused" ;;
  *) echo "usage: verify.sh ready|closed" >&2; exit 2 ;;
esac
