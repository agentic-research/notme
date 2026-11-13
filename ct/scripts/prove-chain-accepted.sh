#!/usr/bin/env bash
# Reproduce the A/B that proves azul accepts a notme chain (notme-1b46a8).
#
# Submits ONE certificate chain to two log shards that differ in exactly one
# config field. If the lenient shard 200s and the strict twin 400s, then:
#
#   - azul's Ed25519 arm (cloudflare/azul#281) verifies notme's real chain;
#     otherwise the lenient shard would fail too, for the same reason.
#   - require_server_auth_eku is load-bearing, and its default still refuses
#     a non-serverAuth leaf exactly as RFC 6962 §3.1 requires.
#
# Usage: LOG=http://localhost:8787 CHAIN=/path/to/chain.json ./prove-chain-accepted.sh
set -euo pipefail
LOG="${LOG:-http://localhost:8787}"
# NB: no braces in this message. A `}` inside ${VAR:?...} closes the expansion
# early and the remainder becomes part of the value — which silently appended
# a `}` to the path and made every run fail to read the file.
CHAIN="${CHAIN:?set CHAIN to a JSON file holding a chain array of base64 DER certs}"

probe() { # shard
  curl -s -o /tmp/ct-body.$$ -w '%{http_code}' --max-time 25 \
    -X POST "${LOG}/logs/$1/ct/v1/add-chain" -d @"${CHAIN}"
}

lenient=$(probe notmedev)
lenient_body=$(cat /tmp/ct-body.$$)
strict=$(probe notmestrict)
strict_body=$(cat /tmp/ct-body.$$)
rm -f /tmp/ct-body.$$

echo "notmedev    (require_server_auth_eku=false) -> ${lenient}"
echo "notmestrict (default, serverAuth required)  -> ${strict}"

fail=0
if [ "${lenient}" != "200" ]; then
  echo "FAIL: the lenient shard refused a valid notme chain: ${lenient_body}" >&2
  fail=1
elif ! printf '%s' "${lenient_body}" | grep -q '"extensions"'; then
  echo "FAIL: 200 with no SCT extensions — no leaf_index was issued" >&2
  fail=1
fi
if [ "${strict}" != "400" ]; then
  echo "FAIL: the strict twin accepted a clientAuth-only leaf (${strict}); the" >&2
  echo "      default must keep refusing it, or upstream behaviour changed." >&2
  fail=1
fi
[ "${fail}" -eq 0 ] && echo "OK — accepted where configured, refused where not."
exit "${fail}"
