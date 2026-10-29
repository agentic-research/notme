#!/usr/bin/env bash
# KEK rehearsal: turn on at-rest encryption of the CA key, and PROVE the
# recovery path before production depends on it (notme-41d0d3).
#
# Why a rehearsal and not just `wrangler secret put`: cloister fails closed
# when notme cannot serve (its ADR-0053), so a notme outage is a cloister
# outage. Once NOTME_KEK_SECRET is set, the stored CA key is sealed under it,
# and losing the secret BRICKS the authority by design — readStoredJwk throws
# rather than minting a new root that would orphan every issued credential.
# The operator must therefore have exercised "secret gone → restore it" at
# least once, with the time measured, before relying on it.
#
#   staging    full rehearsal: enable, prove the row is sealed by withdrawing
#              the secret (the authority must fail closed), restore it, and
#              time the recovery. The key must be the SAME one throughout.
#   production --enable only: set the secret, confirm the same key is served.
#              Never withdraws anything.
#
# Usage:
#   scripts/kek-rehearsal.sh staging    <kek-file>
#   scripts/kek-rehearsal.sh production <kek-file> --enable
#
# <kek-file> holds the secret: 64 hex chars, mode 0600, kept somewhere durable
# (a password manager) BEFORE this runs. Generate with:
#   umask 077 && openssl rand -hex 32 > ~/.notme/kek-staging
# The value is piped to wrangler and never printed.
set -euo pipefail

ENV_NAME="${1:-}"; KEK_FILE="${2:-}"; MODE="${3:-}"
case "$ENV_NAME" in
  staging) BASE="https://auth-staging.notme.bot"; WENV=(--env staging) ;;
  production)
    BASE="https://auth.notme.bot"; WENV=()
    [[ "$MODE" == "--enable" ]] || { echo "production supports --enable only; rehearse on staging" >&2; exit 2; } ;;
  *) sed -n '2,27p' "$0" >&2; exit 2 ;;
esac
[[ -f "$KEK_FILE" ]] || { echo "no kek file: $KEK_FILE" >&2; exit 2; }
perm=$(stat -f '%Lp' "$KEK_FILE" 2>/dev/null || stat -c '%a' "$KEK_FILE")
[[ "$perm" == "600" ]] || { echo "$KEK_FILE must be mode 600 (is $perm)" >&2; exit 2; }
[[ "$(tr -d '\n' < "$KEK_FILE")" =~ ^[0-9a-f]{64}$ ]] || { echo "$KEK_FILE must hold 64 lowercase hex chars (openssl rand -hex 32)" >&2; exit 2; }

cd "$(dirname "$0")/../worker"
wr() { pnpm exec wrangler "$@" "${WENV[@]}"; }
now() { date +%s; }

# A random query string defeats the Cache API (the key includes the query),
# so every probe reaches the Durable Object and its key load.
PROBE=$(mktemp)
probe() { curl -s -o "$PROBE" -w '%{http_code}' "$BASE/.well-known/jwks.json?r=$RANDOM$RANDOM"; }
kid() { python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["keys"][0]["kid"])' "$PROBE"; }
trap 'rm -f "$PROBE"' EXIT

# Wait (up to 90s) for the probe to return the wanted status class.
await() { # $1 = ok|fail
  for _ in $(seq 1 45); do
    c=$(probe)
    if [[ $1 == ok && $c == 200 ]] || [[ $1 == fail && $c != 200 ]]; then echo "$c"; return 0; fi
    sleep 2
  done
  echo "$c"; return 1
}

c=$(probe); [[ $c == 200 ]] || { echo "baseline: $BASE answered $c — fix that first" >&2; exit 1; }
KID0=$(kid); echo "baseline        key $KID0"

t=$(now)
tr -d '\n' < "$KEK_FILE" | wr secret put NOTME_KEK_SECRET >/dev/null
await ok >/dev/null || { echo "FAIL: authority did not come back after enabling" >&2; exit 1; }
KID1=$(kid)
[[ $KID1 == "$KID0" ]] || { echo "FAIL: key changed on enable ($KID0 → $KID1) — STOP, do not continue" >&2; exit 1; }
echo "enabled         key $KID1 (same), $(( $(now) - t ))s"

if [[ $ENV_NAME == production ]]; then
  echo "production sealed on its next cold key load. Keep $KEK_FILE's value safe: losing it bricks the authority."
  exit 0
fi

# Withdraw the secret. If the row was sealed, the next cold load must THROW,
# and the authority must answer non-200 rather than serve a new key.
t=$(now)
printf 'y\n' | wr secret delete NOTME_KEK_SECRET >/dev/null
if code=$(await fail); then
  echo "withdrawn       fails closed ($code) after $(( $(now) - t ))s — the row is sealed"
else
  # Still 200: either the DO stayed warm (key in memory) or the row is NOT
  # sealed. Do not guess which.
  c=$(probe); k=$(kid 2>/dev/null || echo "?")
  echo "INCONCLUSIVE: still serving ($c, key $k) 90s after withdrawal." >&2
  echo "  Same key and a warm DO is the likely reason; re-run after an eviction." >&2
  echo "  A DIFFERENT key here means regeneration — a bug: report it on notme-41d0d3." >&2
  tr -d '\n' < "$KEK_FILE" | wr secret put NOTME_KEK_SECRET >/dev/null
  exit 1
fi

# Recover: restore the SAME secret, measure time to serve again.
t=$(now)
tr -d '\n' < "$KEK_FILE" | wr secret put NOTME_KEK_SECRET >/dev/null
await ok >/dev/null || { echo "FAIL: did not recover within 90s of restoring the secret" >&2; exit 1; }
KID2=$(kid)
[[ $KID2 == "$KID0" ]] || { echo "FAIL: recovered with a different key ($KID2)" >&2; exit 1; }
echo "recovered       key $KID2 (same), time to recover $(( $(now) - t ))s"
echo "PASS: sealed, fails closed without the secret, recovers with it, key unchanged."
