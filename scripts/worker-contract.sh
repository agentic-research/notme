#!/usr/bin/env bash
# worker-contract.sh — boot the REAL Worker locally and run the post-deploy
# contract (scripts/worker-verify.sh) against it (notme-6ae724).
#
# Invoked by `task worker:contract`, locally and in ci.yml — one definition.
#
# ── WHY ──
# CI ran tsc, the plain suite and the vitest-pool-workers suite, but nothing
# ran the post-deploy checks before a deploy. `worker:verify` is the contract
# that has caught every production regression in this repo's history (served
# pathlen:0, unmatched paths as 1101, unstamped builds), and it only ever ran
# AFTER the build was serving traffic.
#
# ── THE CONFIG IS DERIVED, NOT HAND-COPIED ──
# The live wrangler.toml is gitignored (it holds account resource ids), so CI
# derives its config from the committed production template,
# worker/wrangler.toml.example, dropping only what cannot run without a
# Cloudflare account:
#   - [[vpc_services]] — forces wrangler to open a REMOTE connection;
#   - [[routes]]       — zone routing, meaningless locally;
#   - [env.*]          — other environments.
# Every binding, rate limiter, DO class, migration and `run_worker_first` that
# production declares is therefore in the booted Worker by construction: a
# binding added to production cannot be silently absent here. (The e2e config,
# wrangler.e2e.toml, is a hand-written subset for one purpose and is left alone.)
#
# ── TWO HOSTS, ONE PORT ──
# The Worker picks its surface by Host. `localhost:<port>` is the authority
# (SIGNET_AUTHORITY_URL) and `127.0.0.1:<port>` the site (SITE_URL), which is
# the production split (auth.notme.bot / notme.bot) on one local listener.
# SITE_URL deliberately does not start with http://localhost: that would put
# the Worker in its local-dev mode, which serves the authority on every host
# and disables the Cache API — i.e. not the code path production runs.
#
# No CLOUDFLARE_API_TOKEN is used or needed; it is blanked so wrangler cannot
# reach for an account even if one is configured on the machine.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${CONTRACT_PORT:-8790}"
AUTH_BASE="http://localhost:${PORT}"
SITE_BASE="http://127.0.0.1:${PORT}"
STATE="$(mktemp -d)"
CONFIG_DIR="$ROOT/worker/.wrangler"
CONFIG="$CONFIG_DIR/contract.toml"
LOG="$STATE/wrangler.log"
BUILD_SHA="$(git -C "$ROOT" rev-parse HEAD)"

mkdir -p "$CONFIG_DIR"
# Section filter: a table header decides whether the lines under it are kept.
# Paths are rewritten because the derived file lives one directory down.
awk '
  /^[[:space:]]*\[/ {
    name = $0
    gsub(/^[[:space:]]*\[+[[:space:]]*|[[:space:]]*\]+.*$/, "", name)
    drop = (name == "vpc_services" || name == "routes" || name ~ /^env\./)
  }
  !drop
' "$ROOT/worker/wrangler.toml.example" \
  | sed -e 's|^main = "worker.ts"|main = "../worker.ts"|' \
        -e 's|^directory = "public"|directory = "../public"|' \
  > "$CONFIG"

grep -q '^main = "../worker.ts"' "$CONFIG" || { echo "✗ derived config lost its main entry"; exit 1; }
grep -q 'vpc_services' "$CONFIG" && { echo "✗ derived config still binds a VPC service"; exit 1; }

# wrangler dev runs node → workerd children. Killing only the parent leaves
# workerd holding the port and the script waiting on it, so take the TREE
# down, leaves first.
# shellcheck disable=SC2329  # called from cleanup (EXIT trap)
killtree() {
  local child
  for child in $(pgrep -P "$1" 2>/dev/null); do killtree "$child"; done
  kill "$1" 2>/dev/null || true
}
# shellcheck disable=SC2329  # invoked by the EXIT trap
cleanup() {
  if [ -n "${WPID:-}" ]; then
    killtree "$WPID"
    wait "$WPID" 2>/dev/null || true
  fi
  rm -rf "$STATE"
}
trap cleanup EXIT

echo "▸ booting the Worker locally (config derived from wrangler.toml.example, build ${BUILD_SHA:0:12})"
(
  cd "$ROOT/worker"
  CLOUDFLARE_API_TOKEN="" WRANGLER_SEND_METRICS=false exec ./node_modules/.bin/wrangler dev \
    --config "$CONFIG" --port "$PORT" --ip 127.0.0.1 \
    --persist-to "$STATE/persist" \
    --var "BUILD_SHA:${BUILD_SHA}" \
    --var "SITE_URL:${SITE_BASE}" \
    --var "SIGNET_AUTHORITY_URL:${AUTH_BASE}" \
    --var "ALLOWED_AUDIENCES:${AUTH_BASE}" \
    </dev/null > "$LOG" 2>&1
) &
WPID=$!

# Bounded: --max-time because wrangler accepts the TCP connection before it
# can answer (see bootstrap-e2e.yml, where an unbounded probe hung the job).
up=0
for i in $(seq 1 60); do
  if curl -sf --max-time 2 -o /dev/null "${AUTH_BASE}/.well-known/version"; then
    echo "✓ worker up after ~${i}s"
    up=1
    break
  fi
  kill -0 "$WPID" 2>/dev/null || { echo "✗ wrangler exited during startup"; break; }
  sleep 1
done
if [ "$up" -ne 1 ]; then
  echo "--- wrangler log ---"
  cat "$LOG"
  exit 1
fi

status=0
VERIFY_MAX_ATTEMPTS="${VERIFY_MAX_ATTEMPTS:-3}" VERIFY_RETRY_DELAY_SECONDS="${VERIFY_RETRY_DELAY_SECONDS:-1}" \
  bash "$ROOT/scripts/worker-verify.sh" --auth-base "$AUTH_BASE" --site-base "$SITE_BASE" || status=$?

if [ "$status" -ne 0 ]; then
  echo "--- wrangler log (tail) ---"
  tail -60 "$LOG"
fi
exit "$status"
