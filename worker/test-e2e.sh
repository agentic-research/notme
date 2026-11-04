#!/usr/bin/env bash
# E2E contract tests — starts workerd with an operator BOOTSTRAP_CODE, runs Playwright.
# Usage: cd worker && bash test-e2e.sh
set -euo pipefail

STORAGE_DIR="/tmp/notme-e2e"
CONFIG_LOCAL="config-e2e.capnp"
PORT=8788
LOGFILE="/tmp/notme-e2e-workerd.log"

cleanup() {
  if [ -n "${WPID:-}" ]; then
    # The npm `workerd` bin is a node launcher that spawns the native binary;
    # killing only the launcher orphans workerd still holding the port.
    pkill -P "$WPID" 2>/dev/null || true
    kill "$WPID" 2>/dev/null || true
    wait "$WPID" 2>/dev/null || true
  fi
  rm -rf "$STORAGE_DIR" "$CONFIG_LOCAL"
}
trap cleanup EXIT

# ── Build ──
echo "▸ Building dist/worker.js..."
npm run build:local --silent

# ── Bootstrap code ──
# The worker no longer mints or logs a bootstrap code (notme-addef9): the
# operator sets BOOTSTRAP_CODE, exactly as a deployment would. This run is the
# operator, so it generates one, binds it into its own copy of config.capnp,
# and hands the same value to Playwright. It used to grep workerd's stdout for
# "BOOTSTRAP CODE:", which matched nothing, so the registration tests always
# skipped (notme-05324c).
BOOTSTRAP_CODE=$(openssl rand -hex 20)

# ── Start workerd ──
rm -rf "$STORAGE_DIR" && mkdir -p "$STORAGE_DIR"
sed "s|path = \"/data/do\"|path = \"$STORAGE_DIR\"|" config.capnp |
  awk -v code="$BOOTSTRAP_CODE" '
    { print }
    /^  bindings = \[$/ && !done {
      print "    ( name = \"BOOTSTRAP_CODE\", text = \"" code "\" ),"
      done = 1
    }
    END { if (!done) { print "test-e2e.sh: no bindings list in config.capnp" > "/dev/stderr"; exit 1 } }
  ' > "$CONFIG_LOCAL"

echo "▸ Starting workerd on :$PORT..."
# workerd is not a direct dependency of worker/ (pnpm installs it under
# wrangler → miniflare), so ./node_modules/workerd does not exist. Resolve the
# binary wrangler itself runs: the same build the gate tests against.
WORKERD="${WORKERD:-$(node -e 'const w = require.resolve("wrangler/package.json");
  const m = require.resolve("miniflare", { paths: [w] });
  console.log(require.resolve("workerd/bin/workerd", { paths: [m] }))')}"
"$WORKERD" serve "$CONFIG_LOCAL" --experimental > "$LOGFILE" 2>&1 &
WPID=$!
sleep 3

if ! kill -0 "$WPID" 2>/dev/null; then
  echo "✗ workerd failed to start. Logs:"
  cat "$LOGFILE"
  exit 1
fi
echo "✓ workerd running (PID $WPID)"

# ── Run Playwright ──
echo ""
echo "▸ Running Playwright contract tests..."
NOTME_BOOTSTRAP_CODE="$BOOTSTRAP_CODE" npx playwright test e2e/contract.spec.ts --reporter=list "$@"
