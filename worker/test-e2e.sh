#!/usr/bin/env bash
# E2E contract tests — starts workerd, extracts bootstrap code, runs Playwright.
# Usage: cd worker && bash test-e2e.sh
set -euo pipefail

STORAGE_DIR="/tmp/notme-e2e"
CONFIG_LOCAL="config-e2e.capnp"
PORT=8788
LOGFILE="/tmp/notme-e2e-workerd.log"

cleanup() {
  if [ -n "${WPID:-}" ]; then
    kill "$WPID" 2>/dev/null || true
    wait "$WPID" 2>/dev/null || true
  fi
  rm -rf "$STORAGE_DIR" "$CONFIG_LOCAL"
}
trap cleanup EXIT

# ── Build ──
echo "▸ Building dist/worker.js..."
npm run build:local --silent

# ── Start workerd ──
rm -rf "$STORAGE_DIR" && mkdir -p "$STORAGE_DIR"
sed "s|path = \"/data/do\"|path = \"$STORAGE_DIR\"|" config.capnp > "$CONFIG_LOCAL"

echo "▸ Starting workerd on :$PORT..."
./node_modules/workerd/bin/workerd serve "$CONFIG_LOCAL" --experimental > "$LOGFILE" 2>&1 &
WPID=$!
sleep 3

if ! kill -0 "$WPID" 2>/dev/null; then
  echo "✗ workerd failed to start. Logs:"
  cat "$LOGFILE"
  exit 1
fi
echo "✓ workerd running (PID $WPID)"

# ── Extract bootstrap code ──
# Trigger bootstrap code generation by requesting registration options
echo "▸ Triggering bootstrap code generation..."
curl -sf -X POST "http://localhost:$PORT/auth/passkey/register/options" \
  -H "Content-Type: application/json" \
  -d '{}' > /dev/null 2>&1 || true

# Give workerd a moment to log the code
sleep 1

# Parse bootstrap code from workerd stdout
BOOTSTRAP_CODE=$(grep -o 'BOOTSTRAP CODE: [a-f0-9-]*' "$LOGFILE" | head -1 | cut -d' ' -f3)

if [ -z "$BOOTSTRAP_CODE" ]; then
  echo "⚠ No bootstrap code found in logs (may not be needed if already consumed)"
  echo "  Running tests without NOTME_BOOTSTRAP_CODE..."
else
  echo "✓ Bootstrap code: ${BOOTSTRAP_CODE:0:8}..."
fi

# ── Run Playwright ──
echo ""
echo "▸ Running Playwright contract tests..."
NOTME_BOOTSTRAP_CODE="$BOOTSTRAP_CODE" npx playwright test e2e/contract.spec.ts --reporter=list "$@"
