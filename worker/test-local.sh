#!/usr/bin/env bash
# Smoke test for local workerd — build, start, verify, report, cleanup.
# Usage: cd worker && bash test-local.sh
set -euo pipefail

STORAGE_DIR="/tmp/notme-do-test"
CONFIG_LOCAL="config-local.capnp"
PORT=8788
BASE="http://localhost:$PORT"
FAIL=0

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

# ── Prepare config with local storage path ──
rm -rf "$STORAGE_DIR" && mkdir -p "$STORAGE_DIR"
sed "s|path = \"/data/do\"|path = \"$STORAGE_DIR\"|" config.capnp > "$CONFIG_LOCAL"

# ── Start workerd ──
echo "▸ Starting workerd on :$PORT..."
./node_modules/workerd/bin/workerd serve "$CONFIG_LOCAL" --experimental &
WPID=$!
sleep 3

if ! kill -0 "$WPID" 2>/dev/null; then
  echo "✗ workerd failed to start"
  exit 1
fi
echo "✓ workerd running (PID $WPID)"

# ── Helper ──
check() {
  local label="$1" url="$2" expect="$3"
  local body status
  body=$(curl -sf -w '\n%{http_code}' "$url" 2>&1) || body="CURL_FAIL\n000"
  status=$(echo "$body" | tail -1)
  body=$(echo "$body" | sed '$d')

  if echo "$body" | grep -q "$expect"; then
    echo "✓ $label (HTTP $status)"
  else
    echo "✗ $label (HTTP $status) — expected '$expect'"
    echo "  body: $(echo "$body" | head -3)"
    FAIL=1
  fi
}

# ── Endpoint checks ──
echo ""
echo "▸ Testing endpoints..."
check "discovery"       "$BASE/.well-known/signet-authority.json"  '"issuer"'
check "jwks"            "$BASE/.well-known/jwks.json"              '"OKP"'
check "ca-bundle"       "$BASE/.well-known/ca-bundle.pem"          "BEGIN CERTIFICATE"
# passkey-status requires auth — check it returns 401, not 500
check_status() {
  local label="$1" url="$2" expect_code="$3"
  local status
  status=$(curl -so /dev/null -w '%{http_code}' "$url" 2>/dev/null)
  if [ "$status" = "$expect_code" ]; then
    echo "✓ $label (HTTP $status)"
  else
    echo "✗ $label — expected HTTP $expect_code, got $status"
    FAIL=1
  fi
}
check_status "passkey-status (auth required)" "$BASE/auth/passkey/status" "401"

# ── Security: no private key in SQLite (invariant #1) ──
echo ""
echo "▸ Checking invariant #1 (no private key on disk)..."
if find "$STORAGE_DIR" -name "*.sqlite" -exec strings {} \; 2>/dev/null | grep -q '"d"'; then
  echo "✗ FAIL: private key 'd' field found in SQLite!"
  FAIL=1
else
  echo "✓ PASS: no private key on disk"
fi

# ── Summary ──
echo ""
if [ "$FAIL" -eq 0 ]; then
  echo "All checks passed."
else
  echo "SOME CHECKS FAILED"
  exit 1
fi
