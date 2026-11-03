#!/usr/bin/env bash
# worker-verify.sh — the one definition of "the service works", run by
# `task worker:verify` against production, staging, or a local Worker
# (ci.yml boots one with `wrangler dev`).
#
# ── PINNED MODE: VERSION=<version-id> ENV=<production|staging> (notme-325916) ──
# A canary soak that sends ordinary requests measures whichever version the
# split routes to. A real 10/90 production canary served 85/85 samples from the
# OLD version, so a broken NEW version passed every soak check by never being
# asked. With VERSION set, every request carries Cloudflare's override header,
#
#     Cloudflare-Workers-Version-Overrides: <worker-name>="<version-id>"
#
# per https://developers.cloudflare.com/workers/configuration/versions-and-deployments/version-overrides/
# — and because Cloudflare IGNORES that header SILENTLY when the version is not
# in the current deployment (the request falls back to percentage routing),
# the header is a request, not a proof. So every check is bracketed by a pinned
# /.well-known/version probe that must report EXPECT, the build NEW was
# uploaded from (default: git HEAD). A pin that is not honoured fails the run;
# it cannot pass as evidence about the old version wearing the new one's id.
#
# A pinned pass writes $NOTME_EVIDENCE_DIR/<env>/<version-id>.json — the record
# `worker:promote` requires (notme-16b2d5). An unpinned run never writes one:
# it is a service-health check, not evidence about any one version.
#
# Run it DURING the canary (`worker:canary` puts NEW in the deployment) or
# after promotion. Before either, the override cannot apply, and this fails.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

FAIL=0
# Targets are ARGUMENTS (`task worker:verify` passes them), never read from
# the environment: an exported AUTH_BASE/ENV/VERSION/EXPECT in the operator's
# shell must not redirect a caller that stated its target — ship-prod's
# verify of production stayed production with ENV=staging exported only
# because of this (review M6).
AUTH_BASE="https://auth.notme.bot"
SITE_BASE="https://notme.bot"
VERSION=""
ENV_NAME=""
EXPECT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --auth-base) AUTH_BASE="${2:-}"; shift 2 ;;
    --site-base) SITE_BASE="${2:-}"; shift 2 ;;
    --env) ENV_NAME="${2:-}"; shift 2 ;;
    --version) VERSION="${2:-}"; shift 2 ;;
    --expect) EXPECT="${2:-}"; shift 2 ;;
    *) echo "✗ worker-verify: unknown argument '$1'"; exit 2 ;;
  esac
done
[ -n "$AUTH_BASE" ] && [ -n "$SITE_BASE" ] || { echo "✗ worker-verify: empty --auth-base/--site-base"; exit 2; }
# http:// as well, for a local Worker; the api-docs check wants a bare host.
AUTH_HOST="${AUTH_BASE#http*://}"
VERIFY_NONCE="$(date +%s)"
MAX_ATTEMPTS="${VERIFY_MAX_ATTEMPTS:-5}"
RETRY_DELAY_SECONDS="${VERIFY_RETRY_DELAY_SECONDS:-2}"
BODY_FILE="$(mktemp)"
trap 'rm -f "$BODY_FILE"' EXIT

EVIDENCE_DIR="${NOTME_EVIDENCE_DIR:-$PWD/.release-evidence}"
PIN=()
CHECKS=0
if [ -n "$VERSION" ]; then
  case "$ENV_NAME" in
    production) WORKER_NAME="notme-bot" ;;
    staging) WORKER_NAME="notme-bot-staging" ;;
    *) echo "✗ VERSION= needs ENV=production or ENV=staging — it names the Worker in the override header and keys the evidence"; exit 1 ;;
  esac
  [[ "$VERSION" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
    || { echo "✗ VERSION must be a full version id, got '$VERSION'"; exit 1; }
  [ -n "$EXPECT" ] || EXPECT="$(git rev-parse HEAD 2>/dev/null || true)"
  [[ "$EXPECT" =~ ^[0-9a-f]{40}$ ]] \
    || { echo "✗ EXPECT=<40-hex build sha of $VERSION> is required (git HEAD unavailable)"; exit 1; }
  PIN=(-H "Cloudflare-Workers-Version-Overrides: ${WORKER_NAME}=\"${VERSION}\"")
  echo "▸ pinned to ${WORKER_NAME}@${VERSION} (expected build ${EXPECT:0:12})"

  # A new pinned run SUPERSEDES any earlier record for this version: if this
  # run fails, no older pass may survive it (review M4).
  RECORD="$EVIDENCE_DIR/$ENV_NAME/$VERSION.json"
  rm -f "$RECORD"
fi

# Does Cloudflare say VERSION is serving traffic in this environment right now?
# The override is only applied to a version in the current deployment, and two
# versions can share a commit, so without this a pin that was silently ignored
# could pass on the old version's matching commit (review M5).
WRANGLER_CMD="${NOTME_WRANGLER_CMD:-pnpm exec wrangler}"
[ -n "${NOTME_WRANGLER_CMD:-}" ] && echo "⚠ NOTME_WRANGLER_CMD overrides wrangler: $WRANGLER_CMD"
deployment_serves_version() {
  local flags=()
  [ "$ENV_NAME" = staging ] && flags=(--env staging)
  # shellcheck disable=SC2086  # WRANGLER_CMD is a command line, split on purpose
  (cd worker && $WRANGLER_CMD deployments status --json ${flags[@]+"${flags[@]}"} 2>/dev/null) | node -e '
    let s = ""; process.stdin.on("data", (d) => (s += d)).on("end", () => {
      try {
        const v = (JSON.parse(s).versions || []).find((x) => x.version_id === process.argv[1]);
        process.exit(v && v.percentage > 0 ? 0 : 1);
      } catch { process.exit(1); }
    });
  ' "$VERSION"
}
if [ -n "$VERSION" ] && ! deployment_serves_version; then
  echo "✗ ${VERSION} is not serving in the current ${ENV_NAME} deployment (wrangler deployments status) — run task worker:canary first; a pin to an undeployed version is silently ignored"
  echo "SOME CHECKS FAILED"
  exit 1
fi

# curl with the pin (when there is one) on every request — including the ones
# that do not go through check_request, like the root-pathlen read.
pcurl() { curl ${PIN[@]+"${PIN[@]}"} "$@"; }

PIN_BROKEN=0
VERSION_ID_CHECKED=false
# Prove the pin held for the request about to be checked: ask the same base,
# pinned, which build AND which version is answering. The commit must equal
# EXPECT; the version id (from the version-metadata binding) must equal
# VERSION whenever the Worker reports one — it is the only field two versions
# of the same commit cannot share. $1 = base URL, $2 = label, $3 = attempts.
assert_pinned() {
  [ -n "$VERSION" ] || return 0
  local base="$1" label="$2" tries="${3:-1}" n=1 body="" got="" vid=""
  while [ "$n" -le "$tries" ]; do
    body=$(pcurl -sS --max-time 10 "${base}/.well-known/version" 2>/dev/null)
    got=$(printf '%s' "$body" | grep -o '"commit":"[0-9a-f]*"' | cut -d'"' -f4)
    vid=$(printf '%s' "$body" | grep -o '"version_id":"[^"]*"' | cut -d'"' -f4)
    if [ "$got" = "$EXPECT" ] && { [ -z "$vid" ] || [ "$vid" = unknown ] || [ "$vid" = "$VERSION" ]; }; then
      [ "$vid" = "$VERSION" ] && VERSION_ID_CHECKED=true
      return 0
    fi
    # Only the opening probe retries: Cloudflare notes a deployment change can
    # take a couple of seconds to propagate. Mid-run, a miss is a miss.
    [ "$n" -lt "$tries" ] && sleep "$RETRY_DELAY_SECONDS"
    n=$((n + 1))
  done
  if [ "$got" != "$EXPECT" ]; then
    echo "✗ pin not honoured before '$label': answered by build '${got:-none}', expected ${EXPECT:0:12} — ${VERSION} is not in the current deployment, or the override was ignored"
  else
    echo "✗ pin not honoured before '$label': answered by version '${vid}', not ${VERSION} (same commit — the override was ignored)"
  fi
  FAIL=1
  PIN_BROKEN=1
  return 1
}

check_request() {
  label="$1"
  method="$2"
  url="$3"
  expected_status="$4"
  expected_pattern="$5"
  data="${6:-}"
  accept="${7:-}"
  attempt=1
  CHECKS=$((CHECKS + 1))
  # Same origin as the check: both hosts route to this Worker.
  assert_pinned "$(printf '%s' "$url" | cut -d/ -f1-3)" "$label" || return 0

  while [ "$attempt" -le "$MAX_ATTEMPTS" ]; do
    if [ "$method" = "POST" ]; then
      status=$(pcurl -sS -o "$BODY_FILE" -w "%{http_code}" \
        -X POST "$url" -H "Content-Type: application/json" -d "$data")
    elif [ -n "$accept" ]; then
      status=$(pcurl -sS -o "$BODY_FILE" -w "%{http_code}" \
        -H "Accept: $accept" "$url")
    else
      status=$(pcurl -sS -o "$BODY_FILE" -w "%{http_code}" "$url")
    fi

    if [ "$status" = "$expected_status" ] && grep -Fq "$expected_pattern" "$BODY_FILE"; then
      echo "✓ $label"
      return 0
    fi

    if [ "$attempt" -lt "$MAX_ATTEMPTS" ]; then
      sleep "$RETRY_DELAY_SECONDS"
    fi
    attempt=$((attempt + 1))
  done

  detail=$(head -c 160 "$BODY_FILE" | tr '\n' ' ')
  echo "✗ $label (got $status; body: $detail)"
  FAIL=1
}

echo "=== ${AUTH_HOST} ==="
# Opening bracket, with retries for propagation. If the pin does not hold
# here, nothing below is evidence about $VERSION — stop rather than run a
# dozen checks against the wrong build.
if ! assert_pinned "$AUTH_BASE" "start" "$MAX_ATTEMPTS"; then
  echo "SOME CHECKS FAILED"
  exit 1
fi
check_request "landing" "GET" "${AUTH_BASE}/" "200" "identity authority"
check_request "login" "GET" "${AUTH_BASE}/login" "200" "passkey"
check_request "discovery" "GET" "${AUTH_BASE}/.well-known/signet-authority.json" "200" '"issuer"'
# Cache API entries survive Worker deployments, but every key carries
# the build (src/cache-key.ts), so this reads the NEW build's entry.
# No query: /.well-known/* keys ignore it (notme-ed6114) — a bypass
# that worked for the verifier worked for any flood too.
check_request "ca-bundle" "GET" "${AUTH_BASE}/.well-known/ca-bundle.pem" "200" "BEGIN CERTIFICATE"
# The SERVED root must carry the budget the code mints. Production
# served pathlen:0 for five months after the code moved to pathlen=1,
# because the DO's cache check asked only whether BasicConstraints
# existed (notme-1b1db4). Every Issuing CA tier minted under that root
# was unverifiable by any stock validator, and every test passed —
# against a fresh test root. This reads the LIVE root, not a fixture.
assert_pinned "$AUTH_BASE" "root-pathlen"
ROOT_PATHLEN=$(pcurl -s "${AUTH_BASE}/.well-known/ca-bundle.pem" \
  | openssl x509 -noout -text 2>/dev/null | grep -o 'pathlen:[0-9]*' | cut -d: -f2)
if [ "$ROOT_PATHLEN" = "1" ]; then
  echo "✓ root-pathlen (served root admits one intermediate tier)"
else
  echo "✗ root-pathlen: served root has pathlen '${ROOT_PATHLEN:-none}', code mints 1 — Issuing CA tiers cannot verify"
  FAIL=1
fi
# The committed trust anchor must still be what production serves.
# It went stale twice (2026-08-28 pathlen heal, 2026-10-28 notBefore
# re-issue) while trust-anchor.test.ts passed, because that test
# compares trust/ only to itself (notme-8e8836). Production only:
# trust/ pins the production authority.
if [ "$AUTH_BASE" = "https://auth.notme.bot" ]; then
  if pnpm exec tsx scripts/refresh-trust-anchor.ts --check; then
    echo "✓ trust-anchor (trust/ matches the served root)"
  else
    echo "✗ trust-anchor: trust/ disagrees with the served root (see above)"
    FAIL=1
  fi
fi
check_request "jwks" "GET" "${AUTH_BASE}/.well-known/jwks.json" "200" '"crv":"Ed25519"'
# The deployed build must be able to NAME ITSELF. Asserting
# "stamped":true rather than merely a 200: an endpoint that always
# answered "unknown" would pass a liveness check while telling a
# consumer nothing, which is the state that made signet's "no positive
# evidence" objection correct (notme-9f2f79). No nonce — it is
# no-store, so there is no cache entry to bypass.
check_request "build-version" "GET" "${AUTH_BASE}/.well-known/version" "200" '"stamped":true'
# Expect the environment's own authority host in the docs page — a
# staging deploy that renders production URLs is a config leak, not
# a pass. Nonce for the same reason as ca-bundle: Cache API entries
# survive deployments, and this handler cachePuts with max-age=3600.
check_request "api-docs" "GET" "${AUTH_BASE}/api/docs?verify=$VERIFY_NONCE" "200" "${AUTH_HOST}"
check_request "passkey-status" "GET" "${AUTH_BASE}/auth/passkey/status" "401" '"error":"unauthorized"'
check_request "authorize" "GET" "${AUTH_BASE}/authorize" "400" '"error":"redirect_uri required"'
check_request "token" "POST" "${AUTH_BASE}/token" "400" '"error":"dpop_proof_required"' '{"audience":"https://test"}'
# Every check above names a route that exists. Nothing covered the
# fallthrough, which is where notme-cb0354 lived: unmatched paths came
# back as error 1101 in production for as long as the VPC tunnel was
# unhealthy, and the gate stayed green throughout.
#
# The body pattern is the Worker's own constant 404, which it returns
# when the VPC fetch fails. A HEALTHY tunnel would instead hand back
# whatever signet answers for an unknown path, so if this check ever
# fails on the pattern rather than the status, read it as "the tunnel
# came up" and decide there whether signet's 404 shape is acceptable
# to expose — do not just relax the assertion. The status is the part
# that must never regress: 1101 surfaces as 500.
check_request "unmatched-path" "GET" "${AUTH_BASE}/.well-known/not-a-route-$VERIFY_NONCE" "404" '"error":"not_found"'

echo "=== ${SITE_BASE#http*://} ==="
check_request "homepage" "GET" "${SITE_BASE}/" "200" "notme"
check_request "apas" "GET" "${SITE_BASE}/apas?verify=$VERIFY_NONCE" "200" "0.2.1-draft"
check_request "apas-schema" "GET" "${SITE_BASE}/provenance/dispatch/v1?verify=$VERIFY_NONCE" "200" '"workItemRef"' "" "application/schema+json"

# Closing bracket: the last check was answered by the pinned build too.
check_count_before_close=$CHECKS
assert_pinned "$AUTH_BASE" "end"

echo "---"
if [ "$FAIL" -ne 0 ]; then
  echo "SOME CHECKS FAILED"
  exit 1
fi
echo "All checks passed."

if [ -n "$VERSION" ] && [ "$PIN_BROKEN" -eq 0 ]; then
  # Still serving at the end? A version rolled out of the deployment mid-run
  # would have had its later probes silently answered by another version.
  if ! deployment_serves_version; then
    echo "✗ ${VERSION} is no longer serving in the ${ENV_NAME} deployment — no evidence written"
    exit 1
  fi
  mkdir -p "$EVIDENCE_DIR/$ENV_NAME"
  printf '{"schema":"notme.release-evidence/v1","result":"pass","pinned":true,"version":"%s","env":"%s","commit":"%s","version_id_checked":%s,"auth_base":"%s","site_base":"%s","checks":%d,"checked_at":"%s"}\n' \
    "$VERSION" "$ENV_NAME" "$EXPECT" "$VERSION_ID_CHECKED" "$AUTH_BASE" "$SITE_BASE" "$check_count_before_close" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$RECORD"
  if [ "$VERSION_ID_CHECKED" = true ]; then
    echo "✓ evidence: $RECORD (every check answered by version ${VERSION} under the pin)"
  else
    echo "✓ evidence: $RECORD (identity by build ${EXPECT:0:12} + deployment listing; the Worker reports no version_id — add the [version_metadata] binding)"
  fi
fi
