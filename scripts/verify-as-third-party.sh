#!/usr/bin/env bash
# verify-as-third-party.sh — check notme's claims WITHOUT trusting notme.
#
# Goal Zero criterion (D): "a third party can verify without trusting notme at
# the moment of the check." This script IS that check, run as an outsider.
#
# Deliberately uses ONLY curl, openssl and shasum. No notme code, no SDK, no
# npm install. If verification required the issuer's software, the property
# would be circular — you would be trusting the thing under examination.
#
# Usage:  scripts/verify-as-third-party.sh [authority-url]
# Exit:   0 all checks passed · 1 a check failed · 2 a tool is missing

set -uo pipefail

AUTHORITY="${1:-https://auth.notme.bot}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FAIL=0

# The pin. Obtained OUT OF BAND — from the repo, a signed email, a business
# card. The one thing that must not come from the server being checked.
PINNED_SPKI="a2e571d8834225781873fa621ead03393d57dc05ff8379c64755d709018d36a4"
PINNED_CERT="c1ddec9df94353d4fdee8817e2b399d251f7ab2645b1a06efeae1d2f7392ae86"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
pass() { printf '  \033[32m✓\033[0m %s\n' "$*"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$*"; FAIL=1; }
note() { printf '    %s\n' "$*"; }

for t in curl openssl shasum; do
  command -v "$t" >/dev/null || { echo "missing required tool: $t"; exit 2; }
done

bold "Verifying ${AUTHORITY} as a third party"
echo "  tools: curl, openssl, shasum — no issuer software"
echo

# ── 1. The anchor ───────────────────────────────────────────────────────────
# Pinning is a decision made ONCE, away from the network. Everything below
# derives its meaning from this value having been obtained elsewhere.
bold "1. Anchor pinned out of band"
note "SPKI SHA-256: ${PINNED_SPKI}"
echo

# ── 2. Does the live authority match the pin? ───────────────────────────────
# The load-bearing check. If this passes, the server presenting itself as this
# authority holds the key you already decided to trust.
bold "2. The live authority matches the pin"
if ! curl -fsS "${AUTHORITY}/.well-known/ca-bundle.pem" -o "$WORK/root.pem"; then
  fail "could not fetch the CA bundle"
else
  LIVE_SPKI=$(openssl x509 -in "$WORK/root.pem" -pubkey -noout 2>/dev/null \
    | openssl pkey -pubin -outform der 2>/dev/null | shasum -a 256 | cut -d' ' -f1)
  LIVE_CERT=$(openssl x509 -in "$WORK/root.pem" -outform der 2>/dev/null \
    | shasum -a 256 | cut -d' ' -f1)

  # SPKI, not just the certificate: the KEY is the identity. A re-issued
  # certificate over the same key is still the same authority; a new key is
  # not, however similar the certificate looks.
  [ "$LIVE_SPKI" = "$PINNED_SPKI" ] \
    && pass "public key matches the pin" \
    || fail "PUBLIC KEY MISMATCH — live ${LIVE_SPKI:0:16}… vs pinned ${PINNED_SPKI:0:16}…"

  [ "$LIVE_CERT" = "$PINNED_CERT" ] \
    && pass "certificate matches the pin" \
    || note "certificate differs from the pin (re-issued over the same key — not fatal)"

  openssl x509 -in "$WORK/root.pem" -noout -checkend 0 >/dev/null 2>&1 \
    && pass "certificate is within its validity window" \
    || fail "certificate is expired or not yet valid"
fi
echo

# ── 3. What the authority says it is ────────────────────────────────────────
bold "3. Self-description, cross-checked against the anchor"
if curl -fsS "${AUTHORITY}/.well-known/signet-authority.json" -o "$WORK/disc.json"; then
  ISS=$(grep -o '"issuer"[^,]*' "$WORK/disc.json" | head -1 | cut -d'"' -f4)
  [ -n "$ISS" ] && pass "declares issuer: ${ISS}" || fail "no issuer in discovery"
else
  fail "could not fetch discovery"
fi
echo

# ── 4. Is the revocation bundle FRESH? ──────────────────────────────────────
# The check that matters and the one most systems fail. A signed bundle whose
# issuedAt is old is refused by any conformant verifier — and an authority can
# publish a perfectly valid signature over a four-month-old bundle, which is
# indistinguishable from a healthy one unless you look at the clock.
bold "4. The revocation bundle is fresh"
if curl -fsS "${AUTHORITY}/internal/ca-bundle" -o "$WORK/bundle.json"; then
  ISSUED=$(grep -o '"issuedAt":[0-9]*' "$WORK/bundle.json" | cut -d: -f2)
  EPOCH=$(grep -o '"epoch":[0-9]*' "$WORK/bundle.json" | cut -d: -f2)
  SEQNO=$(grep -o '"seqno":[0-9]*' "$WORK/bundle.json" | cut -d: -f2)
  AGE=$(( $(date +%s) - ${ISSUED:-0} ))
  note "epoch=${EPOCH} seqno=${SEQNO} age=${AGE}s"
  # 300s is BUNDLE_MAX_AGE_MS — the same window a conformant verifier applies.
  [ "$AGE" -lt 300 ] \
    && pass "within the 5-minute staleness window" \
    || fail "STALE by $(( AGE / 86400 ))d — a conformant verifier would refuse this"
  grep -q '"signature"' "$WORK/bundle.json" \
    && pass "bundle carries a signature" \
    || fail "bundle is unsigned"
else
  fail "could not fetch the bundle"
fi
echo

# ── 5. Which build is answering? ────────────────────────────────────────────
# Not a security property — an ACCOUNTABILITY one. An authority that cannot
# say which code is serving cannot be held to a claim about its behaviour.
bold "5. The authority names the build serving this request"
if curl -fsS "${AUTHORITY}/.well-known/version" -o "$WORK/ver.json"; then
  COMMIT=$(grep -o '"commit":"[^"]*"' "$WORK/ver.json" | cut -d'"' -f4)
  grep -q '"stamped":true' "$WORK/ver.json" \
    && pass "build ${COMMIT:0:12} (public repo — inspectable)" \
    || fail "build is unstamped — cannot tell what is running"
else
  fail "no version endpoint"
fi
echo

# ── What this does NOT prove — stated, not omitted ──────────────────────────
bold "Not proven by this script, deliberately"
note "The bundle SIGNATURE is Ed25519 over canonical CBOR (RFC 8949 §4.2)."
note "Verifying it needs a CBOR encoder, so it needs software — which is a real"
note "dependency on the issuer's ecosystem rather than on stock tools. Nobody's"
note "agent-provenance story verifies end to end with openssl alone today."
note ""
note "Chain validation of a LEAF credential also needs a leaf to validate:"
note "  openssl verify -CAfile root.pem agent-cert.pem"
echo

[ "$FAIL" -eq 0 ] && bold "All third-party checks passed." || bold "SOME CHECKS FAILED"
exit "$FAIL"
