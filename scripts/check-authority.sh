#!/usr/bin/env bash
# check-authority.sh — continuity, freshness and proof-of-possession checks
# against a notme authority, using only curl, openssl and shasum.
#
# WHAT THIS IS NOT: it is NOT a full discharge of Goal Zero criterion (D)
# ("a third party can verify without trusting notme at the moment of the
# check"). An earlier version claimed that and was wrong in four ways, all
# found in review and all worth stating rather than quietly fixing:
#
#   1. It hardcoded the anchor and called it "out of band" — while shipping
#      inside the repository being evaluated. Anyone controlling the repo
#      controlled both the pin and the server. The pin is now REQUIRED INPUT.
#   2. It fetched the CA certificate and reported that the authority "holds
#      the key". Fetching a PUBLIC certificate proves the server serves those
#      bytes; anyone can re-serve them. Possession is now proved properly, by
#      verifying a leaf the private key actually signed.
#   3. It checked that the bundle had a "signature" FIELD and reported that as
#      a pass. Checking a field exists is not checking it is valid — the exact
#      defect pattern documented in docs/FINDINGS.md, shipped in the script
#      that documents it.
#   4. It presented discovery and build identity as verification. Both are
#      SELF-ASSERTED by the issuer and anchored to nothing; they are reported
#      as claims, and labelled as such.
#
# Usage:
#   scripts/check-authority.sh --spki <sha256> [--leaf <cert.pem>] [url]
#   NOTME_SPKI_SHA256=<sha256> scripts/check-authority.sh
#
# The SPKI hash MUST come from somewhere this authority does not control.
# Exit: 0 all checks passed · 1 a check failed · 2 usage or missing tool

set -uo pipefail

AUTHORITY="https://auth.notme.bot"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FAIL=0
# The anchor. REQUIRED INPUT, never a default — a pin that ships with the code
# being evaluated is not an anchor, it is a self-reference.
PINNED_SPKI="${NOTME_SPKI_SHA256:-}"
LEAF=""
ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --spki) PINNED_SPKI="$2"; shift 2 ;;
    --leaf) LEAF="$2"; shift 2 ;;
    *) ARGS+=("$1"); shift ;;
  esac
done
[ "${#ARGS[@]}" -gt 0 ] && AUTHORITY="${ARGS[0]}"
if [ -z "$PINNED_SPKI" ]; then
  echo "usage: $0 --spki <sha256-of-authority-SPKI> [--leaf cert.pem] [url]" >&2
  echo "  the hash must come from a source this authority does not control." >&2
  exit 2
fi

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
pass() { printf '  \033[32m✓\033[0m %s\n' "$*"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$*"; FAIL=1; }
note() { printf '    %s\n' "$*"; }

for t in curl openssl shasum; do
  command -v "$t" >/dev/null || { echo "missing required tool: $t"; exit 2; }
done

bold "Checking ${AUTHORITY}"
echo "  tools: curl, openssl, shasum — no issuer software"
echo

# ── 1. The anchor, supplied by the caller ───────────────────────────────────
bold "1. Anchor (caller-supplied)"
note "SPKI SHA-256: ${PINNED_SPKI}"
note "This script does not know where you got it. If it came from this"
note "authority, nothing below means anything."
echo

# ── 2. Does the served key match the anchor? ────────────────────────────────
# CONTINUITY, not possession. A matching hash proves the server SERVES the
# certificate you pinned. It does NOT prove it holds the private key —
# a public certificate is public, and anyone can re-serve it. Possession is
# check 3, and only with --leaf.
bold "2. The served certificate matches the anchor"
if ! curl -fsS "${AUTHORITY}/.well-known/ca-bundle.pem" -o "$WORK/root.pem"; then
  fail "could not fetch the CA bundle"
else
  LIVE_SPKI=$(openssl x509 -in "$WORK/root.pem" -pubkey -noout 2>/dev/null \
    | openssl pkey -pubin -outform der 2>/dev/null | shasum -a 256 | cut -d' ' -f1)
  # SPKI, not the certificate: the KEY is the identity. A re-issued certificate
  # over the same key is the same authority; a new key is not.
  [ "$LIVE_SPKI" = "$PINNED_SPKI" ] \
    && pass "served public key matches the anchor" \
    || fail "KEY MISMATCH — served ${LIVE_SPKI:0:16}… vs anchor ${PINNED_SPKI:0:16}…"
  openssl x509 -in "$WORK/root.pem" -noout -checkend 0 >/dev/null 2>&1 \
    && pass "certificate is within its validity window" \
    || fail "certificate is expired or not yet valid"
fi
echo

# ── 3. Proof of possession — the only check that proves a private key ───────
# Verifying that a LEAF chains to the anchor proves the anchor's PRIVATE key
# signed it. Nothing else here does. Without --leaf this is skipped, and the
# script says so rather than implying possession from check 2.
bold "3. Proof of possession"
if [ -z "$LEAF" ]; then
  note "SKIPPED — no --leaf supplied."
  note "Continuity alone does not prove the authority holds its private key."
  note "Pass a credential it issued:  --leaf agent-cert.pem"
elif [ ! -f "$LEAF" ]; then
  fail "leaf file not found: $LEAF"
elif openssl verify -CAfile "$WORK/root.pem" "$LEAF" >/dev/null 2>&1; then
  pass "leaf chains to the anchor — the private key signed it"
  note "subject: $(openssl x509 -in "$LEAF" -noout -subject 2>/dev/null | sed 's/^subject=//')"
  SAN=$(openssl x509 -in "$LEAF" -noout -ext subjectAltName 2>/dev/null | tail -1 | tr -d ' ')
  [ -n "$SAN" ] && note "SAN: ${SAN}"
else
  fail "leaf does NOT chain to the anchor"
fi
echo

# ── 4. Revocation-bundle freshness ─────────────────────────────────────────
# The check most systems lack. An authority can publish a perfectly VALID
# signature over a four-month-old bundle, and that is indistinguishable from
# a healthy one unless you look at the clock. This repo shipped exactly that
# for 130 days (notme-77a024).
#
# NOTE the signature is NOT verified here — see the closing section. Checking
# a "signature" field EXISTS would be theatre, so it is not done at all.
bold "4. Revocation bundle freshness"
if curl -fsS "${AUTHORITY}/internal/ca-bundle" -o "$WORK/bundle.json"; then
  ISSUED=$(grep -o '"issuedAt":[0-9]*' "$WORK/bundle.json" | cut -d: -f2)
  EPOCH=$(grep -o '"epoch":[0-9]*' "$WORK/bundle.json" | cut -d: -f2)
  SEQNO=$(grep -o '"seqno":[0-9]*' "$WORK/bundle.json" | cut -d: -f2)
  AGE=$(( $(date +%s) - ${ISSUED:-0} ))
  note "epoch=${EPOCH} seqno=${SEQNO} age=${AGE}s"
  [ "$AGE" -lt 300 ] \
    && pass "within the 5-minute staleness window" \
    || fail "STALE by $(( AGE / 86400 ))d — a conformant verifier would refuse this"
else
  fail "could not fetch the bundle"
fi
echo

# ── 5. Issuer self-assertions — reported, NOT verified ─────────────────────
# Discovery and build identity are things the server says about ITSELF,
# anchored to nothing. Useful for accountability; worthless against a
# malicious server, which would simply say something else. Labelled so no
# reader mistakes them for verification.
bold "5. Issuer self-assertions (NOT verified)"
if curl -fsS "${AUTHORITY}/.well-known/signet-authority.json" -o "$WORK/disc.json"; then
  note "claims issuer: $(grep -o '"issuer"[^,]*' "$WORK/disc.json" | head -1 | cut -d'"' -f4)"
fi
if curl -fsS "${AUTHORITY}/.well-known/version" -o "$WORK/ver.json"; then
  note "claims build:  $(grep -o '"commit":"[^"]*"' "$WORK/ver.json" | cut -d'"' -f4 | cut -c1-12)"
fi
echo

# ── Boundaries, stated ──────────────────────────────────────────────────────
bold "Not proven here"
note "The bundle SIGNATURE (Ed25519 over canonical CBOR, RFC 8949 §4.2) is not"
note "checked — verifying it needs a CBOR encoder, therefore software, therefore"
note "a dependency on the issuer's ecosystem rather than on stock tools."
note ""
note "Without --leaf, nothing here proves the authority holds its private key."
note "Continuity and freshness are real properties; they are not that one."
echo

[ "$FAIL" -eq 0 ] && bold "All checks passed." || bold "SOME CHECKS FAILED"
exit "$FAIL"
