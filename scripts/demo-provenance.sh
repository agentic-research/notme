#!/usr/bin/env bash
# demo-provenance.sh — prove who produced a release artifact, as an outsider.
#
# You are a third party. You have no credential, you run none of the issuer's
# software, and you have never touched their repository. You download a public
# artifact from someone else's release and establish which identity produced
# it — with curl, openssl and shasum.
#
# What this DOES prove:
#   · the artifact's signing certificate was issued by the key you pinned
#   · that identity names a specific repo, workflow and tag
#   · the credential was valid for five minutes and is now dead
#
# What it does NOT prove:
#   · that the key was never stolen — that is what revocation is for
#   · the bundle signature (Ed25519 over canonical CBOR — needs software)
#
# Usage:  scripts/demo-provenance.sh [--pause]
set -uo pipefail

ANCHOR="a2e571d8834225781873fa621ead03393d57dc05ff8379c64755d709018d36a4"
AUTHORITY="https://auth.notme.bot"
REPO="agentic-research/signet"
TAG="v0.3.0"
ASSET="signet-linux-amd64.signet.crt.pem"
PAUSE=0
[ "${1:-}" = "--pause" ] && PAUSE=1

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT; cd "$W"
b()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
run(){ printf '\033[36m$ %s\033[0m\n' "$*"; [ "$PAUSE" = 1 ] && read -r; eval "$*"; }
ok() { printf '  \033[32m%s\033[0m\n' "$*"; }
no() { printf '  \033[31m%s\033[0m\n' "$*"; }

for t in curl openssl shasum gh; do
  command -v "$t" >/dev/null || { echo "need: $t"; exit 2; }
done

b "0. The anchor — pinned BEFORE touching the network"
echo "  ${ANCHOR}"
echo "  Where you got this is the whole trust decision. It must not come from"
echo "  the authority you are about to check."

b "1. Download a real artifact from someone else's release"
run "gh release download ${TAG} --repo ${REPO} --pattern '${ASSET}' -D ."
[ -f "$ASSET" ] || { no "download failed"; exit 1; }
ok "got ${ASSET}"

b "2. What identity does it name?"
run "openssl x509 -in ${ASSET} -noout -subject -issuer -dates"
run "openssl x509 -in ${ASSET} -noout -ext subjectAltName | tail -1"
echo
echo "  A specific repository, at a specific tag, built by a specific workflow."
echo "  Note the dates: this credential lived for FIVE MINUTES."

b "3. Fetch the authority's key and check it against your anchor"
run "curl -s ${AUTHORITY}/.well-known/ca-bundle.pem -o root.pem"
LIVE=$(openssl x509 -in root.pem -pubkey -noout 2>/dev/null \
  | openssl pkey -pubin -outform der 2>/dev/null | shasum -a 256 | cut -d' ' -f1)
echo "  served: ${LIVE}"
echo "  anchor: ${ANCHOR}"
if [ "$LIVE" = "$ANCHOR" ]; then ok "MATCH"; else no "MISMATCH — stop here"; exit 1; fi
echo
echo "  This is CONTINUITY, not possession. A public certificate is public;"
echo "  anyone could serve these bytes. Possession is the next step."

b "4. Did that private key actually sign the artifact's certificate?"
echo "  -no_check_time because the credential expired five minutes after issue."
echo "  That is the design, not a workaround: the SIGNATURE outlives the"
echo "  CREDENTIAL, which is what makes short-lived identity usable for"
echo "  provenance at all."
run "openssl verify -no_check_time -CAfile root.pem ${ASSET}"

b "5. Is the authority still publishing revocation state?"
run "curl -s ${AUTHORITY}/internal/ca-bundle -o bundle.json"
AGE=$(( $(date +%s) - $(grep -o '"issuedAt":[0-9]*' bundle.json | cut -d: -f2) ))
echo "  bundle age: ${AGE}s (conformant verifiers refuse anything over 300s)"
if [ "$AGE" -lt 300 ]; then ok "FRESH"; else no "STALE — a verifier would refuse this"; fi
echo
echo "  Worth dwelling on: an authority can publish a perfectly VALID signature"
echo "  over a four-month-old bundle. It looks healthy unless you check the"
echo "  clock. This one did exactly that, for 130 days, until it was found."

b "What you just established"
cat <<'EOF'
  A specific GitHub workflow, at a specific tag, obtained an identity from
  this authority and signed a release artifact with it — and you confirmed
  that using a key you pinned in advance, with no credential of your own and
  none of the issuer's software.

  Not established: that the key was never stolen. That is revocation's job,
  which is why step 5 exists — and why a stale bundle is a real finding
  rather than a cosmetic one.
EOF
echo
