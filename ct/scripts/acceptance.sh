#!/usr/bin/env bash
# End-to-end acceptance for issuance logging against a REAL azul log
# (notme-1b46a8, Task 6). See ct/README.md, "End-to-end acceptance".
#
#   CT_LOG_URL=http://localhost:8787/logs/notmedev \
#   AZUL_DIR=<azul worktree serving that log> \
#     ct/scripts/acceptance.sh
#
# 1. vitest (worker/vitest.workers.ct-live.config.mts): mint through
#    /cert/gha with the log up, down (dead port), and back (alarm drain);
#    asserts the authority's side and prints CT_ACCEPT lines.
# 2. azul sct_validator: the step-1 pair's embedded SCTs VERIFY, with a
#    wrong-key control and a no-SCT control.
# 3. azul integration_tests: the drained step-2 certs are X509 entries in the
#    log's signed tree, Merkle inclusion proven, with a never-add-chained
#    control.
#
# The two Rust files live in ct/acceptance/ and are copied into AZUL_DIR only
# for the run (removed on exit). Nothing is committed to azul.
#
# Exit: 0 all passed; 1 a step failed; 0 with SKIPPED when CT_LOG_URL is unset.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
if [ -z "${CT_LOG_URL:-}" ]; then
  echo "SKIPPED: no local log configured (CT_LOG_URL unset). See ct/README.md, 'End-to-end acceptance'."
  exit 0
fi
AZUL_DIR="${AZUL_DIR:?set AZUL_DIR to the azul worktree that serves CT_LOG_URL}"
OUT="${CT_ACCEPT_OUT:-$(mktemp -d)}"
mkdir -p "${OUT}"
ORIGIN="$(printf '%s' "${CT_LOG_URL}" | sed -E 's#^(https?://[^/]+).*#\1#')"
LOG_NAME="$(printf '%s' "${CT_LOG_URL}" | sed -E 's#.*/logs/([^/]+)/?$#\1#')"

code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "${CT_LOG_URL%/}/metadata.json")
[ "${code}" = "200" ] || { echo "FAIL: ${CT_LOG_URL}/metadata.json -> ${code}; is the log running?" >&2; exit 1; }
if curl -s -o /dev/null --max-time 3 http://127.0.0.1:1/; then
  echo "FAIL: something answers on 127.0.0.1:1, the proxy's dead port; step 2 would prove nothing" >&2; exit 1
fi

S1=fail S2=fail S3=fail
echo "== vitest (out: ${OUT}/vitest.log)"
( cd "${ROOT}/worker" && CT_LOG_URL="${CT_LOG_URL}" pnpm exec vitest run \
    --config vitest.workers.ct-live.config.mts --silent=false --reporter=verbose ) \
  > "${OUT}/vitest.log" 2>&1
VT=$?
grep -E '✓|✗|×|FAIL|Tests ' "${OUT}/vitest.log" | sed 's/^/   /'

# CT_ACCEPT lines -> log.json + PEMs.
# shellcheck disable=SC2016 # JS template literals, not shell expansions
node -e '
const fs = require("fs"), out = process.argv[1];
const pem = (b) => "-----BEGIN CERTIFICATE-----\n" + b.match(/.{1,64}/g).join("\n") + "\n-----END CERTIFICATE-----\n";
for (const line of fs.readFileSync(out + "/vitest.log", "utf8").split("\n")) {
  if (!line.startsWith("CT_ACCEPT ")) continue;
  const m = JSON.parse(line.slice(10));
  if (m.step === "log") {
    fs.writeFileSync(out + "/log.json", JSON.stringify({ log_id: m.log_id, key: m.key }));
    fs.writeFileSync(out + "/issuer.pem", pem(m.issuer));
  } else if (m.step === "1" || m.step === "2") {
    fs.writeFileSync(`${out}/step${m.step}-mtls.pem`, pem(m.mtls));
    fs.writeFileSync(`${out}/step${m.step}-signing.pem`, pem(m.signing));
  }
}' "${OUT}"

cleanup() {
  rm -f "${AZUL_DIR}/crates/sct_validator/tests/notme_acceptance_sct.rs" \
        "${AZUL_DIR}/crates/integration_tests/tests/notme_acceptance_inclusion.rs"
}
trap cleanup EXIT
cp -f "${ROOT}/ct/acceptance/notme_acceptance_sct.rs" "${AZUL_DIR}/crates/sct_validator/tests/"
cp -f "${ROOT}/ct/acceptance/notme_acceptance_inclusion.rs" "${AZUL_DIR}/crates/integration_tests/tests/"

echo "== azul sct_validator (out: ${OUT}/sct_validator.log)"
( cd "${AZUL_DIR}" && NOTME_ACCEPT_DIR="${OUT}" \
    cargo test -q -p sct_validator --test notme_acceptance_sct -- --nocapture --test-threads=1 ) \
  > "${OUT}/sct_validator.log" 2>&1 && S1=pass
grep -E '^test |validate_embedded_scts|test result' "${OUT}/sct_validator.log" | sed 's/^/   /'

echo "== azul integration_tests inclusion (out: ${OUT}/inclusion.log)"
( cd "${AZUL_DIR}" && NOTME_ACCEPT_DIR="${OUT}" BASE_URL="${ORIGIN}" LOG_NAME="${LOG_NAME}" \
    cargo test -q -p integration_tests --test notme_acceptance_inclusion -- --nocapture ) \
  > "${OUT}/inclusion.log" 2>&1 && S3=pass
grep -E '^test |checkpoint verified|leaf_index|control|panicked|test result' "${OUT}/inclusion.log" | sed 's/^/   /'

[ "${VT}" -eq 0 ] && S2=pass
echo "== result: vitest(steps 1-3, authority side)=${S2}  sct_validator(step 1)=${S1}  inclusion(step 3)=${S3}"
[ "${S1}${S2}${S3}" = "passpasspass" ]
