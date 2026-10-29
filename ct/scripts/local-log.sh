#!/usr/bin/env bash
# Prepare an azul checkout to serve notme's LOCAL test log (notme-1b46a8).
#
# Usage: ct/scripts/local-log.sh <azul-checkout>
#
# <azul-checkout> must be on the fork branch that carries
# require_server_auth_eku (jamestexas/azul ct-configurable-server-auth-eku,
# draft PR cloudflare/azul#322). Use a throwaway `git worktree`: this writes
# files into crates/ct_worker, none of which may be committed:
#
#   config.notmelocal.json   ct/config.notme.json minus the production shard
#   roots.notmelocal.pem     ct/testdata/roots.local-authority.pem (TEST root)
#   wrangler.notmelocal.jsonc  a standalone wrangler config for the two shards
#   .dev.vars                APPENDS fresh SIGNING_KEY_/WITNESS_KEY_ for each
#                            shard, only if absent (the log key is
#                            write-once). azul TRACKS this file (its dev
#                            keys), so the worktree shows it modified.
#
# Then, from <azul-checkout>/crates/ct_worker:
#   npx wrangler -c wrangler.notmelocal.jsonc dev --persist-to .wrangler/state
#
# WHY NOT config.notme.json VERBATIM: its production shard `notme` has an
# 18-month temporal interval and azul's build.rs refuses a production shard
# outside 3..=12 months, so the full file does not build. The local shards
# `notmedev` / `notmestrict` are what the acceptance test needs anyway.
#
# The roots file is compiled in at build time (build.rs), and it is the
# FIXED test authority key's root, so it stays valid across runs; see
# ct/README.md for the two-pass bootstrap if that key ever changes.
set -euo pipefail
AZUL="${1:?usage: local-log.sh <azul-checkout>}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
CTW="${AZUL}/crates/ct_worker"
[ -f "${CTW}/config.schema.json" ] || { echo "not an azul checkout: ${AZUL}" >&2; exit 2; }
grep -q require_server_auth_eku "${CTW}/config.schema.json" || {
  echo "this azul checkout has no require_server_auth_eku; use the fork branch" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

jq 'del(.logs.notme)' "${HERE}/config.notme.json" > "${CTW}/config.notmelocal.json"
cp -f "${HERE}/testdata/roots.local-authority.pem" "${CTW}/roots.notmelocal.pem"

SHARDS=$(jq -r '.logs | keys[]' "${CTW}/config.notmelocal.json")
kv=""; r2=""
for s in ${SHARDS}; do
  kv="${kv}{\"binding\":\"cache_${s}\",\"id\":\"local-${s}\"},"
  r2="${r2}{\"binding\":\"public_${s}\",\"bucket_name\":\"static-ct-public-${s}\"},"
done
cat > "${CTW}/wrangler.notmelocal.jsonc" <<JSON
{
  "name": "static-ct-notmelocal",
  "main": "build/worker/shim.mjs",
  "compatibility_date": "2025-09-25",
  "build": {
    "command": "cargo install -q worker-build@0.8.5 && DEPLOY_ENV=notmelocal RUSTFLAGS='-Cllvm-args=-wasm-use-legacy-eh' worker-build --release --panic-unwind"
  },
  "version_metadata": { "binding": "VERSION_METADATA" },
  "kv_namespaces": [{"binding":"ccadb_roots","id":"local-ccadb"},${kv%,}],
  "r2_buckets": [${r2%,}],
  "durable_objects": { "bindings": [
    {"name":"SEQUENCER","class_name":"Sequencer"},
    {"name":"BATCHER","class_name":"Batcher"},
    {"name":"CLEANER","class_name":"Cleaner"}
  ]},
  "migrations": [
    {"tag":"v1","new_sqlite_classes":["Sequencer","Batcher"]},
    {"tag":"v2","new_sqlite_classes":["Cleaner"]}
  ]
}
JSON

touch "${CTW}/.dev.vars"
pemvar() { sed 's/$/\\n/g' | tr -d '\n'; }
for s in ${SHARDS}; do
  if ! grep -q "^SIGNING_KEY_${s}=" "${CTW}/.dev.vars"; then
    printf 'SIGNING_KEY_%s="%s"\n' "$s" "$(openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 | pemvar)" >> "${CTW}/.dev.vars"
  fi
  if ! grep -q "^WITNESS_KEY_${s}=" "${CTW}/.dev.vars"; then
    printf 'WITNESS_KEY_%s="%s"\n' "$s" "$(openssl genpkey -algorithm ed25519 | pemvar)" >> "${CTW}/.dev.vars"
  fi
done
echo "ready: cd ${CTW} && npx wrangler -c wrangler.notmelocal.jsonc dev --persist-to .wrangler/state"
