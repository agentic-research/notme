# notme-ct — issuance transparency log

A Static CT API log for notme's own issuance, composed from
[cloudflare/azul](https://github.com/cloudflare/azul)'s `ct_worker`. Answers
`notme-907299`: notme publishes its keys but records nothing about what it
issued, so a stolen CA key mints silently.

This directory holds the pieces that define **notme's log** — its roots, its
temporal interval, its policy. azul is the engine and is not vendored here.

## Status — what is actually proven

Verified 2026-09-25 against a locally running `ct_worker`
(`DEPLOY_ENV=notme npx wrangler -e notme dev`) and a **real** certificate
minted by notme's own `mintBridgeCertPair`:

- `add-chain` accepts the chain and returns an SCT carrying the `leaf_index`
  extension (`ext_type 0`, uint40 index).
- `get-roots` serves exactly one root: `CN=signet-authority, O=notme`.
- `log.v3.json` publishes the log's P-256 key and a `log_id` matching the
  `id` in the SCT.

- `add-pre-chain` accepts a **real precertificate** minted by
  `mintBridgeCertPair` with the poison extension, and returns an SCT. The same
  poisoned certificate submitted to `add-chain` is **refused** — so the two
  endpoints discriminate on the poison rather than accepting anything.
- A precertificate and its final certificate can be minted as a PINNED pair
  that differs only in the CT extension (see below).
- **The embedded SCT's signature VERIFIES**, checked by an independent
  implementation rather than by my own encoder. A full cycle — pinned
  precertificate → `add-pre-chain` → embed the returned SCT under the same
  pin — produces a certificate that azul's
  `sct_validator::validate_embedded_scts` accepts, doing its own RFC 6962
  §3.2 reconstruction (strip the poison, rebuild the signed
  `CertificateTimestamp`, hash the issuer key).

  The assertion is on the SCT **count**, not on `Valid`: Chrome's policy wants
  two distinct log operators and notme runs one log, so `Valid` is
  structurally unreachable and asserting it would be asserting that notme is
  in the WebPKI. azul drops an SCT whose signature fails before the policy
  check sees it (`lib.rs:482`), so a count of one *is* the statement that a
  signature verified. Two controls hold that reading up: substituting a real
  but unrelated P-256 key drops the count to zero, and the precertificate —
  poison, no SCT list — is refused outright.

**Wired in the Worker (tested against a stub log, not a deployed one):**
with a `CT_LOG` service binding, the online authority logs every bridge pair
and every tier certificate; certs carry embedded SCTs when the log answers
within 2000 ms. Otherwise the pair goes to the `ct_backlog` table and the
refresh alarm drains it through `add-chain` (20 rows per fire, 4 concurrent,
giving up on a row after 24 attempts). Health is served at
`/admin/alarm-health` as a `ct` object. With no binding, behaviour is exactly
as before. The tests run under `worker/vitest.workers.ct.config.mts` with a
stub log that signs real SCTs.

**End to end against a real local azul log** (2026-10-29, `task
ct:acceptance`; see "End-to-end acceptance" below): a pair minted through
the real `/cert/gha` route carries embedded SCTs that azul's `sct_validator`
verifies; with the log unreachable the mint still succeeds and both chains
are backlogged; when the log returns, one alarm fire drains them, and azul's
own `integration_tests` code finds both certificates as X509 entries in the
log's signed tree with Merkle inclusion proven. This is a LOCAL log built from
the fork branch, not a deployed one.

**Not yet done**, and not claimed anywhere in this repo:

- **The log is not provisioned.** No notme-ct Worker, R2 bucket, KV namespace
  or keys exist; `trust/notme-ct-log.json` is the `not-provisioned`
  placeholder; nothing in production is bound to `CT_LOG`. See the operator
  runbook below.
- **Verifiers do not require SCTs.** signet still passes `--no-default-ctfe
  --insecure-ignore-sct`. Removing the latter is what turns the log from a
  record into an enforced requirement, and it is the only step that actually
  defends anything: a thief with the CA key mints with no SCT at all, and
  nothing refuses that certificate until a verifier does.
- **Offline task certificates are not logged.** `mintTaskCertPair` runs on the
  operator's machine and has no submission client. The tier certificate that
  authorises it is logged; the per-task certificates it signs are not.
- `cosign verify --ctfe=...` accepting a notme artifact while a cert with no
  valid SCT is rejected has not been run.

## Why embedding needs a PAIRED mint

RFC 6962 §3.2 has the log sign the precertificate's `TBSCertificate` with the
poison **removed**, and a verifier reconstruct those bytes from the final
certificate by removing the SCT list. The two reconstructions must be
byte-identical.

`mintBridgeCertPair` generated a fresh random serial and read the clock on
every call, so minting a precertificate and then a final certificate as two
ordinary calls produces two different `TBSCertificate`s. The SCT would be
signed over bytes the final certificate never contains — and it would verify
nowhere while every other check passed and the certificate looked logged.

The build order in `notme-1b46a8` does not mention this. `opts.pin` now
carries the serials and the validity window across, and
`worker/src/ct-precert.do.test.ts` asserts that a pinned pair's extension sets
are byte-identical once the CT extension is dropped from each. Both halves of
the pin are mutation-checked: ignoring it for serials, or for validity, fails
that test.

## Two preconditions, both now met

1. **Ed25519 chain signatures.** azul's `x509_util::is_link_valid` accepted
   only ECDSA and RSA; Ed25519 (RFC 8410) fell to `_ => false`, so every
   notme certificate was refused. Fixed upstream in
   [azul#281](https://github.com/cloudflare/azul/pull/281), merged
   2026-08-31.
2. **Root path length.** The served root is `CA:TRUE, pathlen:1`, so
   tier-signed certificates can chain. (It was `pathlen:0` for five months —
   `notme-1b1db4`.)

## A third precondition the spike missed

`notme-1b46a8` recorded `require_server_auth_eku` as configuration. It is
not: `ct_worker` hardcoded `true` at its only call site and the field was
absent from `config.schema.json`.

notme's leaves carry `id-kp-clientAuth` and nothing else — the mTLS leaf has
exactly that EKU, and the signing leaf has no EKU extension at all — so
**every notme certificate was rejected**, for a reason unrelated to the one
the spike had already fixed. RFC 6962 §3.1's requirement is right for WebPKI
logs and wrong for a workload-identity CA.

Upstream change: draft PR cloudflare/azul#322 (fork branch `jamestexas/azul:ct-configurable-server-auth-eku`): add the flag to the per-log config, default `true`
so no existing log changes behaviour.

## Reproducing the proof

`scripts/prove-chain-accepted.sh` submits **one** chain to two shards that
differ in exactly one field, and requires the lenient one to issue an SCT and
the strict twin to refuse. If both accepted, the flag would not be
load-bearing and the result would prove nothing about it; if both refused,
the Ed25519 arm would be the suspect.

    LOG=http://localhost:8787 CHAIN=chain.json ./scripts/prove-chain-accepted.sh

`CHAIN` is `{"chain": ["<base64 DER leaf>", ...]}`.

## Files

| file | what it is |
|---|---|
| `config.notme.json` | the log shards, copied into azul's `crates/ct_worker/` as `config.<DEPLOY_ENV>.json`. `notmedev` / `notmestrict` are local test shards; `notme` is the production log |
| `scripts/prove-chain-accepted.sh` | the lenient-vs-strict A/B against a running local log |
| `scripts/local-log.sh` | prepares an azul worktree to serve the local shards with the test root |
| `scripts/acceptance.sh` | the end-to-end acceptance driver (`task ct:acceptance`) |
| `acceptance/*.rs` | the azul-side checks (sct_validator, inclusion), copied into the azul worktree only for a run |
| `testdata/` | the FIXED test authority key and its root, for the local log only |
| `../trust/notme-ct-log.json` | the log's public-key pin; `../scripts/verify-ct-log.ts` (`task ct:verify`) checks the deployed log against it |

## Where the roots file comes from

`roots.<DEPLOY_ENV>.pem` is **not** committed here. A real shard's roots file
is `trust/notme-root.pem` — the one out-of-band copy of the root, pinned and
reviewed as a trust-root change:

    cp ../trust/notme-root.pem <azul>/crates/ct_worker/roots.notme.pem

A second copy in this directory is exactly the drift that had to be fixed to
get here: the committed anchor had gone stale against production and nothing
compared it to anything outside itself (see `trust/README.md`). One copy.

The **local** proof does not use that root, and saying so matters. Its chain is
minted by a throwaway `SigningAuthority` instance in the workers test pool, so
its roots file is that instance's own CA — generated per run, never committed.
The certificates are real notme output from the real mint path, with the same
extensions, algorithms and EKUs; only the issuing instance differs. That is
what makes the proof valid and what keeps it from needing a production key.

`reject_expired` is `false` on all three shards, including production. On the
local shards a fixture minted minutes earlier would otherwise be refused. On
production it is required by the backlog: at submission azul raises the lower
bound on the leaf's `notAfter` to max(`temporal_interval.start_inclusive`, now)
for both `add-chain` and `add-pre-chain` when `reject_expired` is true. A
backlogged bridge cert lives 5 minutes and the alarm drains every 4, so it is
expired by the time it is retried; with `true` the backlog could never log the
certificates it exists for. With `false`, the temporal interval still bounds
what is accepted: `end_exclusive` applies unconditionally, and the lower bound
falls back to `start_inclusive`. (Behaviour read from azul's
`frontend_worker.rs`; not exercised against a deployed log.)

## The production shard `notme`

In `config.notme.json`:

| field | value | why |
|---|---|---|
| `intended_use` | `production` | this is the real log, not a test shard |
| `temporal_interval` | 2026-01-01Z to 2027-07-01Z (end exclusive) | the log accepts only certificates whose `notAfter` falls in this window; a new shard is needed after it |
| `require_server_auth_eku` | `false` | notme leaves are clientAuth or have no EKU. Needs the azul fork (below) |
| `enable_ccadb_roots` | `false` | this log accepts notme's root and nothing from the WebPKI |
| `reject_expired` | `false` | the backlog submits after the leaf has expired; `true` would refuse every drained row (see above) |
| `submission_endpoint` / `monitoring_endpoint` | `https://REPLACE-ME.example/logs/notme/` | **placeholder.** JSON has no comments, so it is explained here: replace both with the URL the deployed log is actually served at (the notme-ct Worker's route, or the R2 public bucket for the monitoring endpoint) before deploying. The log publishes these URLs in its `metadata.json`. |

The file was brought up to the schema in the azul checkout on the fork branch
(`operator_name`, `friendly_name`, `intended_use`, `status`,
`status_timestamp`, `submission_endpoint`, `monitoring_endpoint`): the
`description` / `log_type` / `submission_url` fields the earlier version used
are not in that schema. `config.notme.json` validates against
`crates/ct_worker/config.schema.json`.

**Roots for the production log are the production root,
`trust/notme-root.pem`**, copied verbatim to `roots.notme.pem` (the roots file
is selected by `DEPLOY_ENV=notme`). Do not commit a second copy here.

## End-to-end acceptance

`worker/src/ct-acceptance.do.test.ts`, driven by `ct/scripts/acceptance.sh`
(`task ct:acceptance`). It runs against a **real** azul `ct_worker` on your
machine; nothing in it is a stub. It is not part of `task worker:check`: it
needs a running log, and without `CT_LOG_URL` it SKIPS and says so.

What it checks, all through `/cert/gha` with a genuinely signed GitHub OIDC
token (stubbed JWKS, as the other `/cert/gha` suites do):

| step | the authority's side (vitest) | the log's side (azul's own code) |
|---|---|---|
| 1. log up | both certs embed exactly one SCT, with this log's `log_id`; no backlog | `sct_validator::validate_embedded_scts` verifies each cert's SCT (count 1); a different real key verifies 0; the step-2 cert (no SCT list) is refused |
| 2. log down | the mint still returns 200, with no SCT and no poison; both final chains are in `ct_backlog`; health `backlog` = 2 | — |
| 3. log back | `runDurableObjectAlarm` drains both rows on one fire; health `backlog` 0, `gaveUp` 0, breaker untouched | the checkpoint's signature verifies; both step-2 certs are X509 entries in the data tiles; `assert_leaf_in_checkpoint` proves inclusion; a step-1 cert (precert-logged only) is NOT found as an X509 entry |

"Log down" is a real refused TCP connection: the `CT_LOG` binding is a proxy
(`worker/vitest.workers.ct-live.config.mts`) that the test points at port 1.
Static CT has no `get-entries`; the read path is the tiles and the
checkpoint, which a local `wrangler dev` keeps in its persisted R2 state, and
azul's `CtClient::get_raw` reads with `wrangler r2 object get --local`.

### Running it

    # 1. a throwaway worktree of the azul fork branch (require_server_auth_eku)
    git -C <azul> worktree add --detach /tmp/azul-ct ct-configurable-server-auth-eku
    ct/scripts/local-log.sh /tmp/azul-ct
    # 2. serve the log (first start compiles the Worker: minutes)
    (cd /tmp/azul-ct/crates/ct_worker && \
      npx wrangler -c wrangler.notmelocal.jsonc dev --persist-to .wrangler/state)
    # 3. in another shell, from notme
    CT_LOG_URL=http://localhost:8787/logs/notmedev AZUL_DIR=/tmp/azul-ct task ct:acceptance
    # afterwards
    git -C <azul> worktree remove --force /tmp/azul-ct

| env | meaning |
|---|---|
| `CT_LOG_URL` | the shard base, `http://localhost:8787/logs/notmedev`. Unset → SKIPPED |
| `AZUL_DIR` | the azul worktree serving that log; the two Rust files in `ct/acceptance/` are copied into it for the run and removed on exit |
| `CT_ACCEPT_OUT` | optional: where the PEMs and the three logs go (default: a `mktemp -d`) |

`local-log.sh` writes, in that worktree only: `config.notmelocal.json`
(`config.notme.json` without the production shard), `roots.notmelocal.pem`
(the test root), a standalone `wrangler.notmelocal.jsonc`, and signing /
witness keys appended to `.dev.vars` (a file azul tracks). Commit none of it.

**Why not `config.notme.json` verbatim:** its production shard `notme` has an
18-month temporal interval, and azul's `build.rs` refuses a production shard
outside 3 to 12 months (`notme invalid temporal interval`), so the full file
does not build. That is a defect in the production shard to fix before
provisioning (see "What is NOT done").

### The roots file, and the two-pass bootstrap

The log compiles its roots in at build time (`build.rs`), so it can only
trust an authority whose root existed when it was built. The workers test
pool gives every run fresh storage, so a test authority would mint a new CA
every run and the log could never be bootstrapped to trust it. Hence the
**fixed test authority key** (`ct/testdata/local-authority-key.json`,
inlined in the test, NOT notme's CA): the test plants it before the authority
creates a key, and `ct/testdata/roots.local-authority.pem` is that key's
root. azul matches a chain to a root by issuer name and signature, so the
per-run root certificate (new serial, same key) still chains.

With that file committed there is ONE pass. Two passes are needed only if
the fixed key changes: run once (the test prints the authority's root as
`issuer` in its `CT_ACCEPT log` line, and step 1 fails because the log does
not trust it), write that root to `ct/testdata/roots.local-authority.pem`,
re-run `local-log.sh`, restart `wrangler dev` so it rebuilds, and run again.

## Operator runbook

Everything below touches real Cloudflare resources. None of it has been run;
it is written from azul's `AGENTS.md`, `scripts/create-log.sh` and
`wrangler.jsonc`.

### 1. Provision the log

1. Check out azul on the fork branch that carries `require_server_auth_eku`:
   `jamestexas/azul`, branch `ct-configurable-server-auth-eku` (commit
   `00a9a84` adds the flag; the branch head also adds an integration test).
   This is the draft upstream PR cloudflare/azul#322. **Until it merges,
   deploy from that branch.** On upstream `main` every notme certificate is
   refused (clientAuth-only leaves). Once #322 merges, switch to azul `main`.
2. `cp config.notme.json <azul>/crates/ct_worker/config.notme.json` after
   replacing the two `REPLACE-ME` URLs (`task ct:verify` exits 1 if the pin is
   provisioned while any remain), and
   `cp trust/notme-root.pem <azul>/crates/ct_worker/roots.notme.pem`.
3. In `<azul>/crates/ct_worker/wrangler.jsonc` add an `env.notme` block modelled
   on `env.dev` (account, route, `build.command` with `DEPLOY_ENV=notme`, the
   `SEQUENCER` / `BATCHER` / `CLEANER` Durable Object bindings and migrations).
4. From `<azul>/crates/ct_worker`:
   `ENV=notme LOG_NAME=notme CLOUDFLARE_ACCOUNT_ID=<id> ./scripts/create-log.sh`.
   It prompts, then creates the R2 bucket `static-ct-public-notme`, the KV
   namespace `static-ct-cache-notme`, and the secrets `WITNESS_KEY_notme`
   (Ed25519) and `SIGNING_KEY_notme` (P-256), each only if absent. Those are the
   exact names: `SIGNING_KEY_<LOG_NAME>` and `WITNESS_KEY_<LOG_NAME>`. If you
   set the signing key by hand instead:
   `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 | npx wrangler -e=notme secret put SIGNING_KEY_notme`.
   Treat the signing key as write-once: replacing it is a different log.
5. `npx wrangler -e=notme deploy`.

### 2. Record the key

The log publishes `GET /logs/notme/metadata.json` with `log_id` and `key`
(base64 SPKI DER). Record them in the repo, from a checkout of notme:

    task ct:verify -- --write --metadata https://<log-host>/logs/notme/metadata.json

`--write` refuses (exit 2) if a different pin is already recorded, and checks
that `log_id` is the SHA-256 of `key`. Then commit `trust/notme-ct-log.json`
through normal review and cut a release: the `trust-anchor` job signs it
(keyless, with its bundle, next to `notme-root.pem`) once its status is
`provisioned`. From then on `task ct:verify` compares the live log to the pin
and exits 1 on any difference. See `trust/README.md`.

### 3. Bind `CT_LOG` on notme

Uncomment the `[[services]] binding = "CT_LOG"` block in `worker/wrangler.toml`
(template: `worker/wrangler.toml.example`), pointing at the deployed log
Worker (`CT_LOG_PATH` only if the shard is not named `notme`), then use the
normal canary path (`task worker:canary` / `worker:promote`). **Unbound means no
logging, by design:** that is also the rollback.

### 4. Health and alerting

`GET /admin/alarm-health` (authority-manage session) returns a `ct` object:

| field | meaning |
|---|---|
| `backlog` | unlogged rows still being retried |
| `oldestUnloggedAgeS` | age of the oldest such row, `null` when none |
| `gaveUp` | unlogged rows that hit 24 attempts and are no longer retried |
| `lastError` / `lastErrorAt` | last submission failure |
| `unloggable` | `{count, lastAt}`: mints that went out with no SCT and **no backlog row** because the root could not be read |

Alert on:

- **`gaveUp > 0`.** The alarm fires every 4 minutes and a row gets one attempt
  per fire, so 24 attempts is about **96 minutes**. A log outage longer than
  that moves every queued row to `gaveUp`, and `backlog` then reads **0**:
  the healthiest-looking number during the worst outage. `gaveUp` never
  decreases by itself; those certificates are unlogged for good.
- **`unloggable.count` increasing, or `> 0`.** Those certificates are not in the
  backlog and cannot be recovered by the drain.
- **`backlog` growing** (or `oldestUnloggedAgeS` climbing toward the 5-minute
  certificate life and beyond): the log is slow or down, and rows left past
  their certificate's life are expected to be refused as expired (see above).

## What is NOT done

- Verifiers still do not require SCTs (signet `--insecure-ignore-sct`). Until
  they do, the log records issuance and enforces nothing.
- Offline task certificates (`mintTaskCertPair`) are not logged; their tier is.
- The log is not provisioned and nothing is pinned or bound.
- The production shard in `config.notme.json` does not build: azul's `build.rs`
  requires a production shard's temporal interval to be 3 to 12 months, and
  `notme`'s is 18 (2026-01-01 to 2027-07-01). Shorten it before provisioning.
