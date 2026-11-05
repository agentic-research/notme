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
refresh alarm drains it through `add-chain` (20 rows per fire, 4 concurrent).
Each row backs off on its own, 3 minutes doubling to an hourly cap, so once
the log is back every row is retried within the hour. After 24 failed
attempts a row is counted as `gaveUp` (still retried hourly);
30 days after its mint it is abandoned (`worker/src/signing-authority.ts:2450-2470`
and the health table below). Health is served at
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
the reviewed #322 head `97cbdf7` (identical to the upstream merge commit
`d9402ec`), not a deployed one.

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

Upstream change: cloudflare/azul#322, merged 2026-11-02 as `d9402ec`. Its
diff is identical to the reviewed fork head `97cbdf7`. The change: add the
flag to the per-log config, default `true` so no existing log changes
behaviour.

`false` deliberately means "do not require serverAuth," not "require
clientAuth." The configured roots remain the log's inclusion boundary and
every other chain and CT validation still runs. That is the right transparency
policy here: an unexpected leaf profile should become visible in the log, not
be hidden by an EKU allowlist. The issuing CA and relying party enforce the
certificate's authorized purpose. It also matches notme's pair: the mTLS leaf
is clientAuth-only and the signing leaf has no EKU extension.

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
| `temporal_interval` | 2026-07-01Z to 2027-07-01Z (end exclusive) | the log accepts only certificates whose `notAfter` falls in this window. azul's `build.rs` requires a production shard to span 3 to 12 months, so this is the maximum; the next shard must be live before 2027-07-01 (runbook step 6) |
| `require_server_auth_eku` | `false` | skips only the serverAuth presence check, so the clientAuth mTLS leaf and no-EKU signing leaf are both recorded; configured roots and every other validation still apply. Needs azul at or after `d9402ec` (#322) |
| `enable_ccadb_roots` | `false` | this log accepts notme's root and nothing from the WebPKI |
| `reject_expired` | `false` | the backlog submits after the leaf has expired; `true` would refuse every drained row (see above) |
| `sequence_interval_millis` | `750` | sequencer alarm period. See "Sequencing: cost against inclusion latency" below |
| `max_sequence_skips` | `1` | an empty interval does not write a checkpoint, every other one does. Same section |
| `submission_endpoint` / `monitoring_endpoint` | `https://REPLACE-ME.example/logs/notme/` | **placeholder.** JSON has no comments, so it is explained here: replace both with the URL the deployed log is actually served at (the notme-ct Worker's route, or the R2 public bucket for the monitoring endpoint) before deploying. The log publishes these URLs in its `metadata.json`. |

The file was brought up to the schema in the azul checkout at the #322 head
(`operator_name`, `friendly_name`, `intended_use`, `status`,
`status_timestamp`, `submission_endpoint`, `monitoring_endpoint`): the
`description` / `log_type` / `submission_url` fields the earlier version used
are not in that schema. `config.notme.json` validates against
`crates/ct_worker/config.schema.json`.

### Sequencing: cost against inclusion latency

Read from azul at `d9402ec` (notme-1b46a8, 2026-11-03 cost estimate risk 3,
`docs/audits/2026-11-03-cost-estimate.md`):

- The field names are `sequence_interval_millis` (integer, minimum 100,
  default 1000) and `max_sequence_skips` (integer, default 0):
  `crates/ct_worker/config.schema.json:95` and `:101`,
  `crates/ct_worker/config/src/lib.rs:80-82`, wired at
  `crates/ct_worker/src/sequencer_do.rs:33-34`. A bare `sequence_interval`
  is refused by the schema (additional property), and `build.rs` enforces
  the schema: `sequence_interval_millis: 50` fails the `DEPLOY_ENV=notme`
  build.
- The sequencer re-arms its alarm every interval, unconditionally
  (`crates/generic_log_worker/src/sequencer_do.rs:181`).
- On each tick `PoolState::take` (`crates/generic_log_worker/src/log_ops.rs:173-224`)
  either skips (no full tile to publish and fewer than `max_sequence_skips`
  consecutive skips: line 221) or sequences everything, **including nothing**
  (line 212: "even if there are no entries, we want to create a new
  checkpoint"), and every sequencing uploads a checkpoint to R2
  (`log_ops.rs:1182`). The skip counter is per pool, not per entry, so it
  cycles on idle ticks too: an idle log writes one checkpoint every
  `(max_sequence_skips + 1) × sequence_interval`. Skips **reduce** idle writes;
  nothing in this version eliminates them.
- An `add-[pre-]chain` request is answered only after its entry is
  sequenced and persisted (`crates/ct_worker/README.md`, "Life of an
  add-[pre-]chain request", steps 6-8; `log_ops.rs:1203` releases the
  waiters). So the same period is also the **worst-case wait** a submission
  spends in the pool, plus `batch_timeout_millis` (default 100 ms).
- Leave `sequence_skip_threshold_millis` unset. On an idle tick the "oldest
  leftover" timestamp it compares against belongs to an entry already in the
  tree (or is 0 after a restart), so it reads as expired and forces a
  checkpoint every tick, which undoes the skips (`log_ops.rs:180-188`; a
  reading of the code, not exercised).

**The constraint that sets the values is on notme's side**: the mint waits
for `add-pre-chain` at most `DEFAULT_TIMEOUT_MS` = **2000 ms**
(`worker/src/ct/log-client.ts`), and the drain's `add-chain` uses the same
bound. If the worst-case sequencing wait passes 2 s, mints time out, go out
with no embedded SCT and are backlogged, and the drain's retries time out
the same way. So the 5-10 s intervals the cost estimate floats would make
logging fail rather than make it cheaper. With P = `(skips + 1) × interval`:

| interval / skips | P (idle checkpoint period, worst wait) | idle R2 Class A / month | R2 Class A cost over the 1M free | alarm requests / month |
|---|---|---|---|---|
| 1000 / 0 (azul default) | 1.0 s | 2.59M | ~$7.16 | 2.59M |
| **750 / 1 (chosen; azul's own `config.dev.json`)** | **1.5 s** | **1.73M** | **~$3.28** | 3.46M (~$0.13 more) |
| 1000 / 1 | 2.0 s | 1.30M | ~$1.33 | 2.59M |
| 2000 / 1 | 4.0 s | 0.65M | $0 | 1.30M |

750 / 1 is the cheapest row whose worst case (1.5 s + 100 ms batching +
network) stays under the 2 s mint bound; the estimate prices the log side
at about $8.9 a month with it, against about $12.6 with the defaults. 1000 /
1 sits at the bound and would time out a share of mints. Getting under R2's
free tier (P of at least about 2.6 s) needs notme's CT timeout raised first,
which adds up to P to the latency of every logged mint: an owner decision,
not a config change. The DO stays resident either way (an alarm at most every
second keeps it from evicting): about 332k of the 400k included GB-s.

`notmedev` carries the same two values so the local acceptance
(`task ct:acceptance`) measures `add-pre-chain` latency under the production
timing. `notmestrict` keeps the defaults: it is only the EKU negative control.

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

    # 1. a throwaway worktree at the #322 merge commit (require_server_auth_eku)
    git -C <azul> worktree add --detach /tmp/azul-ct d9402ec
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

**Why not `config.notme.json` verbatim:** the local log needs only the two
test shards, and the production shard would need its own bindings and keys.
(The production shard does build: `DEPLOY_ENV=notme` with the production
root passes azul's `build.rs`. An earlier 18-month interval did not, and was
fixed in `notme-a3a2bc`.)

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

That file is **not** in git: the repo's `*.pem` ignore rule matches it, and
the public-trust exceptions are deliberately exact paths reviewed as
trust-root changes. Copy it from an existing checkout, or do the two passes
below once. With the file present there is ONE pass. Two passes are needed only if
the fixed key changes: run once (the test prints the authority's root as
`issuer` in its `CT_ACCEPT log` line, and step 1 fails because the log does
not trust it), write that root to `ct/testdata/roots.local-authority.pem`,
re-run `local-log.sh`, restart `wrangler dev` so it rebuilds, and run again.

## Operator runbook

Everything below touches real Cloudflare resources. None of it has been run;
it is written from azul's `AGENTS.md`, `scripts/create-log.sh` and
`wrangler.jsonc`.

### 1. Provision the log

1. Check out upstream azul at commit `d9402ec`, the merge of
   cloudflare/azul#322, or any later commit. Deploy a pinned commit, not a
   moving branch. Commits before `d9402ec` refuse every notme certificate:
   the pair has a clientAuth-only leaf and a no-EKU leaf.
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
Worker (`CT_LOG_PATH` only if the shard is not named `notme`), and set
`CT_LOG_ID` / `CT_LOG_KEY` under `[vars]` to the `log_id` and `key` of the
reviewed pin, `trust/notme-ct-log.json` — or, in place of those three,
`CT_LOG_SHARDS`: a JSON array of `{path, log_id, key, temporal_interval}`,
one per shard, UTC and non-overlapping (step 6; template in
`worker/wrangler.toml.example`). Then use the normal canary path
(`task worker:canary` / `worker:promote`). **Unbound means no logging, by
design:** that is also the rollback.

The pin is **required** with the binding. The authority embeds an SCT, and
marks a backlog row logged, only if the SCT carries `CT_LOG_ID` and its
signature verifies under `CT_LOG_KEY` over the RFC 6962 §3.2 entry it
submitted (`worker/src/ct/verify-sct.ts`). A wrong `CT_LOG_PATH`, the wrong
shard, or some other Worker behind the binding therefore shows up as
`lastError` "wrong log" or "bad signature" and a growing backlog, not as
certificates carrying SCTs that no verifier trusts. With either variable
missing or malformed, nothing is submitted: every mint goes out unlogged
(never refused), its final chains are backlogged, and health reports
`configError` (and `lastError` "config: ..."). The drain submits nothing
while the pin is invalid; once `CT_LOG_ID` / `CT_LOG_KEY` are fixed, the next
fires log those rows, each SCT verified under the pin, so a forgotten secret
costs the embedded SCTs of that window but not the log entries
(notme-c0c9a2).

The log never causes a refusal. The authority can, and only in one case.
The final certificate is signed after the `add-pre-chain` round-trip, and
other requests can interleave during that wait. So if a `rotate()` or
`revokeEpoch()` lands inside it, the mint is refused (the RPC throws "signing
key or epoch changed while the CT log was consulted") instead of being signed
with the retired key or the revoked epoch. The caller retries, and the retry
mints under the current key (notme-b52d7c).

**Deploy check: measure production `add-pre-chain` latency** against the
mint's 2000 ms timeout (`DEFAULT_TIMEOUT_MS`, `worker/src/ct/log-client.ts`).
Measured locally on 2026-11-03 (`wrangler dev`, azul `d9402ec`, fresh state
per series; `[wrangler:info]` request durations):

| sequencing | first `add-pre-chain` after a cold start | warm `add-pre-chain` | warm `add-chain` (drain) |
|---|---|---|---|
| 1000 ms / 0 skips (defaults, control) | 1368-1377 ms (1 series) | 1516 ms | 778-789 ms |
| **750 ms / 1 skip (chosen)** | **2308 ms, then 1900 ms** (2 series) | 891-1434 ms (6 runs) | 1239-1409 ms |

Warm, the chosen values pass every run of `task ct:acceptance` with 0.6-1.1 s
of margin. **Cold, the first submission ran 2308 ms in one of two series**:
that mint timed out, went out without an embedded SCT, was backlogged and
then drained (the acceptance's step 1 failed on that run and passed on the
re-run). In production the sequencer stays warm (its alarm fires every
750 ms), so a cold start is a deploy or restart of the log, not a quiet
period; the cost is the first pair or two after it losing their embedded SCT
while still being logged. Local `wrangler dev` timing is not production
timing, and n is small. If production runs close to 2000 ms, every mint will
time out and be backlogged with no embedded SCT. On
the canary, watch the log Worker's request durations and `ct.backlog` /
`lastError` on `/admin/alarm-health`: a backlog that grows while the log is
up means the timeout, not the log, is the problem.

### 4. Health and alerting

`GET /admin/alarm-health` (authority-manage session) returns a `ct` object:

| field | meaning |
|---|---|
| `backlog` | unlogged rows still being retried |
| `oldestUnloggedAgeS` | age of the oldest such row, `null` when none |
| `gaveUp` | unlogged rows that hit 24 attempts; still retried on the same backoff (at most an hour apart), and counted here until logged or, 30 days after their mint, abandoned |
| `abandoned` | `{count, lastAt}`: backlog rows given up on for good — gaveUp and minted over 30 days ago. Never retried again: those certificates are **permanently unlogged**. Monotonic |
| `lastError` / `lastErrorAt` | last submission failure, with the reason: `HTTP <status>`, `timeout`, `invalid SCT`, `network error`, `wrong log` (SCT id is not `CT_LOG_ID`), `bad signature` (does not verify under `CT_LOG_KEY`), `no shard covers notAfter <time>` (no configured shard's interval holds the cert's `notAfter`; nothing was submitted); or `config: ...` from a mint that found the pin invalid and backlogged its chains. A drain fire skipped for an invalid pin does not overwrite it |
| `unloggable` | `{count, lastAt, reason}`: mints that went out with no SCT and **no backlog row**: the root could not be read or parsed, or the backlog INSERT failed. (An invalid pin is not counted here: those mints are backlogged.) |
| `embedFailed` | `{count, lastAt}`: mints whose SCTs verified but could not be embedded; they were backlogged instead |
| `configError` | why `CT_LOG_ID` / `CT_LOG_KEY`, or `CT_LOG_SHARDS`, cannot be trusted (bad JSON, a bad key, overlapping intervals, both forms set, ...); `null` when they are valid (or `CT_LOG` is unbound) |
| `shardEndsAt` | `end_exclusive` of the configured shard that ends **last** (ISO 8601): after it no certificate has a shard and every mint is backlogged. `null` with the single pin (no interval), unbound, or a `configError` |
| `shardEndsInDays` | whole days until `shardEndsAt`, floored; `0` or negative once it has passed |
| `shardClosingSoon` | `true` when `shardEndsAt` is less than **60 days** away, or past (notme-a806d0) |

Alert on:

- **`shardClosingSoon` true.** No configured shard covers certificates
  expiring after `shardEndsAt`. Roll now (step 6): add, provision and pin
  the next shard, then deploy `CT_LOG_SHARDS` with both. 60 days because the
  roll is several reviewed steps with lead time (config, provisioning R2 /
  KV / two secrets, deploy, the key through review and a release, a canary
  deploy of notme), and an alert read at a monthly review must still leave a
  full cycle; it is under azul's 3-month minimum production shard span, so
  a newly added shard does not alert at once. The hard deadline is 24 h
  before `shardEndsAt` (the longest tier TTL); past it, certificates are
  backlogged with `lastError` "no shard covers notAfter". The single pin
  reports no interval, so this alert only works with `CT_LOG_SHARDS`.

- **`configError` not `null`.** The binding is up but nothing is being
  logged; every mint is backlogged and `backlog` grows. Fix `CT_LOG_ID` /
  `CT_LOG_KEY` (runbook step 3) and the backlog drains on the next fires.
- **`lastError` reading `wrong log` or `bad signature`.** The binding reaches
  something that is not the pinned log: check `CT_LOG_PATH`, the `service`
  name, and that the pin is the shard's current key.
- **`gaveUp > 0`.** Each row's retries back off 3, 6, 12, 24, 48 minutes,
  then hourly (notme-a3804c; it used to be 24 tries in ~96 minutes, then one
  a day). A row reaches 24 attempts after about 20 hours of failures, and
  then counts in `gaveUp` instead of `backlog`, so during a long outage
  `backlog` can read **0**: the healthiest-looking number during the worst
  outage. `gaveUp` rows keep the hourly retry (rows under 24 attempts first,
  least recently tried next, at most 20 rows per fire), so once the cause is
  fixed they drain within about an hour, plus 4 minutes per 20 rows queued.
  The retry is bounded: 30 days after its mint a gaveUp row is **abandoned**
  (`abandoned.count`, logged as `ct.backlog_abandoned`), so fix the cause
  within that window.
- **`abandoned.count` increasing.** Certificates the log will never record.
  Same severity as `unloggable`.
- **Catch-up rate.** The drain does at most 20 rows per 4-minute fire, about
  **300 rows an hour**. An outage that backlogged N certificates takes about
  N/300 hours to drain once the log is back (a bridge pair is 2 rows). Near
  a shard's end that matters only if the shard set does not cover the
  certificates' `notAfter`; with both shards configured (step 6) each row
  still goes to the shard its `notAfter` names, however late it drains.

Backlog retention: a row is deleted 7 days after it was logged, or 7 days
after it was abandoned (the week is for looking at what an outage
backlogged; the log itself is the record of what was logged). A row that is
neither logged nor abandoned is never deleted, and a row that was never
tried (minted while the pin was broken) is never abandoned.
- **`unloggable.count` increasing, or `> 0`.** Those certificates are not in the
  backlog and cannot be recovered by the drain.
- **`backlog` growing** (or `oldestUnloggedAgeS` climbing toward the 5-minute
  certificate life and beyond): the log is slow or down, and rows left past
  their certificate's life are expected to be refused as expired (see above).

### 4a. Precerts for certificates that were never delivered

A monitor matching the log against issuance will find a few precerts whose
certificate nobody received (notme-b35676). Three paths produce one:

1. **`mint_state_moved`** — a `rotate()` or `revokeEpoch()` lands during the
   add-pre-chain wait. The re-check after the wait refuses to sign the final
   certificate under the retired key or old epoch.
2. The mint is then **retried once** under the new state (review L2), which
   mints and submits a second precert under a **new serial**. The first
   serial's certificate never exists. Causes 1 and 2 are one event and one
   record: the refused attempt's serials. The retry's serials are delivered.
   (**`mint_failed`** is the same window ending in any other error.)
3. **`claim_taken_over`** — a tier collect whose mint outlasts the 60 s
   reclaim window loses its claim to a second collect. Its certificate,
   already logged or backlogged, is discarded, and the reclaimer's is
   delivered.

Each serial is kept durably in the DO's `ct_not_delivered` table and
published read-only:

```bash
curl -s https://auth.notme.bot/.well-known/ct-not-delivered.json
# {"notDelivered":[{"serial":"…","reason":"mint_state_moved","discardedAt":1793750400}]}
```

`serial` is lowercase hex without the DER sign byte, as `openssl x509
-serial` prints it (case aside). Rows from the last 400 days are served,
newest first, at most 1000, cached for 60 s. The route is unauthenticated,
like `/.well-known/epochs.json`: every serial is already public in the log,
and a row adds only a reason and a time, no subject or key.

**Retention: 400 days (`CT_NOT_DELIVERED_RETENTION_S`, notme-a3804c).** A row
is deleted 400 days after the certificate was discarded. That is longer than
any certificate this authority logs can live (bridge pairs default to 5
minutes, tiers are capped at 24 h) by more than a year, and longer than a
whole shard interval (a year in `ct/config.notme.json`) plus a month. Past
it the certificate has been expired for over a year and its shard has
closed, so a monitor reconciling that shard has long since had the answer.
Pruning was chosen over paginating the route: a cursor on an unauthenticated,
edge-cached `/.well-known` route reopens the query-in-the-cache-key miss that
notme-ed6114 closed (every distinct cursor is a SigningAuthority call), and
the list stays short anyway. Rows arise only from an operator action inside
a log wait or a mint slower than 60 s. If the retained list ever exceeds
1000 rows, the response is the newest 1000 and the authority logs
`ct.not_delivered_truncated`, so the cap is never silent.
A write failure loses the row but not the mint, and is logged as
`ct.not_delivered_write_failed` with the serials.

### 5. After `rotate()`: give the log the new root

The log accepts only chains that end in a root compiled into it
(`roots.notme.pem`, from `trust/notme-root.pem`). After `rotate()` the
authority issues under a new root the log has never seen, so every
submission is refused, every mint is backlogged, and after about 96 minutes
those rows are `gaveUp`. Nothing is lost if the log is updated:

1. Update `trust/notme-root.pem` to the new root through review
   (`trust/README.md`, "Updating this anchor").
2. **Append** the new root to `<azul>/crates/ct_worker/roots.notme.pem`; keep
   the old root in the file. Backlogged rows minted before the rotation still
   chain to the old root, and replacing it would leave them refused for good.
3. Redeploy the log (`npx wrangler -e=notme deploy`). Its key does not
   change, so the pin and `CT_LOG_ID` / `CT_LOG_KEY` stay as they are.
4. Watch `/admin/alarm-health`: `backlog` drains on the next fires; rows
   already `gaveUp` are retried within 24 h, and `gaveUp` returns to 0.

### 6. Roll the shard before it closes: configure both shards across the boundary

A production shard spans 3 to 12 months (azul `build.rs`, from Chrome's log
policy), so the log has to be rolled. `notme` accepts certificates whose
`notAfter` is before **2027-07-01T00:00:00Z**; the next shard accepts only
`notAfter` from that instant on.

The authority chooses the shard **per certificate, by its `notAfter`**
(notme-afa9d8, `worker/src/ct/shards.ts`). With `CT_LOG_SHARDS` naming both
shards, a certificate expiring before the boundary goes to `notme` and one
expiring on or after it goes to `notme2027h2`, whenever it is minted; each
SCT is verified under the key of the shard it came from. The drain chooses
again by the same rule, from the certificate's own `notAfter` and the
CURRENT shard set, so a backlog row goes to the right shard even if it was
backlogged before the next shard was configured. There is no switch instant
and nothing to time: the roll is an overlap in configuration, not a cutover.

A certificate whose `notAfter` no configured shard covers is **never
submitted** (to no shard: the wrong shard would refuse it, or worse, sign an
SCT for a log nobody checks it against). It is minted unlogged and
backlogged, `lastError` reads `no shard covers notAfter <time>; chains
backlogged`, and each drain fire counts a failed attempt with the same
reason until a shard that covers it is configured.

The single pin (`CT_LOG_ID` / `CT_LOG_KEY` / `CT_LOG_PATH`) still works and
means one shard with no interval: every certificate goes to it, so it
cannot roll without the losses below. Move to `CT_LOG_SHARDS` before the
first roll. (With the single pin, switching early loses certificates whose
`notAfter` precedes the new shard's start; switching at the close costs the
last hour's tiers their embedded SCT.)

1. Add the next shard to `config.notme.json`, e.g. `notme2027h2` with
   `temporal_interval` 2027-07-01Z to 2028-01-01Z and the same policy fields
   (`require_server_auth_eku: false`, `enable_ccadb_roots: false`,
   `reject_expired: false`, and the sequencing fields).
2. Provision it (step 1: `LOG_NAME=notme2027h2` gives its own R2 bucket, KV
   namespace and keys) and deploy it, well before the close.
3. Record its key. The new shard is a different log with a different key.
   The pin file (`trust/notme-ct-log.json`) is still a **single** object
   naming one log, and `task ct:verify -- --write` refuses to overwrite a
   different pin; until it holds one entry per shard, record the new shard's
   `metadata_url`, `log_id`, `key` and digest by a reviewed manual edit and
   cut a release so the signed pin follows. The old pin stays in git history
   and in the earlier release's signed asset.
4. Deploy notme, through the canary, with `CT_LOG_SHARDS` holding **both**
   shards (template in `worker/wrangler.toml.example`) and the single-pin
   variables removed (setting both is a `configError`). Do this any time
   before the earliest `notAfter` that can reach the boundary: at the latest
   24 hours before it, the longest tier TTL; in practice, as soon as the new
   shard is deployed. `ct.shardClosingSoon` stays `true` until you do.
5. Watch `/admin/alarm-health`: `configError` stays `null` and `lastError`
   never reads `no shard covers notAfter`.
6. Keep the old shard serving reads; it stays the record for what it logged.
   Drop it from `CT_LOG_SHARDS` only once no backlog row can still need it
   (its interval has ended and `backlog` / `gaveUp` are 0).

## What is NOT done

- Verifiers still do not require SCTs (signet `--insecure-ignore-sct`). Until
  they do, the log records issuance and enforces nothing.
- Offline task certificates (`mintTaskCertPair`) are not logged; their tier is.
- The log is not provisioned and nothing is pinned or bound.
- The trust pin `trust/notme-ct-log.json` (and `task ct:verify`) holds ONE
  log; a second shard is recorded by a manual reviewed edit (step 6.3), not
  as a second entry. notme-afa9d8 asks for one entry per shard.
