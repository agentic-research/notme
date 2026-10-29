# Issuance Logging (Static CT) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every certificate the online authority mints is recorded in notme's Static CT log. Certificates carry an embedded SCT when the log answers in time; when it doesn't, they are minted anyway and queued for logging.

**Architecture:**
- Both online mint choke points take an optional log binding (`CT_LOG`, a service binding to the notme-ct Worker): `SigningAuthority.mintBridgeCertPair` and `SigningAuthority.mintIssuingCa`.
- With the binding present, a mint runs the proven precertificate flow:
  1. pinned precert with the poison extension;
  2. `add-pre-chain`;
  3. final cert under the same pin, with the SCT list.
- If the log fails or times out, the final cert is minted without an SCT, and its chain goes into a Durable Object backlog. The existing refresh alarm drains the backlog via `add-chain`.
- With no binding, behaviour is exactly today's, so this code can deploy before the log exists.

**Tech Stack:** TypeScript, Cloudflare Workers + Durable Objects (SQLite), vitest-pool-workers (miniflare service-binding stubs), `@peculiar/x509`. The log engine is cloudflare/azul's `ct_worker`, outside this repo.

**Spec / prior work:**
- `ct/README.md` records what is proven: add-chain and add-pre-chain accept real notme chains, the embedded SCT verifies under azul's independent validator, and why the mint must be PINNED.
- Beads notme-1b46a8 (build) and notme-907299 (the gap).
- Owner decision 2026-10-29: provision the log; on log failure, fail OPEN at mint and let verifiers decide.

## Global Constraints

- **No binding, no change.** With `CT_LOG` absent, every mint is byte-for-byte today's behaviour: no poison, no SCT, no backlog row. Production deploys safely before the log exists.
- **Pinned pairs only.** A precert and its final cert share serials and validity via `opts.pin`. The final cert's extensions equal the precert's with the poison replaced by the SCT list, as `ct-precert.do.test.ts` already pins.
- **Fail open, bounded.** Log submission times out at **2000 ms** per call. On timeout, a non-200 or an unparseable SCT, mint WITHOUT an SCT and insert a backlog row. Never refuse a mint because the log is down.
- **Bridge pair:** BOTH certificates (mTLS and signing) are logged. Each needs its own precert and SCT; submit both concurrently. If either fails, both final certs omit SCTs and both chains go to the backlog. Never mint a pair where one cert is logged and the other is not.
- **Backlog:** table `ct_backlog(id INTEGER PRIMARY KEY, chain_json TEXT NOT NULL, created_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, logged_at INTEGER)`. It is drained by the existing alarm via `add-chain` of the FINAL cert (no SCT can be embedded after the fact, but the log still records it). At most **20 rows per alarm fire**. A row stops being retried after **24 attempts**; it stays visible in health with `attempts ≥ 24`.
- **Observability:** `/admin/alarm-health` (or a sibling `/admin/ct-health`, `authorityManage`-gated) reports backlog depth, oldest unlogged age, and last submission error.
- **Offline task certs (`mintTaskCertPair`) are OUT of scope.** They are minted offline by design (spec: mint path §5.4 / phase 6). Their tier IS logged.
- The DO's public method count is pinned at **62** (`rpc-surface.do.test.ts`). Add no public methods; helpers are ECMAScript `#private`.
- Mutation discipline: each task names the mutations its tests must kill.
- Workers-pool runs on this machine need `--testTimeout 30000`; run one vitest process at a time.
- Commit format: `[notme-1b46a8] type(scope): description` plus the session attribution lines.

## Review Focus

1. **Half-logged pair:** the mTLS precert is logged and the signing precert times out. Expected: neither final cert has an SCT, both chains are backlogged, the caller gets a working pair. Test in Task 2.
2. **SCT for the wrong bytes:** an SCT from a precert whose pin differs from the final cert. Expected: impossible by construction, because both use one pin object. Test: the final cert's SCT verifies against the final cert's reconstructed TBS, using `sct.ts`'s own reconstruction or the existing fixture approach (Task 2).
3. **Slow log stalls minting:** a log that accepts the connection but never answers. Expected: the mint completes within the timeout plus mint time, and the cert is backlogged. Test in Task 1 (client) and Task 2 (end to end).
4. **Backlog storm:** a log down for a day produces many rows. Expected: each alarm drains at most 20 rows, gives up per row at 24 attempts, and never re-arms faster than the existing alarm cadence. Test in Task 4.
5. **Binding absent:** no extra work and no table writes. Expected: output identical to today. Test in Task 2 (compare extension OIDs against the no-binding mint).

---

### Task 1: The log client

**Files:** Create `worker/src/ct/log-client.ts`. Test: `worker/src/__tests__/ct-log-client.test.ts`.

**Interfaces — produces:**
- `submitPreChain(log: Fetcher, chainB64: string[], timeoutMs = 2000): Promise<SctResponse | null>`. POSTs `{ chain }` to `/ct/v1/add-pre-chain`. Returns `null` on timeout, network error, non-200, or a body that fails the `SctResponse` shape check (`sct_version` 0, `id` base64 of 32 bytes, `timestamp` a number, `extensions` and `signature` base64 strings).
- `submitChain(log: Fetcher, chainB64: string[], timeoutMs = 2000): Promise<boolean>`. Same, against `/ct/v1/add-chain`; `true` only on 200.

`SctResponse` comes from `./sct`. The path prefix is the log's base path, configured in `CT_LOG_PATH` and defaulting to `/logs/notme`.

- [ ] Step 1: tests with a fake `Fetcher`:
  - 200 with a valid SCT returns it;
  - a malformed SCT returns `null`;
  - 500 returns `null`;
  - a fetch that never resolves returns `null` within `timeoutMs + 100`;
  - the request body is `{ chain: [...] }` at the right path.
- [ ] Step 2: run them and see them fail (module missing).
- [ ] Step 3: implement with `AbortSignal.timeout`.
- [ ] Step 4: run them and see them pass.
- [ ] Step 5: mutations. Removing the timeout fails the "never resolves" test; skipping the shape check fails the "malformed" test.
- [ ] Step 6: commit.

### Task 2: Log both certificates of every bridge pair

**Files:**
- Modify `worker/src/signing-authority.ts` (`mintBridgeCertPair`, ~1686; schema for `ct_backlog`).
- Test: `worker/src/ct-mint.do.test.ts` (new).
- Modify `worker/vitest.workers.config.mts`: add a `CT_LOG` service binding to a stub whose behaviour each test selects (ok / 500 / hang / ok-then-fail). Keep existing tests unbound by using a SECOND pool project or a per-test toggle; existing suites must see no binding.

**Interfaces:**
- Consumes Task 1.
- Env gains an optional `CT_LOG?: Fetcher`.

**Algorithm when `CT_LOG` is bound:**
1. Build one `pin` (serials and validity).
2. Mint the precert pair with `extraExtensions: [ctPoisonExtension()]`.
3. Submit both precert chains concurrently: `[precert, issuing CA]`, base64 DER.
4. If both return SCTs, mint the final pair under the same pin with `sctListExtension([serialiseSct(sct)])` per cert.
5. Otherwise mint the final pair with no CT extension, and insert both final chains into `ct_backlog`.

- [ ] Step 1: tests.
  - Binding absent: the final certs contain neither OID, and `ct_backlog` is empty.
  - Log ok: each final cert carries `CT_SCT_LIST_OID`, no poison, and the same serial and validity as its precert (capture via the stub). The SCT's `id` is the stub log's id.
  - **RF1**, the signing precert gets 500: no SCT on either cert, and 2 backlog rows.
  - **RF3**, a hang: the mint completes within the timeout plus slack, and the pair is backlogged.
  - **RF5**, absent binding equals today: compare extension OID lists.
- [ ] Step 2: red. Step 3: implement. Step 4: green, plus the existing suites (`do-rpc-trust-boundary`, `cert-exchange-*`, `token-exchange`, `rpc-surface`).
- [ ] Step 5: mutations, each failing a test:
  - log one cert and not the other;
  - drop the pin from the final mint;
  - backlog nothing on failure;
  - refuse the mint on log failure.
- [ ] Step 6: commit.

### Task 3: Log every tier

**Files:** `worker/src/signing-authority.ts` (`mintIssuingCa`, ~1727); `worker/src/ct-mint.do.test.ts`.

The same algorithm for the single tier certificate, including renewals (`renewTier` and collect both call `mintIssuingCa`). Tests mirror Task 2: absent, ok, fail → backlog, hang. Mutations: no pin, and no backlog.

### Task 4: Drain the backlog

**Files:**
- `worker/src/signing-authority.ts` (the existing `alarm()` refresh path, plus health);
- the `/admin/alarm-health` route in `worker/worker.ts`, or a new `/admin/ct-health` behind `authorityManage`;
- `worker/src/ct-mint.do.test.ts`.

**Behaviour:**
- In the existing alarm, after the bundle refresh and inside its try, call `#drainCtBacklog()` if `CT_LOG` is bound.
- Submit up to 20 rows with `logged_at IS NULL AND attempts < 24`, oldest first, via `submitChain`. Set `logged_at` on success and `attempts = attempts + 1` on failure.
- Never throw out of the drain; a drain error must not trip the alarm circuit breaker.
- Health reports `backlog` (unlogged count), `oldestUnloggedAgeS`, `gaveUp` (attempts ≥ 24) and `lastError`.

- [ ] Tests:
  - 25 rows with a log ok: one fire logs 20, the next logs 5.
  - A log that 500s: attempts increment, and rows at 24 are skipped and counted in `gaveUp`.
  - A drain that throws does not increment the alarm failure count.
  - Health fields are correct.
- [ ] Mutations:
  - no 20-row cap;
  - no attempts cap;
  - a drain error counted as an alarm failure.

### Task 5: Deploy wiring and published log key

**Files:**
- `ct/config.notme.json`: add a production log entry, `notme` (`log_type: prod`, `temporal_interval` 2026-01-01..2027-07-01, `require_server_auth_eku: false`, roots = the production root).
- `ct/README.md`: deploy steps and status.
- `worker/wrangler.toml.example`: commented `[[services]] binding = "CT_LOG"`.
- `Taskfile.yml`: a `ct:verify` target that fetches the deployed log's `log.v3.json` and checks its key against `trust/notme-ct-log.json`.
- `.github/workflows/release.yml`: the `trust-anchor` job also signs `trust/notme-ct-log.json`.
- `trust/README.md`.

Deploying the log itself is an OWNER step, documented and not automated here. It needs:
- azul `ct_worker` built from a source carrying the `require_server_auth_eku` flag;
- an R2 bucket and a KV namespace;
- `SIGNING_KEY` and `WITNESS_KEY` secrets;
- then the `CT_LOG` binding on notme.

- [ ] Steps:
  - `trust/notme-ct-log.json` holds a placeholder state that `ct:verify` reports as "log not yet provisioned" (exit 0), so CI is not broken before the log exists;
  - `docs:check` passes;
  - actionlint passes.

### Task 6: Falsifiable acceptance

**Files:** `worker/src/ct-acceptance.do.test.ts`.

Against a REAL local azul log (`CT_LOG_URL`; skipped when absent, as `ct-full-cycle` is), drive the real route `/cert/gha` with a stubbed GHA JWKS, as existing GHA tests do, with `CT_LOG` bound to that log:

1. The returned pair's SCTs verify under azul's `sct_validator`. Reuse the spike's Rust test: write the certs to a file, then run `cargo test -p sct_validator --test notme_embedded_sct` in `~/remotes/art/azul` when available, else skip with a clear message.
2. Stop the log, mint again: the mint succeeds unlogged and is backlogged.
3. Restart the log, fire the alarm: the backlog drains, and `get-entries` shows the final cert.

**Baseline:** run against plan-start HEAD and record the failure.

Cross-mutations to record:
- Task 2's no-backlog;
- Task 4's drain disabled.
