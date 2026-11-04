# Durable Objects audit against Cloudflare best practices (2026-11-03)

Tracked findings: notme-b51777 (M1), notme-b52d7c (M2), notme-b54368 (M3), notme-b556a4 (M4), notme-b567c9 (error-message leaks); Low items folded into notme-070a8f and notme-5c2511. Line numbers are as of goalzero 2ce4813.


Repo `notme`, branch `goalzero` (HEAD c74f888). Read-only audit: no edits, tests not run. Docs fetched 2026-11-03.

## Verdict

**The DO design is sound and above average. There are no High findings.** SigningAuthority is a legitimate coordination atom. Single-use state uses SQLite compare-and-swap throughout, and RPC errors are returned as discriminated unions. The `#private` discipline is enforced by a pinned surface test, and the alarm pattern follows what the docs recommend. There are four Medium findings. Three come from one root cause: a non-storage `await` sitting between related reads and writes. Docs: "Non-storage I/O like fetch() ... allows other requests to interleave". The fourth is a public config template that a fresh account can no longer deploy.

## Sources (fetched live)

| Key | URL |
|---|---|
| RULES | https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/ |
| STORAGE | https://developers.cloudflare.com/durable-objects/best-practices/access-durable-objects-storage/ |
| ERR | https://developers.cloudflare.com/durable-objects/best-practices/error-handling/ |
| SQLAPI | https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/ |
| ALARMS | https://developers.cloudflare.com/durable-objects/api/alarms/ |
| INMEM | https://developers.cloudflare.com/durable-objects/reference/in-memory-state/ |
| MIGR | https://developers.cloudflare.com/durable-objects/reference/durable-objects-migrations/ |
| LIMITS | https://developers.cloudflare.com/durable-objects/platform/limits/ |
| RPC | https://developers.cloudflare.com/workers/runtime-apis/rpc/ (and /rpc/lifecycle/) |
| WBP | https://developers.cloudflare.com/workers/best-practices/workers-best-practices/ |
| WCFG | https://developers.cloudflare.com/workers/wrangler/configuration/ |
| VITEST | https://developers.cloudflare.com/workers/testing/vitest-integration/isolation-and-concurrency/ |

**Where the docs and the local skill disagree:**
- `~/.claude/skills/durable-objects/references/rules.md` shows migrations run with `ctx.blockConcurrencyWhile(async () => this.migrate())`. RULES says the same thing. STORAGE's own SQL example runs `CREATE TABLE IF NOT EXISTS` in the constructor *without* blockConcurrencyWhile. For purely synchronous `sql.exec` DDL the wrapper adds nothing for correctness. The docs win, and both forms are acceptable.
- RULES now names the test package `@cloudflare/vitest-plugin`. The repo uses `@cloudflare/vitest-pool-workers` 0.18.7, whose `cloudflareTest` Vite-plugin form is the same v4 API. This is not a defect.

## Inventory

- **SigningAuthority** (`worker/src/signing-authority.ts:457`)
  - `extends DurableObject`, SQLite-backed (wrangler.toml.example:157-158, `new_sqlite_classes`).
  - One named instance, `idFromName("default")`, used at 37 call sites in worker.ts plus cert-exchange.ts and internal-ca-bundle.ts.
  - About 62 public RPC methods plus `alarm()`. No constructor and no blockConcurrencyWhile; schema is created lazily by `#ensure*Schema` helpers.
- **RevocationAuthority** (`worker/src/revocation.ts:83`)
  - A plain class, not `extends DurableObject`. Legacy KV backend (wrangler.toml.example:153-154, `new_classes`).
  - `fetch()`-only. Its sole caller is `checkRevocation()` (revocation.ts:346), which has no production call sites (by design per bead notme-8d3018). It is bound and deployed but unrouted.

---

## Findings

### M1 (Medium): `consumeBootstrapCode` does not use compare-and-swap; one bootstrap code can admit two registrants

**Fixed in f9f69af** (notme-b51777): the UPDATE carries `AND used = 0` and success requires `changes() = 1`.

- **Location:** `worker/src/signing-authority.ts:4218-4239`
  - Reads `SELECT ... WHERE used = 0` (4218).
  - Then `await timingSafeEqual(...)` (4225). This is an HMAC over crypto.subtle, a non-storage await, preceded by `await import`.
  - Then an unconditional `UPDATE bootstrap SET used = 1 WHERE id = 'code'` (4236), with no `AND used = 0` and no `changes()` check.
- **Docs:**
  - RULES: input gates "block new events" during synchronous execution, so storage-only read-modify-write is safe.
  - RULES: "Non-storage I/O like fetch() ... allows other requests to interleave. Use optimistic locking (version checks)".
  - The docs guarantee nothing about crypto.subtle or dynamic-import awaits, so the conservative reading treats them as interleave points.
  - The code's own comment at 4053-4062 makes the same call: "`await import(...)` is a yield point".
- **Risk:**
  - Two concurrent `beginFirstUserRegistration` calls (signing-authority.ts:3389-3401) carrying the same code can both get `true`, and both write a first-user mark. Two admins come out of one single-use code.
  - Every other single-use path in this class uses `DELETE`/`UPDATE ... WHERE <state>` plus `changes()` (mintDPoPTokenOnce 1126-1141, redeemAuthorizationCode 1592-1605, consumePopNonce 2346-2353, collectTierEnrolment 2629-2641). This one does not.
- **Fix (one line):**
  - Change the write to `UPDATE bootstrap SET used = 1 WHERE id = 'code' AND used = 0`.
  - Return `changes() === 1`.
  - Add a two-concurrent-consumers DO test.

### M2 (Medium): a CT-bound mint can sign with a key or epoch that changed during its log round-trip

**Fixed in 1a91149** (notme-b52d7c): after the add-pre-chain await the key id and epoch are re-read and the mint is refused if either moved. Since e687734 (notme-b54368) the same re-check runs before every signature on every cert mint path, not only after the log await. Since 1d42837 (notme-d06b7b) a refused or failed tier mint at collect gives the enrolment back, so a retry can still collect it.

- **Location:**
  - `signing-authority.ts:1803-1810` (mintBridgeCertPair) and `2266-2270` (mintIssuingCa) capture `signingKey` and `state.epoch/keyId`.
  - Then `#mintLogged` awaits `postPreChain` over the CT_LOG service binding (1906-1920, up to 2 s per cert).
  - It then mints the final cert with the captured key and epoch (1925 / 1939).
- **Docs:** RULES says "Non-storage I/O like fetch() or writing to R2 allows other requests to interleave. Use optimistic locking (version checks) around it." A service-binding fetch is exactly that kind of I/O.
- **Risk:** during the window, `rotate()` (3111) or `revokeEpoch()` (3221) can run.
  - **After `rotate()`:** the in-flight request signs a certificate with the retired key, whose row was deleted and whose CryptoKey is still held in a closure. It reports the old `key_id`. That is issuance under a key the operator just retired, possibly because it was compromised, accepted by verifiers through the `prevKeyId` grace window.
  - **After `revokeEpoch()`:** the cert carries the pre-revocation epoch. That fails safe at verifiers but is handed out as if it were good.
  - The window is narrow and operator-triggered, so this is Medium, not High.
  - Only applies when `CT_LOG` is bound. The unbound path has no external I/O.
- **Fix:**
  - After the `Promise.all` at 1906, re-read `state` (epoch, keyId) synchronously right before the final `p.mint`.
  - If either changed, return a retryable refusal (or remint from scratch) instead of signing with the captured key.
  - Optionally keep a monotonically increasing `key_generation` in `state` and compare it.

### M3 (Medium): `rotate()` is not atomic

**Fixed in e687734** (notme-b54368):
- rotate() does all its crypto first: it loads the old key, exports its public half, then generates, exports, seals and imports the new key.
- Then it makes every storage change in one `ctx.storage.transactionSync`: the archive, delete, insert, seqno bump and both prev-key values. The in-memory key switches in the same synchronous run.
- `prevKeyId`/`prevPubKey` now use the synchronous `ctx.storage.kv` API. It reads and writes the same `__cf_kv` store as the async `put()` used before, so existing records carry over. A probe confirmed it rolls back with the transaction.
- If the old key was replaced while rotate() was awaiting, it refuses and writes nothing.
- Cold start converges in both modes. Each attempt finishes its async work, then synchronously adopts the key already in memory, or runs `INSERT … ON CONFLICT DO NOTHING` and re-reads the row, retrying if the stored row is not its own.
- The comment's follow-up is also done. Every cert mint captures key, kid and epoch in one synchronous read. `#mintLogged` re-checks them before every signature, including the no-log and no-issuer paths, which used to sign unchecked.
- Tests: `worker/src/rotate-atomic.do.test.ts`.

- **Location:** `signing-authority.ts:3111-3176`
  - The archive INSERT, `DELETE FROM keys`, and seqno bump are synchronous (3144-3161).
  - Then `await this.#getOrCreateSigningKey()` (3164) generates, exports and seals the new key over several crypto.subtle awaits, and INSERTs it.
  - Then come two separate awaited KV-API writes: `await put("prevKeyId")` and `await put("prevPubKey")` (3168-3169).
- **Docs:**
  - SQLAPI: writes with no `await` between them are combined and submitted atomically, and "Using `await` will disable automatic write coalescing."
  - SQLAPI: transactionSync rolls back if the callback throws.
  - RULES: "No shutdown hooks ... write state incrementally."
  - RULES: "Uncaught exceptions in a Durable Object can leave it in an unknown state."
- **Risk:**
  - Failure or eviction between the DELETE and the new INSERT leaves the authority keyless. The next call silently generates another key, and `prevKeyId`/`prevPubKey` are never written, so the grace window that rotate exists to provide (notme-54f84b) is lost.
  - Failure or eviction between the two puts leaves `prevKeyId` pointing at a stale `prevPubKey`; `generateBundle` (3063) guards `prevKeyId !== keyId` but not that pairing.
  - If the crypto awaits interleave, as the conservative docs reading allows, a concurrent request sees `#signingKey === null` with no row, generates its own key, and the second `INSERT INTO keys` (860) hits a PK conflict and throws. If the throwing side is rotate, its prev-key writes never happen.
  - The cold-start path (810-878) has the same two-concurrent-first-callers shape. In persistent mode the second INSERT throws, which fails loudly. Ephemeral mode's `INSERT OR REPLACE` (841) silently diverges the stored pubkey from a key that already signed.
- **Fix:**
  - Do all async work first: generate, export, seal and keyId the new key; read the old public key.
  - Then perform the archive, delete, insert, seqno bump and the prev-key writes in one `ctx.storage.transactionSync(() => ...)`.
  - Move `prevKeyId`/`prevPubKey` into a SQL row, or use the synchronous `ctx.storage.kv` API, which shares the transaction context per SQLAPI.
  - Set the in-memory key only after the commit.

### M4 (Medium): `wrangler.toml.example` provisions a KV-backed class a fresh account can no longer create

- **Location:** `worker/wrangler.toml.example:152-154` (`[[migrations]] tag="v1" new_classes=["RevocationAuthority"]`). The same block is in `worker/wrangler.e2e.toml:56-58`.
- **Docs:**
  - STORAGE: "Creating new namespaces with the key-value storage backend is no longer supported" for accounts without an existing KV-backed namespace. "The key-value storage backend remains available for existing namespaces."
  - MIGR: "Storage backends are immutable once provisioned ... a migration path from the key-value storage backend to the SQLite storage backend will be available in the future."
- **Risk:**
  - The file says "Copy to wrangler.toml and fill in your CF resource IDs" in a public repo. A new adopter's first `wrangler deploy` is refused.
  - Production is unaffected (the namespace already exists), and staging works only because the account already holds a KV-backed namespace.
  - `wrangler.e2e.toml` runs under `wrangler dev` (local), so it is not affected today.
  - RevocationAuthority is also unrouted in production (notme-8d3018), so the class is deployed weight with no caller.
- **Fix:**
  - In the example only, change v1 to `new_sqlite_classes = ["RevocationAuthority"]`. A fresh deployment has no migration history, and the class's `storage.transaction()` and KV calls work unchanged on SQLite per SQLAPI.
  - Keep production's real `wrangler.toml` as is.
  - Better: if nothing is going to route to it, remove the class with a `deleted_classes` migration in production and drop it from the template.

### L1 (Low): circuit breaker "do NOT re-arm" is defeated by the warm-path `scheduleNextRefresh()`

- **Location:** `signing-authority.ts:722`, 4329-4334, 4415, 4463-4470.
  - Inside `alarm()`, `#publishBundle → generateBundle → #getOrCreateSigningKey` (warm path) calls `scheduleNextRefresh()`. That runs *before* the breaker decision, so the alarm is already re-armed when the "tripped on this fire, not re-arming" branch returns.
  - Any RPC traffic also re-arms it while the breaker is open (722).
- **Docs:** ALARMS: "If `getAlarm` is called while an alarm is already running, it returns `null` unless `setAlarm` has also been called since the alarm handler started running." So the warm-path setAlarm does take effect inside the handler.
- **Risk:**
  - The breaker does not stop alarm invocations. It only turns them into cheap "skipped" fires: one per 4 minutes while traffic exists, plus one extra after the trip.
  - The cost bound still holds. The comments and the bead's acceptance criterion ("does not re-arm") are inaccurate.
  - Combined with the self-latching design, a 20-minute KV blip needs a manual `resetAlarmHealth()`. ALARMS instead recommends: "catch any exceptions inside your `alarm()` handler and schedule a new alarm before returning". The breaker's real impact is limited because `ensureCurrentCABundle` (internal-ca-bundle.ts:45-75) regenerates a stale bundle on read.
- **Fix:**
  - Either make the warm path skip re-arming when `failure_count >= MAX`, or replace the latch with exponential backoff (e.g. 4 min → 8 → 16 ... capped at 1 h). That stays cost-bounded and self-heals.
  - Correct the comments either way.

### L2 (Low): DO bundle publish has no KV TTL, unlike the Worker path

- **Location:** `signing-authority.ts:4351-4354`. The Worker path writes `expirationTtl: 60` (internal-ca-bundle.ts:72-74).
- **Risk:** with a dead alarm, the DO-written `bundle:current` never expires. internal-ca-bundle.ts:39-44 says "both are fixed", but the DO-side put still has no TTL. This is mitigated by the stale-at-read gate.
- **Fix:** add the same `{ expirationTtl }` to the DO put.

### L3 (Low): non-transactional table-rebuild migrations can wedge the object

- **Location:**
  - `signing-authority.ts:618-636` (retired_keys v1→v2: CREATE, INSERT, DROP, RENAME).
  - `worker/src/auth/principals.ts:94-113` (capability_grants v2 rebuild, same shape).
- **Docs:** SQLAPI: "If `callback()` throws an exception, the transaction will be rolled back." Implicit coalescing gives no rollback on throw. RULES: "Uncaught exceptions ... can leave it in an unknown state".
- **Risk:** a throw after `CREATE TABLE retired_keys_v2` (which has no IF NOT EXISTS) leaves `_v2` behind. Every later `#ensureSchema` then throws "table already exists" and the CA stops serving. These are one-shot migrations, probably already applied in production; the risk is to forks and staging upgrades.
- **Fix:** wrap each detect-and-rebuild in `ctx.storage.transactionSync`.

### L4 (Low): schema DDL runs on hot paths on every call; `ALTER` errors are swallowed indiscriminately

- **Locations:**
  - `#ensureTierEnrolmentSchema` (2369-2423): CREATE plus 9 `ALTER TABLE ADD COLUMN` attempts that throw and are caught on *every* tier call.
  - `getSessionSecret` (3421): CREATE on every call. It has 28 call sites, including every session-authenticated request.
  - `getCACertificatePem` (956).
  - `ensurePrincipalSchema` (principals.ts:44-125): reads sqlite_master plus DDL on every call.
  - `#ensurePopNonceSchema` (2311).
  - Only `#ensureSchema`, `#ensureCtSchema` and `#ensureAlarmHealthSchema` are memoised.
- **Docs:**
  - RULES: "Migrate in the constructor ... `PRAGMA user_version` is unsupported, so track versions in a table."
  - The skill's rules.md says the same thing.
- **Risk:**
  - Correctness is fine: the DDL is synchronous, so it is atomic with respect to other events.
  - The real costs are CPU on the hot path, plus a `catch {}` that hides any ALTER failure other than "duplicate column".
- **Fix:**
  - Run one `migrate()` from the constructor, inside `ctx.blockConcurrencyWhile`, over a `schema_version` table.
  - Run each step once, inside transactionSync.
  - Delete the per-method `#ensure*` calls, or memoise them.

### L5 (Low): replay and nonce pruning scans unindexed columns on every write

- **Location:**
  - `DELETE FROM dpop_jtis WHERE expires_at <= ?` (1126) on every DPoP mint.
  - `auth_codes` (1545).
  - `pop_nonces` (2324).
  - `tier_enrolments` prune (2457).
- **Docs:** RULES: "Index frequently filtered columns." STORAGE: indexes reduce "how much data is scanned", and the extra write is "typically offset by the reduction in rows read".
- **Fix:** add `CREATE INDEX IF NOT EXISTS ... (expires_at)` on each table.

### L6 (Low): callers never retry transient DO errors

- **Location:** every `env.SIGNING_AUTHORITY.get(...).method()` caller (worker.ts, cert-exchange.ts, internal-ca-bundle.ts:55). Nothing checks `.retryable` or `.overloaded`.
- **Docs:**
  - ERR: "JavaScript Errors with the property `.retryable` set to True are suggested to be retried" (idempotent requests only).
  - ERR: `.overloaded` "should not be retried".
  - ERR: "avoid reusing a `DurableObjectStub` after it throws".
  - ERR: "strongly recommended to apply exponential backoff".
- **Risk:** every deploy resets the object, so in-flight read calls fail with 500s that could have succeeded.
- **Fix:** add a small `withDoRetry` helper (fresh stub per attempt, jittered backoff, at most 3 tries) and apply it only to idempotent reads: `getSessionSecret`, `getPublicKeyJwk`, `getCACertificatePem`, `getAuthorityState`, `generateBundle`. Never wrap the consume-once methods.

### L7 (Low): DO exception messages are returned to HTTP clients

- **Location:** `worker/src/cert-exchange.ts:341` (`"cert minting failed: " + e.message`) and `:373`.
- **Docs:** ERR: exceptions "will be propagated to the callsite of the client", with `.remote` set for user-code and infrastructure errors.
- **Risk:**
  - Internal messages reach an authenticated caller verbatim. Examples: SQLite constraint text, the KEK misconfiguration message (`#keyStorageMode`, 470-473), runtime reset or overload strings.
  - Elsewhere the class deliberately avoids this (comments at 3276-3279, 1493-1499).
- **Fix:** log `e` and return a constant body.

### L8 (Low): a rejected KEK derivation is cached for the life of the instance

- **Location:** `signing-authority.ts:497` (`this.#kekPromise ??= deriveKek(secret)`).
- **Docs:** INMEM: in-memory state lives until eviction.
- **Risk:** one transient failure poisons every key load until eviction.
- **Fix:** add `.catch(e => { this.#kekPromise = null; throw e; })`.

### L9 (Low): `approveTierEnrolment` reports `ok` without checking its guarded UPDATE

- **Location:** `signing-authority.ts:2534-2555`. It reads the row, then `await this.getAuthorityState()` runs inside the argument list, and the `UPDATE ... AND status='pending'` result is never checked.
- **Risk:** of two concurrent approvals, the loser is told `{ok:true}` but its scopes and criteria are not recorded. This is a misleading UI result, not a privilege issue.
- **Fix:** compute the epoch before the read, then check `changes() === 1`.

### L10 (Low): compatibility_date is 8 months old

- **Location:** `wrangler.toml.example:5` and `wrangler.e2e.toml`, both `2026-03-01`, mirrored in `vitest.workers.config.mts:35`.
- **Docs:** WBP: "Setting it to today's date on new projects ensures you get the latest behavior." Update it periodically.
- **Fix:** bump all three together. The vitest comment already requires that.

### L11 (Low): alarm test arms a 50 ms alarm, then races `runDurableObjectAlarm`

- **Location:** `worker/src/alarm-health.do.test.ts:76-84` (`setAlarm(Date.now() + 50)`, then `runDurableObjectAlarm`, then `expect(ran).toBe(true)`). The same pattern is at :93-99.
- **Risk:**
  - Under load the real alarm can fire before `runDurableObjectAlarm`. The helper then returns `false`, the assertion fails, and the KV write lands at an arbitrary time.
  - This is a strong candidate root cause for the open flake bead notme-070a8f ("publishes a bundle to KV when the alarm fires").
  - Separately, every key load arms a real 4-minute alarm (722, 880) that no test deletes.
- **Fix:**
  - Arm `Date.now() + 60_000`; `runDurableObjectAlarm` runs it immediately whatever its time.
  - `deleteAlarm()` in an `afterEach` for stubs the test armed.
  - VITEST: "Storage isolation is per test file", so leftovers stay within the file, which matches the bead's same-file cascade.

### Info

- **I1 — single named SigningAuthority is a legitimate coordination atom, not a reflexive "global singleton".**
  - RULES says "Create one Durable Object per logical unit that needs coordination" and also "Do not create a single 'global' Durable Object that handles all requests".
  - The CA root must serialise epoch, seqno, key identity, tier generations and single-use consumption. Several invariants span tables in one SQLite database, e.g. `#admitRegistration` plus credential store inside one transactionSync (3274), and `joinInviteWithFederated` (3505). Sharding those would turn local atomicity into cross-object coordination.
  - Two classes of work do *not* need the atom:
    1. Read-mostly fan-out on the request hot path: `getSessionSecret` (28 sites, every session request), `getPublicKeyJwk`, `getCACertificatePem`, `getAuthorityState` in verifyX509.
    2. Independent replay ledgers keyed by random ids: `dpop_jtis`, `pop_nonces`, `auth_codes`.
  - The trigger to act is LIMITS' soft limit ("About 1,000 requests per second per individual object") or RULES' 500-1,000 rps guidance. Below that, leave it.
  - Cheapest first step when needed: serve the read-only values from a short-TTL isolate or Cache API copy, accepting a seconds-long lag on session-secret rotation. Shard nonce ledgers by `idFromName(hash(jti) % N)` only if mint volume grows.
- **I2 — `idFromName` + `get` vs `getByName`.** Code uses `idFromName("default")` plus `get` at every site. RULES recommends `getByName()` ("Use `getByName()` for consistent routing"). This is equivalent, and stubs are lazy ("Creating a stub does not instantiate or wake up the Durable Object"), so per-request stub creation is fine. Optional cleanup: one `authorityStub(env)` helper.
- **I3 — no location hint or jurisdiction.** The CA lives near whoever first touched it. RULES: hints "are suggestions, not guarantees". Acceptable; consider `locationHint` only if latency matters.
- **I4 — RevocationAuthority uses `fetch()` rather than RPC.** RULES: "Projects with compatibility date `2024-04-03` or later should use RPC methods." Because it is a plain class (no `extends DurableObject`) it has no RPC surface, so its TS `private` (revocation.ts:84, 94) is not an exposure. Also, `checkRevocation` maps any non-ok body, including a 400, to `rollback_attack` (revocation.ts:353-355). Moot while unrouted.
- **I5 — observability.** Logs and invocation logs are enabled for prod and staging. Traces are not. WBP: "Enable logs and traces before you deploy to production." Optional.
- **I6 — CT backlog rows are never deleted once logged.** This is unbounded but tiny against LIMITS' "10 GB" per SQLite object and "2 MB" row limit. No action needed; an optional prune of rows where logged_at is older than N days.
- **I7 — warm-path `getAlarm()` on every key access.** `#getOrCreateSigningKey` runs `await scheduleNextRefresh()` (722) on every sign, often 2-3 times per mint via `getAuthorityState`. It is cheap and documented as the notme-4896d8 fix. No action.
- **I8 — the 4-minute refresh against the 5-minute max age leaves one minute of slack.** ALARMS gives no precision guarantee (only "guaranteed at-least-once execution"). This is mitigated by stale-at-read regeneration (internal-ca-bundle.ts:45). No action unless an external verifier reads KV directly.
- **I9 — DO tests do not load wrangler config.** They declare bindings inline (vitest.workers.config.mts, for VPC reasons), so the migrations block is never exercised by tests and the compat date is duplicated by hand. This is acceptable and documented in the file.

---

## What the code does right (per the docs)

1. **SQLite backend for the class that matters.** SigningAuthority uses `new_sqlite_classes` (STORAGE: "Cloudflare recommends all new Durable Object namespaces use the SQLite storage backend").
2. **Migration history is append-only and correct**, v1 then v2. `migrations` is top-level and inheritable, so staging inherits it, while DO bindings are redeclared per environment as WCFG requires ("Bindings ... are not inheritable").
3. **Single-use and CAS semantics done right almost everywhere.**
   - DELETE / UPDATE ... WHERE state, plus `changes()`, all synchronous between the check and the write: mintDPoPTokenOnce 1126-1141, redeemAuthorizationCode with `DELETE ... RETURNING` (1592-1605), consumePopNonce, collectTierEnrolment, revokeTierEnrolment, `#admitRegistration`.
   - The tier generation counter is claimed with a `generation = ?` guard, and the comment explicitly anticipates interleaving across the earlier awaits (2900-2902).
   - This is exactly RULES' "optimistic locking (version checks)" guidance. M1 is the lone exception.
4. **transactionSync where multi-table atomicity matters.** Passkey registration admit plus store (3274) and federated invite join (3505). Both match SQLAPI's rollback-on-throw semantics.
5. **Persist first, then cache in memory.** The key row is written before `#signingKey` is set (859-878). Caches (`#signingKey`, `#ctPinCache`, schema flags) are derived from storage and safe to lose on eviction (INMEM, RULES: "Always persist important state to SQLite storage").
6. **Alarm handler follows the documented pattern.**
   - It catches every error and reschedules itself, never throwing into the 6-retry budget (ALARMS: "catch any exceptions inside your `alarm()` handler and schedule a new alarm before returning").
   - It checks getAlarm before setAlarm (ALARMS: a single alarm, and setAlarm "will override the existing alarm").
   - It is idempotent under double fire: seqno only advances, and counters use SQL `x = x + 1`.
   - CT drain work is bounded (20 rows, concurrency 4, about 10 s) and well inside LIMITS' "15 minutes" alarm wall time.
   - The CT drain is isolated from the breaker.
7. **RPC surface hygiene.**
   - Consistent ECMAScript `#private` on every non-RPC member of both the DO and the three WorkerEntrypoints, with a test that pins the public surface (`rpc-surface.do.test.ts`).
   - This matches RPC's example: a public method and getter are callable, while `#value` stays internal.
   - CryptoKeys never cross RPC, and `#getOrCreateSigningKey` is off the surface.
8. **Expected failures are returned, not thrown, across RPC.** `ReceiptSignResult`, `DelegatedJwtSignResult`, `mintBridgeCert` refusals and passkey verify failures are all returned values. This sidesteps ERR's "avoid reusing a `DurableObjectStub` after it throws" and the stringified-error problem.
9. **Bounded storage growth on unauthenticated writers.** `TIER_ENROLMENT_CAP`, `CLAIM_CAP`, TTL pruning on every write, and never-pruned audit tables only for public-key history (which is what RECEIPTS §2.3 requires).
10. **Every RPC call is awaited, and work is deliberately not floated.** RULES: "Always `await` RPC calls". WBP: floating promises.
11. **No blockConcurrencyWhile around I/O, and none needed.** All DDL is synchronous `sql.exec`. RULES: "Never across I/O."
12. **Tests use the documented harness.**
    - Real workerd via vitest-pool-workers.
    - `runInDurableObject` in 26 files and `runDurableObjectAlarm` for alarms.
    - Per-name DO isolation, a real SQLite backend (`useSQLite: true`), and the classic backend matched for REVOCATION (`useSQLite: false`).
    - CT suites are split so the default suite proves the no-binding path.
13. **Well inside the limits.** No SQL statement comes near 100 bound parameters or 100 KB. Row payloads are kilobytes against the 2 MB cap. RPC payloads are far below RPC's "32 MiB". CPU per call is a few Ed25519 operations plus X.509 encoding, far from the 30 s default.

