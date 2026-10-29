# Mint Path Phase 1 — Generation Counter and Clone Policy — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A copied tier key is detected at its next renewal and the enrollment is shut off, while an honest machine that loses a renewal response is never mistaken for a copy.

**Architecture:**
- Each enrollment gets a generation counter. Renewal binding v2 signs the generation the machine believes is current.
- The authority advances the counter atomically. It treats an exact resend of the last request as a retry and anything else stale as a fork.
- The approver chooses a clone policy at approval. `singleton` is the default; `replicas:N` is gated on `authorityManage` and capped at a 7-day horizon.
- The `task-cert` client renews with v2, persisting the request before sending so it can resend the exact bytes.

**Tech Stack:** TypeScript, Cloudflare Workers + Durable Objects (SQLite), vitest (plain and `vitest-pool-workers`), `@peculiar/x509`, tsx for `scripts/task-cert`.

**Spec:** `docs/superpowers/specs/2026-10-28-mint-path-design.md`, §5.1, §5.2 and §8 (phase 1 row of §10).

## Global Constraints

- Binding v2 bytes: `"notme/tier-renew/v2\0" || SPKI || uint64be(iat) || uint64be(generation)`.
- Retry digest: SHA-256 over the **full v2 binding bytes**.
- Retry window: one tier lifetime after the original `iat`, which is **3600 s**. The skew window for fresh requests stays `RENEWAL_SKEW_S` (120 s).
- A newly signed request at `current - 1` is a fork, never a retry.
- Fork under `singleton`: set `revoked_at` and `revoke_reason = 'fork_detected'`. The refusal reason is `fork_detected` (HTTP 403).
- Retiring v1:
  - New enrollments accept v2 only.
  - An enrollment that has renewed with v2 once never accepts v1 again.
  - Enrollments that predate this change keep v1 until their horizon ends.
- Clone policy values: `singleton` (default), `replicas:2`, `replicas:4`, `replicas:8`. Anything else is a 400.
  - `replicas:*` requires the approver's **live** `authorityManage`, otherwise 403.
  - `replicas:*` with `renew_days` 30 is a 400.
- Phase 1 has no branch endpoint: under `replicas:N`, every line behaves as a singleton. The policy is recorded and shown, and branching (§5.3) is a follow-up bead.
- Every new behaviour is mutation-checked: name the production change that makes each new test fail, and confirm it fails.
- Workers-pool runs on this machine need `--testTimeout 30000`.
- Commit format: `[<bead-id>] type(scope): description`, ending with the session's attribution lines.

## Review Focus

1. **A replayed old renewal request** (captured, `iat` hours old, stale generation) must be refused as `stale_proof`, **not** treated as a fork. Otherwise anyone who saw one request could shut a machine off. Test in Task 2.
2. **An invalid proof with a stale generation** must not revoke anything. Only a valid signature by the enrolled key can trigger a fork. Test in Task 2.
3. **Two concurrent renewals at the same generation** (a clone racing the original): exactly one advances the counter, and the other is a fork. Test in Task 2.
4. **The client never signs a fresh v2 request while a pending one exists.** After a lost response outlasting the retry window, it must stop with "renewal state lost, re-enroll" rather than fork itself. Test in Task 4.
5. **A legacy enrollment** (no `generation` in `tier.json`, `binding_version` NULL) keeps renewing with v1. Its first v2 renewal locks v1 out. Test in Task 3.

---

### Task 1: Binding v2 and the retry digest (pure)

**Files:**
- Modify: `worker/src/auth/tier-enrolment-binding.ts`
- Test: `worker/src/__tests__/tier-renewal-binding.test.ts` (new)

**Interfaces:**
- Produces:
  - `TIER_RENEW_V2_TAG = "notme/tier-renew/v2\0"`
  - `tierRenewalBindingV2(spki: Uint8Array, iat: number, generation: number): Uint8Array`
  - `renewalRequestDigest(binding: Uint8Array): Promise<string>`, returning lowercase hex SHA-256
  - `RENEWAL_RETRY_WINDOW_S = 3600`

- [ ] **Step 1: Write the failing tests**

  - `"v2 binding is tag || SPKI || uint64be(iat) || uint64be(generation)"`: build the bytes by hand for `spki = new Uint8Array([1,2,3])`, `iat = 1_700_000_000`, `generation = 5`, then `expect(tierRenewalBindingV2(...)).toEqual(expected)`.
  - `"v1 and v2 bindings never coincide"`: for the same spki and iat, `tierRenewalBinding(spki, iat)` differs from `tierRenewalBindingV2(spki, iat, 0)`.
  - `"generation must be a non-negative safe integer"`: `-1`, `1.5` and `2 ** 53` each throw.
  - `"the digest is SHA-256 of the binding, lowercase hex"`: equals `hex(sha256(binding))`, length 64.

- [ ] **Step 2: Run to verify the tests fail**

  Run: `cd worker && pnpm exec vitest run src/__tests__/tier-renewal-binding.test.ts`
  Expected: FAIL, `tierRenewalBindingV2` is not exported.

- [ ] **Step 3: Implement the four exports** in `tier-enrolment-binding.ts`, beside `tierRenewalBinding`, mirroring its encoding.

- [ ] **Step 4: Run to verify the tests pass**

  Same command. Expected: 4 passed.

- [ ] **Step 5: Commit** as `[notme-747cc7] feat(tier): renewal binding v2 commits to a generation`.

---

### Task 2: Generation counter, retry and fork detection in `renewTier`

**Files:**
- Modify: `worker/src/signing-authority.ts`. Touches `#ensureTierEnrolmentSchema` (~line 1836), `collectTierEnrolment` (~2001) and `renewTier` (~2096).
- Modify: `worker/worker.ts`. The `/cert/issuing-ca/renew` route (~3111) and the `/cert/issuing-ca/device/token` route.
- Test: `worker/src/tier-generation.do.test.ts` (new). Copy the `machine` / `human` / `enrolled` helpers from `tier-renewal.do.test.ts`, following that file's pattern.

**Interfaces:**
- Consumes: Task 1's exports.
- New columns, added by the existing `ALTER TABLE` loop:
  - `generation INTEGER NOT NULL DEFAULT 0`
  - `last_renewal_digest TEXT`
  - `last_renewal_iat INTEGER`
  - `revoke_reason TEXT`
  - `binding_version INTEGER`
- `renewTier(params: { publicKeyPem: string; iat: number; proof: string; generation?: number })`:
  - success adds `generation: number`, the value the client must sign next;
  - the reason union gains `"fork_detected"`.
- `collectTierEnrolment` success adds `generation: 0`, and sets `binding_version = 2` on the row it activates.
- The route passes `generation` when `body.generation` is a number. It returns `generation` on success, and `fork_detected` as 403.

**Decision order inside `renewTier`** (this is the algorithm the tests pin):
1. Key lookup, then verify the proof over v2 if `generation` is given, else v1. Invalid → `invalid_proof`, changing nothing.
2. `revoked_at` set → return `revoke_reason ?? "revoked"`.
3. Horizon, epoch and live scopes, unchanged.
4. If `generation === row.generation`: require a fresh `iat` (`RENEWAL_SKEW_S`), else `stale_proof`. Then run the atomic claim:

   ```sql
   UPDATE tier_enrolments
      SET generation = generation + 1, last_renewal_digest = ?, last_renewal_iat = ?, binding_version = 2
    WHERE key_fingerprint = ? AND status = 'active' AND generation = ?
   ```

   If `changes() !== 1`, it is a fork: the other side won.
5. Else, if `generation === row.generation - 1`, the digest equals `last_renewal_digest`, and `now - iat <= RENEWAL_RETRY_WINDOW_S`: this is a **retry**. Mint again with no counter change.
6. Else, if the `iat` is fresh (within `RENEWAL_SKEW_S`): this is a **fork**. Set `revoked_at` and `revoke_reason = 'fork_detected'`, and return `fork_detected`.
7. Else `stale_proof`. This is Review Focus 1.
8. Mint the tier as today, returning `{ ..., generation: <the row's generation after this call> }`.

- [ ] **Step 1: Write the failing tests** in `tier-generation.do.test.ts`. Each one uses a v2 `renew(m, generation, iat?)` helper.

  - `"a fresh enrollment collects at generation 0 and renews 0 → 1 → 2"`: the token response has `generation: 0`, and successive renews return `generation` 1, then 2.
  - `"a copy that renews second is a fork, and the enrollment is shut off"`: the original renews at 0 and gets 1. A second request at 0 with a fresh iat and a different digest returns 403 `{ error: "fork_detected" }`. The original's next renew at 1 then returns 403 `fork_detected`.
  - `"a lost response: resending the exact request is a retry, not a fork"`: send at 0 and discard the response. Resend the identical body: 200, `generation: 1`, and the counter is still 1. A follow-up renew at 1 gives 200.
  - `"a freshly signed request at current-1 is a fork, not a retry"`: renew at 0 (→1), then a NEW signature at 0 with `iat + 1` → `fork_detected`.
  - `"an exact resend after the retry window is stale, not a fork"`: plant `last_renewal_iat` 3601 s ago via `runInDurableObject`. The resend returns 401 `stale_proof`, and `revoked_at` stays null.
  - **Review Focus 1**, `"a replayed hours-old request with a stale generation does not revoke"`: renew at 0 and 1, then replay the captured generation-0 request body. Expect 401 `stale_proof`, and the enrollment still renews at 2.
  - **Review Focus 2**, `"an invalid proof at a stale generation changes nothing"`: renew at 0, then sign generation 0 with a different key. Expect 401 `invalid_proof`; the generation is still 1 and `revoked_at` is null.
  - **Review Focus 3**, `"two concurrent renewals at the same generation: one wins, one forks"`: `Promise.all` of two fresh, differently-timestamped requests at 0. The statuses are exactly `{200, 403}`, and the counter is 1.

- [ ] **Step 2: Run to verify the tests fail**

  Run: `cd worker && pnpm exec vitest run --config vitest.workers.config.mts src/tier-generation.do.test.ts --testTimeout 30000`
  Expected: FAIL, the token response has no `generation`.

- [ ] **Step 3: Implement the schema columns, collect's `generation: 0` / `binding_version = 2`, the decision order above, and the route plumbing.**

- [ ] **Step 4: Run to verify the tests pass**

  Run the same file, then `tier-renewal.do.test.ts` and `tier-enrolment.do.test.ts`, which must stay green: v1 renewal still works for rows with no `binding_version`. Then `rpc-surface.do.test.ts`: the pin is unchanged at 62, since no DO method is added.

- [ ] **Step 5: Mutation-check.** Each mutation must fail at least one new test:
  - skip the `generation = ?` guard in the UPDATE;
  - treat any `current - 1` as a retry, ignoring the digest;
  - drop the fresh-`iat` condition in step 6;
  - revoke before verifying the proof.

- [ ] **Step 6: Commit** as `[notme-747cc7] feat(tier): renewal counts generations; a copy renewing is a fork`.

---

### Task 3: Retiring binding v1

**Files:**
- Modify: `worker/src/signing-authority.ts`, `renewTier`, step 1 of the decision order.
- Test: `worker/src/tier-generation.do.test.ts`, a new `describe`.

**Interfaces:**
- Consumes: the Task 2 columns.
- Produces: a v1 request (no `generation`) against a row with `binding_version = 2` returns `invalid_proof`.

- [ ] **Step 1: Write the failing tests**

  - `"a new enrollment refuses v1 renewal"`: enroll (collect sets `binding_version = 2`), then a v1 renew returns 401 `invalid_proof`.
  - **Review Focus 5**, `"a legacy enrollment renews with v1 until its first v2 renewal"`: set `binding_version = NULL` via `runInDurableObject`. v1 renew → 200. v2 renew at 0 → 200, `generation: 1`. v1 renew again → 401.

- [ ] **Step 2: Run to verify they fail**

  Same command as Task 2. Expected: the first test FAILS (v1 is accepted).

- [ ] **Step 3: Implement.** Refuse v1 when `row.binding_version === 2`.

- [ ] **Step 4: Run to verify they pass**, together with all of `tier-renewal.do.test.ts`.

- [ ] **Step 5: Mutation-check.** Accept v1 regardless of `binding_version`; the first test must fail.

- [ ] **Step 6: Commit** as `[notme-747cc7] feat(tier): v2-only for new enrollments; v1 locks out after first v2 renewal`.

---

### Task 4: The `task-cert` client renews with v2 and resends exactly

**Files:**
- Modify: `scripts/task-cert/lib.ts` (`renewProof`, `renewTier`)
- Modify: `scripts/task-cert/cli.ts` (`renewNow`, `status`, and enroll's `tier.json` write)
- Test: `worker/src/__tests__/task-cert-client.test.ts`, a new `describe("renewal with a generation")`, using a fake `fetchFn` as the existing polling tests do.

**Interfaces:**
- Consumes: Task 1's `tierRenewalBindingV2`, and the Task 2 response field `generation`.
- Produces:
  - `renewTier(authority, key, opts: { generation?: number; pending?: PendingRenewal | null; savePending: (p: PendingRenewal) => void; clearPending: () => void }, fetchFn?)`
  - `type PendingRenewal = { body: string; iat: number; generation: number }`
- Files:
  - `tier.json` gains `generation`.
  - A pending request is saved as `~/.notme/tier/renew-pending.json` (0600) **before** the POST, and deleted on any definitive answer, whether 2xx or 4xx.

**Client rules:**
- If `pending` exists and `now - pending.iat <= 3600`: resend `pending.body` verbatim, and never sign a new request.
- If `pending` exists and is older than that: throw `"renewal state lost — a response never arrived within the retry window; run \`task-cert enroll\` to approve this machine again"`. Do **not** sign.
- If there is no pending request: sign v2 when `generation` is known; fall back to v1 only when `tier.json` has no `generation` (legacy).
- On success, write the new tier and set `tier.json.generation` to the response's `generation`.

- [ ] **Step 1: Write the failing tests**

  - `"signs v2 over the stored generation"`: with `generation: 3`, the fake fetch receives a body whose proof verifies under `tierRenewalBindingV2(spki, iat, 3)`, and `body.generation === 3`.
  - `"saves the request before sending, clears it after a definitive answer"`: `savePending` is called before the fake fetch resolves; `clearPending` is called after a 200 and after a 403.
  - `"a network failure leaves the pending request; the next call resends the same bytes"`: the first fake fetch throws. The second call is given that pending request and sends the identical body string.
  - **Review Focus 4**, `"a pending request older than the retry window stops instead of signing"`: `pending.iat = now - 3601` → it throws a message containing `renewal state lost`, and the fake fetch is never called.
  - `"legacy tier.json without a generation renews with v1"`: the proof verifies under `tierRenewalBinding(spki, iat)`, and the body has no `generation`.

- [ ] **Step 2: Run to verify they fail**

  Run: `cd worker && pnpm exec vitest run src/__tests__/task-cert-client.test.ts`
  Expected: FAIL, the signature mismatch.

- [ ] **Step 3: Implement the rules** in `lib.ts`, and wire `savePending` / `clearPending` / `generation` in `cli.ts`'s `renewNow`. Enroll writes `generation: 0` from the token response. `status` prints `generation N` and the clone policy (Task 5 field `clone_policy`, shown when present).

- [ ] **Step 4: Run to verify they pass**

  Run the same command, then the full plain suite: `pnpm exec vitest run`.

- [ ] **Step 5: Commit** as `[notme-747cc7] feat(task-cert): renew with a generation; resend the exact request after a lost response`.

---

### Task 5: Clone policy on the enrollment

**Files:**
- Modify: `worker/src/signing-authority.ts` (`approveTierEnrolment`, `listTierEnrolments`, a schema column)
- Modify: `worker/worker.ts`. The `/cert/issuing-ca/device/approve` route (~3020), `enrolPageHtml` (~1187: a select beside `#renew`), and the enrollments list route.
- Test: `worker/src/tier-generation.do.test.ts`, a new `describe("clone policy")`.

**Interfaces:**
- New column: `clone_policy TEXT NOT NULL DEFAULT 'singleton'`.
- `approveTierEnrolment` params gain `clonePolicy: "singleton" | "replicas:2" | "replicas:4" | "replicas:8"`.
- The approve body gains `clone_policy` (default `"singleton"`), and the approve response echoes it.
- `listTierEnrolments` rows gain `clone_policy` and `generation`.
- The token (collect) response gains `clone_policy`, so the client can show it.

- [ ] **Step 1: Write the failing tests**

  - `"a plain approval is singleton"`: list shows `clone_policy: "singleton"`.
  - `"replicas requires authorityManage"`: a human with `["bridgeCert","certMint"]` approving with `clone_policy: "replicas:4"` gets 403. A human who also holds `authorityManage` gets 200, and the list shows `"replicas:4"`.
  - `"replicas allows at most a 7-day horizon"`: `replicas:2` with `renew_days: 30` → 400; with 7 → 200.
  - `"anything else is refused"`: `"replicas:3"`, `"many"` and `""` each give 400.
  - `"the enroll page offers the policy, singleton selected"`: `GET /enroll?code=…` HTML contains `id="clone"` and `<option value="singleton" selected`.

- [ ] **Step 2: Run to verify they fail**

  Same command as Task 2. Expected: FAIL, the list has no `clone_policy`.

- [ ] **Step 3: Implement.** Validate in the route, and read `authorityManage` from `liveScopes`, not the cookie. Store the policy, and expose it in the list and the collect response. The page's select sends `clone_policy` alongside `renew_days`.

- [ ] **Step 4: Run to verify they pass**, plus `tier-renewal.do.test.ts` and `login-redirect`, since the enroll page changed.

- [ ] **Step 5: Mutation-check.** Read `authorityManage` from the cookie's scopes; drop the 30-day cap. Each must fail a test.

- [ ] **Step 6: Commit** as `[notme-747cc7] feat(enroll): clone policy — singleton by default, replicas as break glass`.

---

### Task 6: Documentation, gates and follow-up beads

**Files:**
- Modify: `README.md`
  - the pause-and-resume refusal table gains `fork_detected`: "a copy of this machine renewed; both are shut off" / "`enroll` again";
  - the revocation-levers table gains "fork detection: automatic, one machine, at the copy's next renewal".
- Modify: `worker/public/_api-docs.html`, the `/cert/issuing-ca/renew` body (`generation`), the response (`generation`), and the `fork_detected` reason.
- Modify: `docs/superpowers/specs/2026-10-28-mint-path-design.md`, status line → `approved 2026-10-28; phase 1 implemented`.

- [ ] **Step 1: Run every gate**

  - `task worker:check`, with workers-pool at `--testTimeout 30000` if load requires it;
  - `task docs:check`;
  - `task pin:check`.

  All exit 0.

- [ ] **Step 2: File beads** with `rsry_bead_create`, linked to `notme-907299`:
  - phase 2: criteria `.1.10` + three definitions + `task-cert verify` enforcement;
  - phase 3: `task-cert serve` over UDS;
  - phase 4: `deploy/1` push approval + the mount lever;
  - phase 5: LLO `llo-run/1`, criteria in a sigpol bundle, the ledger-vs-Interlace population check;
  - phase 6: hardware custody + receipts;
  - branches (§5.3);
  - cross-repo: signet `.1.10` enforcement, LLO `.1.7` writing and `.1.10` reading.

- [ ] **Step 3: Commit and push** as `[notme-747cc7] docs: fork detection in the README, API docs and spec status`, then run `git push origin goalzero`.
