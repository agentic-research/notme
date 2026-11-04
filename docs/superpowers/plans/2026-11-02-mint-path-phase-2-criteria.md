# Mint Path Phase 2: Criteria in the Certificate — Implementation Plan

**Status (2026-11-03):** executed. Phase 2 (criteria in the cert, `.1.10`, enforced at mint and in `task-cert verify`) merged; bead notme-bdc850 is closed. Kept as the historical plan.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A certificate says which unit of identity it is (`.1.10` criteria). A
tier carries the criteria its approver granted. A task certificate must name
one of them. The minter and `task-cert verify` both refuse a certificate that
doesn't satisfy its stated criteria.

**Architecture:**
- One module, `worker/src/criteria.ts`, owns three things:
  - the `.1.10` encoding;
  - the registry of the three definitions;
  - one pure check, `checkCriteria`.
- The worker stamps criteria into tiers at enrollment and renewal.
- `mintTaskCertPair` enforces the mint-side rules.
- The `task-cert` client imports the same module, so mint and verify cannot
  disagree.
- Legacy tiers, enrolled before this phase, carry no `.1.10`. They keep
  working until an operator-set cutoff.

**Tech Stack:** TypeScript on Cloudflare Workers (Durable Object
`SigningAuthority`), `@peculiar/x509`, vitest (`vitest-pool-workers` for
`*.do.test.ts`, plain vitest for `worker/src/__tests__`), the `task-cert` CLI
under `scripts/task-cert/` run with tsx.

**Spec:** `docs/superpowers/specs/2026-10-28-mint-path-design.md` — §4
(Criteria), §5.5, §6, §8 (legacy cutoff), §9. Bead notme-bdc850. This plan also
resolves notme-1a5465 (Task 5).

## Global Constraints

- **The OID.** `.1.10` is `${OID_PEN}.1.10`, in the `cert-authority.ts` sub-arc
  registry. It moves with the arc to the PEN (notme-229dc3).
- **The encoding.** The spec's per-certificate shape is
  `SEQUENCE { UTF8String name, INTEGER version }`.
  - *Ruling:* the extension value is `SEQUENCE OF` that shape, so a tier can
    carry several.
  - A task certificate carries exactly one element.
  - `name` has no version suffix: `agent-session/1` is name `agent-session`,
    version `1`.
- **Criticality.** The extension is **non-critical**, like every other notme
  extension. Enforcement lives in verifiers (§9). A critical flag would make
  every stock X.509 validator, signet's and LLO's included, reject every new
  certificate.
- **Task ⊆ tier.** A task's criteria must be one its tier carries. The client
  may choose among the granted criteria, but never add to them (§5.5).
- **Omitting `.1.10`.** This is acceptable only under a tier with no `.1.10`;
  the certificate is reported as `legacy`. Under a tier that carries criteria,
  a task without `.1.10` is refused (§5.5).
- **The legacy cutoff** is verifier configuration, never hardcoded (§8):
  `task-cert verify --legacy-cutoff <ISO date>`, or env
  `NOTME_LEGACY_CUTOFF`.
- **`.1.7` is not notme's** (the cert-authority.ts table says "DO NOT
  REUSE"). This phase writes nothing to `.1.7`.
- **Commits:** `[notme-bdc850] type(scope): …`, ending with the session's
  attribution lines.
- **Gates:** `task worker:check` and `task docs:check`. Run one vitest
  process at a time, and use `--testTimeout 30000` under load.

### The three definitions (exact values)

| name/version | `mintedBy` | max lifetime (notAfter − notBefore) | scope ceiling | requires | grantable at `/enroll` this phase |
|---|---|---|---|---|---|
| `agent-session/1` | `tier` | 300 s | `CERT_ELIGIBLE_SCOPES` | — | **yes** (the default) |
| `llo-run/1` | `tier` | 300 s | `["bridgeCert"]` | `.1.7` present (its exact encoding is agreed with LLO in phase 5) | no, until phase 5 |
| `deploy/1` | `authority` | 900 s | `["bridgeCert"]` | — | no; the authority mints it online (phase 4) |

Rulings behind the table:
- **Lifetimes.** 300 s is the spec's "tasks 5 min". 900 s is the spec's
  "minutes; no renewal" for deploy, and is my call.
- **`llo-run/1` is defined but can't be minted yet.** The minter refuses it
  until LLO agrees the `.1.7` binding (phase 5, notme-bdffc7), and `/enroll`
  doesn't offer it. Offering a criteria nothing can mint would be decoration.
- **`deploy/1` under a tier is always refused.** It is minted only by the
  authority, after a passkey approval.

## Review Focus

1. **A legacy tier renews after this ships.** An enrollment row with
   `criteria = NULL` must renew into a tier with no `.1.10`, and its tasks
   must verify as `legacy`. Adding criteria to a legacy row would make its
   in-flight tasks fail. Test in Task 2.
2. **A criteria-bearing enrollment renews.** The renewed tier must carry the
   same criteria. Dropping them would make every later task "legacy", which
   is a silent downgrade. Test in Task 2.
3. **A subtask of a criteria task.** The child must carry exactly its
   parent's criteria. A missing or different one is refused at mint. Test in
   Task 3.
4. **Malformed `.1.10`.** Zero elements, two elements on a task, version 2 of
   a known name, an unknown name, trailing bytes, or a wrong tag. Each must
   come back as `{ ok: false, reason }`, never a throw and never ok. Test in
   Task 1.
5. **An honest user upgrading the client.** `task-cert mint` without
   `--criteria`, under a tier with exactly one criteria, uses it. Under a tier
   with several it refuses and names them, rather than minting a task that
   verify will later refuse. Test in Task 4.

---

### Task 1: The criteria module

**Files:**
- Create: `worker/src/criteria.ts`
- Modify: `worker/src/cert-authority.ts`:
  - export `OID_CRITERIA = \`${OID_PEN}.1.10\``, next to `OID_TASK_SCOPE`;
  - add a `.1.10 criteria` row to the OID table comment (~line 105);
  - export the existing private DER helpers that criteria.ts needs
    (`derTlv`, `derUtf8String`) rather than duplicating them.
- Test: `worker/src/__tests__/criteria.test.ts`. Add it to
  `worker/tsconfig.scripts.json` like the other plain tests.

**Interfaces — Produces:**
```ts
export interface Criteria { name: string; version: number }
export interface CriteriaDefinition {
  id: string;                      // "agent-session/1"
  mintedBy: "tier" | "authority";
  maxLifetimeS: number;
  scopeCeiling: ReadonlySet<string>;
  requiresConfinementDigest: boolean;
  grantable: boolean;              // offered at /enroll this phase
}
export const CRITERIA: ReadonlyMap<string, CriteriaDefinition>;  // keyed "name/version"
export function criteriaId(c: Criteria): string;                 // "agent-session/1"
export function parseCriteriaId(id: string): Criteria | null;    // "agent-session/1" → {name, version}; null if malformed
export function encodeCriteria(list: Criteria[]): Uint8Array;    // DER SEQUENCE OF SEQUENCE{UTF8String, INTEGER}; throws on empty or duplicates
export function readCriteria(cert: { getExtension(oid: string): { value: ArrayBuffer } | null }):
  | { present: false }
  | { present: true; ok: true; list: Criteria[] }
  | { present: true; ok: false; reason: string };              // malformed never throws
export type CriteriaVerdict =
  | { ok: true; criteria: Criteria | null; legacy: boolean }
  | { ok: false; reason: string };
export function checkCriteria(
  tier: X509Like | null,           // null: the leaf was issued by the authority itself (deploy/1)
  leaf: X509Like,
  opts?: { at?: Date; legacyCutoff?: Date },
): CriteriaVerdict;
```
`X509Like` is the subset of `@peculiar/x509`'s `X509Certificate` used:
`getExtension(oid)`, `notBefore`, `notAfter`. The scopes are read with the
existing local scope reader (cert-authority.ts ~line 1008; export it if
needed). For `.1.7` only presence is checked; its encoding is phase 5's.

The `checkCriteria` rules, in this order, each with a distinct reason string:
1. Read `.1.10` on the tier and on the leaf.
2. If either is malformed: `malformed criteria on <tier|leaf>`.
3. If the leaf has more than one element: `a task carries exactly one criteria`.
4. Tier absent, leaf absent:
   - `{ok:true, criteria:null, legacy:true}`;
   - unless `legacyCutoff` is set and `at > legacyCutoff`, which gives
     `legacy certificate past the operator's cutoff`.
5. Tier absent, leaf present, tier not null: `task claims criteria its tier does not carry`.
6. Tier present, leaf absent: `tier carries criteria; the task names none`.
7. Leaf criteria unknown to `CRITERIA`: `unknown criteria <id>`.
8. `mintedBy === "tier"` but `tier === null`, or `mintedBy === "authority"` but
   `tier !== null`: `<id> is minted by the <tier|authority> only`.
9. Tier present and the leaf's id not in the tier's list:
   `task criteria <id> is not granted by its tier`.
10. `notAfter − notBefore > maxLifetimeS`: `<id> allows at most <n>s, this certificate spans <m>s`.
11. Any leaf scope outside `scopeCeiling`: `<id> does not allow scope <s>`.
12. `requiresConfinementDigest` and `.1.7` is absent:
    `<id> requires the run's confinementDigest (.1.7)`.

`checkCriteria` never reads the wall clock for lifetime; it uses the
certificate's own fields. It reads `at` (default `new Date()`) only for the
cutoff.

- [ ] **Step 1: Write the failing tests** in `criteria.test.ts`. Build
  certificates with `@peculiar/x509` directly (self-signed Ed25519 is fine,
  because this module checks no signatures), with these cases:
  - `encodeCriteria` → `readCriteria` round-trips one and three elements, and
    the DER starts with `0x30` and nests `0x30, 0x0c …, 0x02 …`;
  - `encodeCriteria([])` and duplicates throw;
  - every malformed shape in Review Focus 4 returns `ok:false` with
    `malformed criteria on leaf`, or for two elements on a task
    `a task carries exactly one criteria`; none of them throws;
  - rules 4–12 each get one test asserting `ok` and the exact reason;
  - rule 4 cutoff: legacy at 2027-01-01 with a cutoff of 2026-12-31 → refused,
    and with a cutoff of 2027-06-01 → ok;
  - rule 10 is exercised at exactly `maxLifetimeS`, which is ok, and at
    `maxLifetimeS + 1`, which is refused;
  - `deploy/1` with `tier=null` and a 3-hour span → refused by rule 10. This
    is the spec's "a deploy certificate that's two hours old is refused";
  - the registry has exactly three entries with the table's values;
  - `grantable` is true only for `agent-session/1`.
- [ ] **Step 2: Run them and see them fail.**
  `cd worker && pnpm exec vitest run src/__tests__/criteria.test.ts` →
  FAIL (module not found).
- [ ] **Step 3: Implement `worker/src/criteria.ts`** to the interface above.
  - Hand-rolled DER, like `certTaskScope` (cert-authority.ts ~800).
  - Long-form lengths are accepted.
  - INTEGER is positive and at most 4 bytes.
  - Reject trailing bytes at every level.
  - The module comment states the notme-1a5465 rule from Task 5 in two
    lines: `.1.9`'s goal hash is notme's "which work"; `.1.7`
    `confinementDigest` is LLO's "what the run may touch"; neither derives
    from the other.
- [ ] **Step 4: Run them again; they pass.** Also run `task docs:check`.
- [ ] **Step 5: Commit**:
  `[notme-bdc850] feat(criteria): the .1.10 extension, three definitions, and one check`.

### Task 2: Tiers carry their granted criteria

**Files:**
- Modify: `worker/src/cert-authority.ts`, in `mintIssuingCaCert` opts: add
  `criteria?: Criteria[]`. When present, add the extension
  `new Extension(OID_CRITERIA, false, encodeCriteria(criteria))`.
- Modify: `worker/src/signing-authority.ts`:
  - `tier_enrolments` gains `criteria TEXT`, nullable (NULL = legacy), using
    the same additive-migration pattern as `clone_policy` (~2374);
  - `approveTierEnrolment` takes `criteria: Criteria[]` and stores it as JSON;
  - `mintIssuingCa` takes `criteria?: Criteria[]`;
  - collect (~2619) and renew (~2813) pass `JSON.parse(row.criteria)` when it
    is non-null, and omit it otherwise;
  - collect and status responses include `criteria`, as an id list or null.
- Modify: `worker/worker.ts`:
  - the approve route (~3045) accepts `body.criteria`: an array of ids,
    defaulting to `["agent-session/1"]`;
  - each id must parse, exist, and be `grantable`, otherwise 400
    `criteria must be grantable criteria ids: agent-session/1`;
  - duplicates also give 400;
  - the response includes `criteria`;
  - the `/enroll` page (~1226) shows a "Criteria" line with a checkbox per
    grantable definition (only `agent-session/1`, checked) and sends the
    checked ids.
- Test: `worker/src/tier-enrolment.do.test.ts`, `worker/src/tier-renewal.do.test.ts`.

**Interfaces — Consumes:** Task 1's `Criteria`, `CRITERIA`, `parseCriteriaId`,
`encodeCriteria`, `readCriteria`, `OID_CRITERIA`.
**Produces:**
- the collect, renew and status JSON field `criteria: string[] | null`;
- `mintIssuingCa(params & { criteria?: Criteria[] })`.

- [ ] **Step 1: Write the failing tests:**
  - an approval with no `criteria` produces a tier with `.1.10 = [agent-session/1]`
    (read back with `readCriteria`);
  - `criteria: ["llo-run/1"]`, `["deploy/1"]`, `["nope/1"]`,
    `["agent-session/1","agent-session/1"]` and `[]` each give 400;
  - Review Focus 2: a renewed tier carries the same `.1.10`;
  - Review Focus 1: a row written with `criteria = NULL`, simulating a
    pre-phase-2 enrollment, collects and renews tiers with **no** `.1.10`,
    and the responses say `criteria: null`.
- [ ] **Step 2: Run and see them fail.** `cd worker && pnpm exec vitest run --config vitest.workers.config.mts src/tier-enrolment.do.test.ts src/tier-renewal.do.test.ts`.
- [ ] **Step 3: Implement** the changes listed under Files.
- [ ] **Step 4: Run again; they pass.** Then the full `task worker:check`.
- [ ] **Step 5: Commit**:
  `[notme-bdc850] feat(tier): the approver grants criteria; tiers carry them through renewal`.

### Task 3: The minter enforces task ⊆ tier

**Files:**
- Modify: `worker/src/cert-authority.ts` `mintTaskCertPair`:
  - opts gain `criteria?: Criteria`;
  - stamp `.1.10 = [criteria]` when given.
- Test: `worker/src/task-credential.do.test.ts`, `worker/src/__tests__/derived-task.test.ts`.

The mint-side rules, added to the producer-enforces comment block as a
`CRITERIA` line. They are checked before signing, and each throws an `Error`
whose message is the same reason string `checkCriteria` would give:
- the tier has `.1.10` and `opts.criteria` is absent → refused (rule 6);
- the tier has no `.1.10` and `opts.criteria` is present → refused (rule 5);
- the criteria is not in the tier's list → refused (rule 9);
- the definition is `mintedBy: "authority"` → refused (rule 8);
- `requiresConfinementDigest` → refused with
  `llo-run/1 needs the run's confinementDigest from the LLO host; supplied from phase 5 (notme-bdffc7)`;
- `ttlMs / 1000 > maxLifetimeS` → refused (rule 10);
- scopes outside the ceiling → refused (rule 11);
- **subtask (`opts.parent`):** the child's criteria must equal the parent's
  `.1.10` element. An absent parent `.1.10` requires an absent child `.1.10`.
  Otherwise: `a subtask carries its parent's criteria`.
- Last, as a self-check, run `checkCriteria(tier, minted)` on the result and
  throw if it fails. The producer never hands out a certificate its own
  verifier refuses.

- [ ] **Step 1: Write the failing tests**, one per rule above, plus:
  - an honest mint under an `agent-session/1` tier → `checkCriteria` gives
    `{ok:true, legacy:false}`;
  - a legacy tier with no criteria → `{ok:true, legacy:true}`;
  - Review Focus 3, in `derived-task.test.ts`: a subtask with matching
    criteria is ok; missing or different criteria are refused.
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run again; they pass.** Then `task worker:check`.
- [ ] **Step 5: Commit**:
  `[notme-bdc850] feat(task): the minter refuses criteria its tier did not grant`.

### Task 4: The client mints and verifies with criteria

**Files:**
- Modify: `scripts/task-cert/lib.ts`:
  - `mintTask` opts gain `criteria?: string` (an id);
  - when absent, it reads the tier's `.1.10`:
    - exactly one → use it;
    - none → legacy;
    - several → throw `tier grants several criteria (<ids>); choose one with --criteria`;
  - `verifyChain(rootPem, tierPem, leafPem, at?, opts?: { legacyCutoff?: Date })`
    calls `checkCriteria` after the signature and window checks, and returns
    its reason on failure;
  - the ok result becomes `{ ok: true; criteria: string | null; legacy: boolean }`;
  - `saveEnrolment` / renew persist `criteria` from the response into
    `tier.json`.
- Modify: `scripts/task-cert/cli.ts`:
  - `mint --criteria <id>`;
  - `verify --legacy-cutoff <ISO>`, with env `NOTME_LEGACY_CUTOFF` as the
    fallback, refusing an unparseable date with exit 2;
  - `verify` prints `OK: root → tier → task (criteria agent-session/1)` or
    `OK: … (legacy: issued under a pre-criteria tier)`;
  - `status` prints `criteria: …`;
  - update the header usage comment.
- Test: `worker/src/__tests__/task-cert-client.test.ts`.

**Interfaces — Consumes:** Task 1's `checkCriteria`, `readCriteria` and
`parseCriteriaId`; Task 2's `criteria` response field; Task 3's
`mintTaskCertPair` `criteria` option.

- [ ] **Step 1: Write the failing tests:**
  - Review Focus 5: single-criteria default, several-criteria refusal,
    legacy default;
  - `verifyChain` returns `criteria` and `legacy`;
  - a task re-signed by the tier with the `.1.10` extension stripped is
    refused by `verifyChain` with `tier carries criteria; the task names none`.
    This is the negative control that copying a pre-criteria minter cannot
    get past verify;
  - the legacy cutoff is applied from the option.
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run again; they pass.** Then `task worker:check`.
- [ ] **Step 5: Commit**:
  `[notme-bdc850] feat(task-cert): mint picks the tier's criteria; verify enforces them`.

### Task 5: Decisions, docs, and the falsifiable check

**Files:**
- Modify: `docs/superpowers/specs/2026-10-28-mint-path-design.md`:
  - Status: "phase 1 and 2 implemented".
  - §12 gains **decision 4, goal hash vs confinementDigest (notme-1a5465)**:
    - They are different facts.
    - `.1.9`'s goal hash stays notme's "which work".
    - `confinementDigest` is LLO's "what the run may touch". It appears only
      in `.1.7`, with LLO's registered meaning, and only under `llo-run/1`.
    - It is supplied by the LLO host that configures the run. The party
      vouching for it knows the deployment, and LLO itself checks equality,
      so LLO ADR-0036 O1's unknown-deployment case doesn't arise.
    - It is written only from phase 5, after LLO agrees and after the PEN
      (notme-229dc3), because the shared arc still collides at `.1.5`.
  - §5.5 records the `SEQUENCE OF` ruling and the non-critical ruling.
- Modify: `README.md`, in the agents, machines and tasks section: one
  paragraph on criteria, covering what a tier carries, `--criteria`,
  `--legacy-cutoff`, and that `llo-run/1` and `deploy/1` are defined but not
  mintable yet.
- Modify: the `cert-authority.ts` OID table, if Task 1 left it short.
- Bead actions (controller):
  - close notme-1a5465 with decision 4's text;
  - comment on notme-bdc850;
  - file a signet bead for "signet verify enforces `.1.10`" against the
    sigpol definition (§8, phase 5), if none exists.

- [ ] **Step 1: The mutation check.** Apply each mutation alone, run the
  suite, and confirm the named test fails, then revert it. Record the table in
  the task report.

| Mutation | Must fail |
|---|---|
| `checkCriteria` rule 6 returns ok | Task 4 stripped-extension negative control |
| rule 9 skipped | Task 3 "not granted by its tier" |
| rule 10 uses `>=` instead of `>` | Task 1 boundary at exactly `maxLifetimeS` |
| renew omits `criteria` | Task 2 Review Focus 2 |
| collect stamps `[agent-session/1]` on a NULL row | Task 2 Review Focus 1 |
| subtask equality check removed | Task 3 Review Focus 3 |

- [ ] **Step 2: Docs.** Make the edits above; `task docs:check` passes.
- [ ] **Step 3: Full gates.** `task worker:check` and `task docs:check` pass.
- [ ] **Step 4: Commit**:
  `[notme-bdc850] docs(mint-path): phase 2 criteria; goal hash and confinementDigest are different facts`.

## Not in this phase

- **Phase 3 (notme-bdd7f9):** `task-cert serve`.
- **Phase 4 (notme-bdeeb5):** issuing `deploy/1` and phone approval.
- **Phase 5 (notme-bdffc7):** making `llo-run/1` mintable and writing `.1.7`.
  Also enforcement in signet and LLO, and criteria in a sigpol bundle.
- **Phase 6 (notme-be13b0):** receipts.
- **Branches (notme-be1ecd).**
- **The legacy cutoff date itself.** It is the operator's, announced in
  release notes.
