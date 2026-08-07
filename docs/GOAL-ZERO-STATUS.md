# Goal Zero — status and orientation

**Epic:** `notme-bed754` · **Branch:** `goalzero` (87 commits ahead of `main`, PR #70)
**Production:** version `91b54069` at 100%, `task worker:verify` 13/13
**Tests:** 526 unit (38 files) + 120 real-DO (15 files) + 2 deliberate `it.fails`
**Last updated:** 2026-08-06

Read this before picking up Goal Zero work. It exists because several
conclusions in this repo were *reached, then corrected*, and a fresh reader who
finds only the artifacts will re-derive the wrong ones.

---

## 1. What Goal Zero means

From `notme-bed754`: the identity service can be released and operated with **no
unknown security-critical failures**. Five criteria:

| | Criterion | State |
|---|---|---|
| **A** | Every P0/P1 closed, linked, or deliberately deferred; runtime contracts exercised; artifacts have provenance; no schema/build drift; cross-repo smoke recorded | partial — see §5 |
| **B** | The authority states what it names; identity no longer varies with auth ceremony; registration policy follows from that | **ADR written (`proposed`), code half open** |
| **C** | A revocation unit exists between "wait out the TTL" and "revoke everything" | open, blocked on B |
| **D** | A third party can verify without trusting notme at the moment of the check | open, half done |
| **E** | First boot needs no secret from the logs and cannot be triggered by a stranger | open |

Plus a **documentation-honesty clause** applying to all of them: where a
property is deliberately not provided, docs must say so rather than implying
the stronger property. This clause has already done real work — see §3.

---

## 2. The branch model

`feature → goalzero` is the happy path: merge freely, no ceremony.
`goalzero → PR → main` is **one** release, and scrutiny happens once, at that
gate. PR #70 is the accumulating release PR. Do not open per-feature PRs to
`main`.

Consequence worth knowing: anything requiring a change on `main` — notably the
self-pin in `.github/workflows/gha-identity.yml:137`, which pins
`agentic-research/notme/action` at a commit SHA — **cannot land until that
merge**. That constraint forced the migration window in §4.

---

## 3. Corrections — read this section before trusting older text

Four conclusions in this repo were wrong and have been fixed. Each was
plausible, each survived review once, and the corrected version is now in the
artifact. If you find contradicting older text, the correction wins.

**3.1 Scope narrowing does NOT bound delegation depth.**
An earlier ADR-019 draft argued that monotone scope attenuation made depth
bound itself, so no tier needed formalising. False: `verifyScopeChain` accepts
equality by design, so the relation is reflexive, hence a preorder, hence never
well-founded. Even forbidding equality bounds a chain only at `|S|+1` — a limit
set by whoever last added a scope string. Depth needs its own rank function;
X.509 has one in `pathLenConstraint` (RFC 5280 §6.1.4(l)–(m) is a loop
variant). The macaroon/Biscuit citation *argued the opposite* of what it was
cited for: both permit unbounded attenuation precisely because authority cannot
grow, and both bound depth separately.
→ `docs/design/019-delegation-authority.md` D4, `worker/src/auth/scope-chain.ts` header.

**3.2 URI `nameConstraints` do NOT constrain paths.**
ADR-008 §299 proposed `permittedSubtrees: URI:wimse://notme.bot/agent/*` and
claimed conformant validators enforce it. RFC 5280 §4.2.1.10: *"For URIs, the
constraint applies to the host part of the name."* So `notme.bot` is satisfied
by `wimse://notme.bot/anything`. The namespace bound is **absent, not
unimplemented**. §299 now carries a CORRECTION block; three possible mechanisms
are an open question on ADR-019 D5.

**3.3 One prefix-closed identifier cannot serve both correlation and revocation.**
Serials name certificate *instances*, so renewal forks the correlation subtree;
revocation wants instance precision, correlation wants principal stability. The
CIDR analogy used to justify it was the counterexample, not the support. Also
`mintBridgeCertPair` issues *two* certs with two independent serials, so no
serial names "the bridge" — `OID_PEER_BINDING` does.
→ `worker/src/auth/correlation-key.ts`, `notme-9f84e6`.

**3.4 "Delegated authority" is not a principal.**
The agent is the principal; delegation is the relationship. A bridge does not
delegate *a human to a machine*; it delegates *authority from* a human or
organization *to* an agent. This is delegation, not impersonation — RFC 8693's
`sub`/`act` split models it already.
→ ADR-019 Decision.

**3.5 An agent saying "done" is submission, not completion.**
Five claims hide behind the word: delegation (may attempt), promise
(undertakes), submission (claims finished), verification (evidence meets the
predicate), acceptance (it is done). Only the last is a *declarative* and only
an authority can perform it, so acceptance cannot be self-signed. Acceptance
needs no new credential type — it is a grant scoped `accept:<taskHash>`, which
closes the "who authorised the verifier" recursion. Note the trap: **CI is
often not an independent verifier**, because it executes configuration from the
repository under test.
→ ADR-019 "Task completion is a grant", `notme-9f84e6`.

---

## 4. Deployed and settled

- **PoP signs the binding pre-image, not its digest** (`notme-a011d2`).
  WebCrypto ECDSA hashes internally, so passing a digest signed
  `SHA-256(SHA-256(x))` and no Go signer could ever match. Three inline copies
  now share `worker/src/auth/pop.ts`.
  **A migration window is live**: the verifier accepts the pre-fix digest
  encoding too and reports `binding: "digest"` when it does. Remove
  `ACCEPT_LEGACY_DIGEST_BINDING` once the action pin is bumped past `0d2312f`
  and nothing reports `"digest"`.
- **Unmatched paths 404 instead of throwing 1101** (`notme-cb0354`, closed).
- **Rate limiters bound in production** (`notme-191328`, closed) — CERT 10/60s,
  PASSKEY 5/60s, TOKEN 20/60s. They previously existed only in
  `wrangler.toml.example`, so every `if (env.X_LIMITER)` guard silently skipped.
- **Scope chain rule in production** (`auth/scope-chain.ts`) — it previously
  existed *only as a helper inside a test*, with six green tests covering
  nothing production ran.

---

## 5. What remains

### Structural (criteria B–E)

| Bead | What | Blocked on |
|---|---|---|
| `notme-600df1` | **The keystone.** ADR-019 is written and `proposed`. Adopting it = flipping Status | a decision, plus open question 1 (addition vs cut) — **signet has not been asked** |
| `notme-77438b` | Identity varies with auth ceremony (`worker.ts:2307`) — the code half of (B) | `600df1` open question 1 |
| `notme-2c4209` | Registration policy | `600df1` |
| `notme-77a024` | Revocation unit. **Pick a mechanism**: signed revocation epochs, CRL DP, OCSP, or trust-bundle refresh. Today it is TTL-only below an epoch | `600df1` |
| `notme-8e8836` | Trust root anchored out of band — half done; remainder is signing trust material with the release pipeline's Sigstore identity | — |
| `notme-907299` | Issuance transparency (Static CT API — **not** RFC 6962, whose logs shut down 2026-02-28) | `8e8836` |
| `notme-addef9` | Bootstrap: first boot tells the operator to read a code out of Worker logs, and any stranger's request triggers the mint | — (decidable now) |

### P0s outside the structural set

| Bead | State |
|---|---|
| `notme-a011d2`, `notme-718ac0` | **Done on notme's side; blocked on signet.** One rc.3 run closes both. Left open deliberately: "we deployed the fix" ≠ "the path works end to end", and notme cannot mint a GitHub OIDC token for its own endpoint |
| `notme-9f2f79` | ADR-018's canary gate cannot verify the version it claims to — failed twice, silently *toward* the status quo. Needs a call on whether targeting works on a Free-plan zone; if not, delete the phase rather than keep an unperformable ceremony |
| `notme-acc822` | Scope half landed. Namespace half is now known-absent (§3.2). Depth half needs the middle tier |
| `notme-28959a` | undici in `action/dist` — parked at owner's direction while signet coordinates |

### Cross-repo, awaiting others

- `cloister-c10ff2` — the optional ninth commitment key `delegation`. **Inert
  end-to-end until cloister acts**: notme will sign a nine-key commitment and
  no verifier is obliged to accept one. Also flags that RECEIPTS.md §2.2.1
  step 2 says the envelope must have "exactly the keys" while step 3 says only
  "with the keys named in §2.1" — so whether extra keys must be rejected is
  undefined, and two conformant verifiers can differ. That ambiguity matters
  whether or not the field is adopted.

---

## 6. Scope question the owner must settle for criterion (A)

(A) requires every P0/P1 "closed, linked, or deliberately deferred." There are
**~72 open beads**, most P1/P2, many unrelated to release integrity — the
ley-line substrate work, the CAS-release epic, workerd-as-rope research. Read
literally that is an enormous surface; read as *release blockers* it is the
§5 table. **That distinction is not written down anywhere**, and it is the
difference between Goal Zero being close and being far.

Also unaudited: `worker/THREAT_MODEL.md` and the ADRs have not been checked
against what actually ships. Given this cycle found four artifacts asserting
properties nothing verified, expect that audit to find more.

---

## 7. Recurring defect patterns

Recorded on `notme-bed754`; useful as a search heuristic, not just history.

**"An artifact asserting a property of its own provenance that nothing verified."**
Cert `authMethod`; always-empty workflow outputs; a committed bundle asserting a
build it wasn't from; an identity URI naming a workload after a human ceremony;
ADR-008 §299 asserting an RFC guarantee the RFC does not give.

**"A green test proving a real property of a path production never takes."**
The bootstrap test that called the one function the passkey flow never calls;
an output gate checking 3 of 4 directions; `verifyScopeChain` defined *inside*
the test file with six passing tests covering nothing shipped; canonical-CBOR
fixtures built by the encoder under test.

Two conventions follow from these and appear in the suite:

- **`it.fails` marks a gap, not a bug.** `delegation-depth.do.test.ts` asserts
  the middle tier is *still missing*, so it goes red the moment someone builds
  it — that is the signal to delete the `.fails`.
- **Some fixtures are deliberately foreign.** `pop-preimage.test.ts` and the
  hand-encoder in `receipt-commitment.test.ts` build inputs *without* the code
  under test, because a fixture built by the encoder it validates is a fixed
  point rather than a conformance check.

---

## 8. Operational notes that cost time to learn

- **`wrangler tail` returned nothing** for a failing request *and* a known-good
  200 in the same window. Production 500s had to be diagnosed by differential
  probing. Do not assume logs are available.
- **Version-override targeting is unreliable** (`notme-9f2f79`). Probing a new
  version returned the *old* version's behaviour, which read as "the fix
  doesn't work" and nearly suppressed a correct fix. Verify **after** promoting;
  rollback is `wrangler versions deploy <old-id>@100%`.
- **`action/dist/index.js` is tracked but shadowed by an ignore rule.** Use
  `git add -f` for that one path.
- **`cbor-x` encodes any number ≥ 2³² as float64**, and `timestamp_ms` always
  exceeds it — so encoder-built commitments are never canonical. Use
  `encodeCanonicalMap`, or the hand-encoder in the tests.
- Beads live in Dolt; `.beads/beads.jsonl` is an *export* and can lag. Cloister's
  export is stale by days — do not regenerate it blind, as that sweeps unrelated
  changes into a commit.
