# Goal Zero — the road to done

Companion to [`GOAL-ZERO-STATUS.md`](GOAL-ZERO-STATUS.md), which says where we
are. This says **what order to do things in, and who has to decide what.**

Written 2026-08-06. Production is `2f0b1598`, `worker:verify` 14/14, 101
commits ahead of `main` on `goalzero`.

---

## The shape of the problem

Goal Zero is not blocked on volume of work. It is blocked on **four decisions**,
three of which are not notme's alone, and each of which unblocks a cluster.
Everything else is either done, mechanical, or genuinely dependent.

The failure mode to avoid: building D4's middle tier before the naming decision
lands, because the tier's *name* determines what every consumer's verifier
expects to find in it.

---

## Phase 0 — Decisions (blocking, mostly not code)

| # | Decision | Owner | Unblocks | Cost of deciding wrong |
|---|---|---|---|---|
| **0.1** | **Adopt ADR-019?** Flip Status to `accepted` | repo owner | criteria (B), (C); registration policy | low — it is a proposal, reversible |
| **0.2** | **What is a "bridge cert"?** (`signet-9dfb44`, `signet-a4881c`) | **signet** + notme | D4 middle tier, and therefore (C) | **medium** — re-rated down; no protocol break, but a signed value + a schema TypeID |
| **0.3** | **Criterion (A) scope** — defer 7 named beads? (see below) | repo owner | closing (A) at all | **low** — the disputed set is 7 beads |
| ~~0.4~~ | ~~Fail open or closed with no bundle~~ — **RESOLVED for enforcement** by cloister ADR-0053 (fail closed, shipped). Still open for *archival/audit* only | cloister (done) / notme | (D), archival verification | — |

**0.4 came back while this was being written.** Cloister has decided and
shipped fail-closed for the *enforcement* path: no anchor → `CaUnavailableError`
→ JSON-RPC `-32005`, loudly, with a code naming the cause. That was never
notme's decision to make — it is cloister's boundary. What remains open is only
the *archival/audit* role, which cannot fail closed without making historical
verification impossible.

The cost cloister named and accepted: **notme's availability is now cloister's
availability.** That prices notme uptime as a hard dependency of a downstream
system, and it adds a prerequisite to `notme-41d0d3` — the CA-key envelope
cannot be enabled until its recovery path has been *exercised*, because an
unreachable KEK stops cloister rather than degrading it.

### 0.2 — RE-RATED, and the naming answer changed

Signet came back (`signet-a4881c`) with two things that change this item.

**The wire contract does not use the word.** `/cert/gha` returns
`{"certificates": {"mtls", "signing"}, "identity", "scopes"}` — already precise,
already the right words. So the rename is **not a protocol break**, and 0.2
should not be modelled as a risky change gating all of Phase 2. That re-rating
is correct and this document had it wrong.

**But "low — a day of documentation" understates it in two places**, both
verified here:

1. **`bridgeCert` is a SIGNED VALUE.** It is a scope, and scopes are DER-encoded
   into the cert at `OID_SCOPES` (`cert-authority.ts:325`). Certificates already
   issued carry it permanently and cannot be rewritten. Any verifier matching on
   it must accept both names during the overlap — the same dual-accept migration
   shape as `ACCEPT_LEGACY_DIGEST_BINDING`, which is now a known, cheap pattern
   here. It also appears in `@notme/contract` (`BRIDGE_CERT`), the generated TS
   and Go enums, and the public api-docs.
2. **`BridgeCertResult` is a Cap'n Proto struct** (`schema/identity.capnp:62`)
   with a stable derived TypeID (`0x8b5e0c952601cb1f`). Cap'n Proto derives
   TypeIDs from the qualified name, so renaming the struct **changes the
   TypeID** — a schema break for any typed consumer. Mitigating: `gen/go` has no
   in-repo consumers and its disposition is already an open question
   (`notme-ea5c65`), and `@notme/contract` is `private: true`, so the blast
   radius is smaller than it looks. It is not zero.

So: **medium, not high, and not low.** No protocol break; a signed-value
migration plus a schema decision. It should not gate Phase 2.

**The naming answer also changed, and signet corrected its own earlier term.**
"Bridge CA" is *already taken* — the Federal Bridge CA is the canonical example,
and it means cross-certification between otherwise-unrelated PKIs: a peer trust
broker, not a subordinate within one hierarchy. Anyone with a PKI background
reads "bridge" as the federation concept, which is a thing notme is *not* doing
here. That collision is worse than the internal one, because it misleads
outward.

For an artifact that is `IsCA: true, MaxPathLen: 0` the standard term is
**Issuing CA** — precise, and it states in the name both that it may issue and
that nothing further may follow it. `Subordinate CA` (CA/Browser Forum) and
`Intermediate CA` are the more familiar alternatives. `delegated` — this
document's earlier suggestion, taken from signet's own ADR-004 EKU — is **not**
standard PKI; the actual X.509 delegation construct is the RFC 3820 proxy
certificate, which carries grid-computing baggage and thin library support.

**Recommended: `Issuing CA` for the CA-shaped artifact, `enrollment certificate
pair` (members: `mTLS certificate`, `signing certificate`) for what `/cert/gha`
returns.** One consequence to hand back to signet: adopting this makes their own
EKU name `id-kp-signet-bridge-delegate` a misnomer. The OID is opaque so nothing
breaks, but the documentation name should move with it.

### 0.3 in detail — the disputed set is 7 beads, not 70

An earlier draft of this document called (A) "weeks or months" and implied the
scope question was large. **Counted, it is not.** As of 2026-08-06:

```
82 open        P0: 5   P1: 35   P2: 34   P3: 8
```

Criterion (A) says **P0/P1** — so P2 and P3 (42 beads) are out of scope by the
criterion's own wording, and never were the question. That leaves **40**, of
which **31 touch the release surface** (worker/, .github/, action/, schema/,
Taskfile, or are bugs) and are unambiguously in.

The remaining **9** are the entire dispute, and two are self-referential:

| Bead | Why it is disputed |
|---|---|
| `notme-bed754` | the Goal Zero epic itself — closes when G0 closes, definitionally |
| `notme-cf288e` | the promotion plan — same |
| `notme-3e22e0` | Phase 0: deploy + validate consolidated state |
| `notme-3dac49` | Phase B.1: lift `notme.bot` → `notme/auth/` + CF API 10375 |
| `notme-e7e1cf` | CAS-release ADR: action-release manifest + predicate type |
| `notme-32c72f` | cross-repo: cloister state re-survey before substrate composition |
| `notme-e005a8` | supersede workerd-as-rope → ley-line substrate |
| `notme-ce0903` | explore workerd-as-rope — content-addressed isolate composition |
| `notme-d82673` | decade: identity-aware network gateway |

So the real question is narrow: **do the four substrate-research beads
(`32c72f`, `e005a8`, `ce0903`, `d82673`), the two infra-migration beads
(`3e22e0`, `3dac49`), and the CAS-release ADR (`e7e1cf`) block a release?**

**Recommendation: defer all seven — but EXTRACT one question from `e7e1cf`
first.** Criterion (A) permits "deliberately deferred", and that is what these
are. Research beads have no release-blocking property by construction; the
`notme/auth/` migration is a separate initiative. What (A) forbids is
*silence* — a bead sitting open with nobody having decided.

**`notme-e7e1cf` is not cleanly deferrable, and checking it is what caught
this.** It proposes a predicate type URI `https://notme.bot/action-release/v1`,
describes it as *"mirrors the existing APAS predicate"*, builds an in-toto
Statement v1 with canonical CBOR for the DSSE PAE, and carries an unresolved
question in its own body:

> *"Where does the predicate type registry actually live? notme/docs?
> signet/docs/apas? A new repo?"*

That question is **shared**, not local. The acceptance-predicate work
(`notme-8eb592`) will hit it independently, and two predicate types designed
without a registry convention will collide or diverge. It is also a
**compose-do-not-invent** question in ADR-020's sense: a predicate type minted
under `notme.bot` puts vocabulary in notme's namespace when APAS — signet's
document — is where predicate types already live.

So: defer the CAS-release *implementation*, and lift the registry question out
to ADR-020 as an open question, where the acceptance work will see it.

**One softer note.** `notme-d82673` (identity-aware network gateway) is a
*consumer* of the delegation model rather than a definer of it, so deferring it
is safe — but if 0.2 changes the bridge naming, its assumptions move with it.
Worth re-reading it after 0.2 lands rather than treating the deferral as final.

That leaves criterion (A) as **31 release-surface P0/P1 beads**, most of them
narrow bugs, several of which this cycle has already fixed without closing.

---

## Phase 1 — Unblocked now, no decision required

Do these while Phase 0 is out for decision. None touch the contested naming.

| Work | Bead | Why now |
|---|---|---|
| ~~`worker:verify` convergence gate~~ **DONE** | `notme-9f2f79` | `task worker:await-convergence` now sits between deploy and verify in `ship-prod`; N consecutive samples, fails rather than warns |
| Delete ADR-018's canary phase, rewrite as promote → converge → verify → rollback | `notme-9f2f79` | Targeting proven not to work; keeping the ceremony is worse than removing it |
| Trust material signed by the release pipeline's Sigstore identity | `notme-8e8836` | Second half of (D)'s foundation; independent of naming |
| OIDC attestation as the *documented* default first boot | `notme-addef9` | Code half shipped; this is docs + the fallback story |
| Represented principal on `/cert/gha` | `notme-600df1` | The m2m path records *what ran*, never *whose authority*. Additive, no rename involved |
| Renovate or Dependabot | *(needs filing)* | Nothing proposes upgrades; the undici lag was weeks |

---

## Phase 2 — Gated on Phase 0

| Work | Gated on | Notes |
|---|---|---|
| **D4 middle tier** (`CA=true, pathlen=0`) | 0.2 | Deleting `it.fails` in `delegation-depth.do.test.ts` is the completion signal |
| `nameConstraints` — or its replacement | 0.2 | URI constraints bind the **host**, not the path (ADR-008 §299 corrected). Needs distinct hosts, an `otherName`, or a critical extension |
| Revocation unit | 0.1, 0.2 | A grant is the unit; the *mechanism* still needs choosing |
| Task credential producer | 0.2 | Gives the correlation key its third segment and the receipt field a value |
| DSSE ↔ X.509 binding | 0.2 | Blocks every acceptance/attestation path (`notme-8eb592`) |

---

## Phase 3 — Cross-repo, already asked

| Ask | Repo | Status |
|---|---|---|
| `signet-9dfb44` — bridge naming, one-intermediate rule, stale ADR-004 note | signet | **filed, blocking 0.2** |
| `cloister-c10ff2` — optional ninth commitment key, and §2.2.1 step-3 ambiguity | cloister | filed; the field is inert until they act |
| rc.3 confirmation | signet | unblocked — `/.well-known/version` now proves what is deployed |

The step-3 ambiguity in `cloister-c10ff2` matters **whether or not** the field
is adopted: notme implements the strict reading, and if cloister's verifier is
permissive the two have been diverging silently.

---

## Phase 4 — Documentation honesty (criterion A's other half)

Never done, and this cycle found **five** artifacts asserting properties
nothing verified. Expect more. Prompt and scope are in `GOAL-ZERO-STATUS.md`;
it is parallelisable and conflicts with nothing above.

---

## What "done" looks like

Goal Zero closes when:

1. Every criterion (B)–(E) has either shipped code or a recorded, deliberate
   deferral **with its reason** — not silence.
2. `worker:verify` gates on convergence, so a green verify means the build you
   deployed is the build that answered.
3. The bridge naming is settled and D4 is built or explicitly deferred.
4. Criterion (A)'s scope is defined, and every bead inside it is closed,
   linked, or deferred.
5. Docs claim no property the deployment does not deliver.
6. `goalzero` → `main` merges as one release, and the action self-pins advance
   in the same cut.

**The honest read:** items 1–3 are weeks of work, mostly gated on decisions
rather than effort. Item 4 is **smaller than it looks** — 31 release-surface
P0/P1 beads once the seven named above are deferred, several already fixed
this cycle without being closed. Item 5 is the genuinely unbounded one: the
documentation-honesty audit has never run, and this cycle found five artifacts
asserting properties nothing verified. That is the item most likely to move
the finish line.

---

## Sequencing rule

If only one thing happens next, make it **0.2** — chase signet on the naming.
It is the only blocker that another repo owns, it has the highest cost of
being wrong, and it gates the largest cluster of downstream work.

If two things happen, add the **`worker:verify` convergence gate**: it is small,
unblocked, and until it lands every deploy's green light is partly luck.
