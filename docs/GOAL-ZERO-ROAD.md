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
| **0.2** | **What is a "bridge cert"?** (`signet-9dfb44`) | **signet** + notme | D4 middle tier, and therefore (C) | **high** — a rename after shipping breaks consumers |
| **0.3** | **Criterion (A) scope**: release blockers, or all ~70 open beads? | repo owner | closing (A) at all | medium — decides if G0 is weeks or months |
| **0.4** | **Fail open or closed** when no revocation bundle is reachable? | notme + cloister | (D), archival verification | medium — changes what a verifier may claim |

**0.2 is the long pole** and it is waiting on another repo. File it, chase it,
and do not start D4 until it answers. Recommended position: notme renames
(`bridge` → `delegate` for the intermediate, `task` → `bridge` for the leaf),
because signet ADR-004 and APAS already agree with each other and signet has an
EKU assigned.

---

## Phase 1 — Unblocked now, no decision required

Do these while Phase 0 is out for decision. None touch the contested naming.

| Work | Bead | Why now |
|---|---|---|
| **`worker:verify` convergence gate** | `notme-9f2f79` | **Weakest link in every deploy today.** Verify retries ~10s; convergence takes ~60s, so a verify immediately after promotion can pass against the OLD build |
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
rather than effort. Item 4 could be days or months depending on 0.3. Item 5 is
unbounded until the audit runs.

---

## Sequencing rule

If only one thing happens next, make it **0.2** — chase signet on the naming.
It is the only blocker that another repo owns, it has the highest cost of
being wrong, and it gates the largest cluster of downstream work.

If two things happen, add the **`worker:verify` convergence gate**: it is small,
unblocked, and until it lands every deploy's green light is partly luck.
