# Remaining work, in order

**Updated:** 2026-11-02 · **Open beads:** 72 in notme (`rsry status --json` →
`repos.notme.open`) · **Tracked as:** rsry decade `notme-zero`, one thread per
stage. Where an order is a real gate, it is also a bead dependency (`A`
depends on `B`).

The goal is zero open beads, or as close to it as the world allows. Any bead
that can't be finished stays **open**, with the reason written on it, and is
listed under [What may not close](#what-may-not-close). It is never closed
to make the count look better.

## How "done" is proven

Each stage proves its beads the same way. That is what makes the whole thing
feel finished rather than merely argued.

| Stage | A bead closes when |
|---|---|
| 1. Release | The thing is observed in **production from outside**: a live endpoint, a published artifact, a verifier run. The command and its output go on the bead. An owner action counts when its result is observable, not when it is said to be done. |
| 2. Hardening | A test that **reproduces the defect fails first** (red), the fix makes it pass, and one mutation of the fix makes it fail again. `task worker:check` is green. A docs-only fix cites file:line, and `task docs:check` is green. |
| 3. Task-based | The phase's step of the mint-path proof (spec §7) is an automated test with a **negative control**. Removing the mechanism makes it fail. Cross-repo enforcement closes only when the other repo's verifier refuses. |
| 4. After release | The same standard as stages 2–3, once a bead is picked up. Until then these beads aren't promised. |

## Stage 0: in flight now

- **Done:**
  - invites and `/join` (H1), merged from `fix/h1-invites-join` after two
    security reviews. notme-2131e8 closed; notme-3dfe15 stays open for part 1
    only (the OIDC nonce, which is the owner's decision);
  - phase 2, notme-bdc850 (see stage 3);
  - the P1 proxy IPv6 fix, notme-bad2e5 (daa3ab2);
  - notme-159805 and notme-ad2a7a: the code was already fixed; the missing
    tests were added (c40a134, a37e4b2).
- **The doc-drift batch** merged 2026-11-02 (0b584d5). Ten beads closed with
  their commits. Two stay open, each with what remains:
  - notme-8fb37f: the alarm tests are weak;
  - notme-8639dd: one stat tile still has no source.
  Security promises the code didn't keep became notme-bad2e5 and
  notme-baea8c.

## Stage 1: the release (Goal Zero, notme-bed754)

In order. Items marked **owner** need the operator, and an agent can't do
them.

1. **notme-c0c9a2:** if the log pin is misconfigured, write the cert to the
   CT backlog so it drains once the pin is fixed. Must land before step 2.
2. **notme-1b46a8 / notme-907299:** provision the CT log from upstream azul
   `d9402ec` (owner), fill the pin, bind `CT_LOG`, deploy. Closes when a
   production mint's SCT verifies against the live log.
3. **notme-41d0d3:** KEK-wrap the CA key. Rehearse on staging, then
   production with `scripts/kek-rehearsal.sh` (**owner**).
4. **notme-729801:** `task verify-release TAG=v0.3.1` in signet with
   cosign ≥ 3.1.3 (**owner**).
5. **notme-77ead7:** set dpop's npm package to disallow tokens (**owner**).
6. **notme-229dc3:** apply for the IANA PEN (**owner**, then days to weeks at
   IANA), then swap `1.3.6.1.4.1.99999` for the assigned arc. This also
   removes the shared-arc collisions.
7. **The stage 2 gate:** the release tag waits on the remaining live-path
   security fixes and the release-pipeline fixes (stage 2 groups H1 and H2).
8. **notme-cf288e → tag → notme-8e8836:** promote staging → canary →
   production (`task ship-prod`, **owner**), then cut the tag. The signed
   trust anchor (8e8836) closes when the release job signs it from that tag.
   **Deploy note (phase 2):** upgrade every `task-cert` checkout to 2a5dd9b
   or later before approving new machines. An older checkout mints tasks with
   no `.1.10` under a new enrollment; its own old `verify` accepts them, the
   new `task-cert verify` (and later signet and LLO) refuses them with `tier
   carries criteria; the task names none`. Nothing breaks at deploy; recovery
   is `git pull` (mint reads `tier.pem` by default, no re-enrolment).
9. **notme-bed754** closes when 1–8 are closed.

Waiting on someone else: **notme-bc4cd2** (adopt LLO v0.21.0) waits for LLO
to publish the tag.

## Stage 2: hardening

**H1, live-path security.** This gates the release tag.
- notme-3dfe15, **part 1 only:** `/join` has no server-issued OIDC nonce.
  GitHub Actions tokens take no nonce, so this needs the owner's choice:
  (A) single-use jti on `/join`, or (B) change the shared audience setting.
  Parts 2 and 4/5 are merged.
- notme-a2e75d: the first-user and claim marks are bound to the userId only,
  not to the browser like invite reservations are.
- notme-c9fc8c: renewal binding v2 doesn't commit to the enrollment, and
  there's a binding-version oracle.
- notme-1629fe: the canonical fixture gate has no integrity anchor.

**H2, a trustworthy release pipeline and gates.** This gates the release tag.
- notme-16b2d5: `worker:promote` has no gate.
- notme-325916: the canary soak samples traffic instead of targeting the new
  version.
- notme-6ae724: no runtime contract tests in CI.
- notme-070a8f: an alarm-health flake cascades across 8 files and can hide
  real failures.
- notme-3fc74b: plain-suite tests reach the live `auth.notme.bot`.
- The alarm epic **notme-5c2511**, with notme-e992ad and notme-5d358a.

**H3, correctness and hygiene.** Doesn't gate the tag.
- notme-baea8c: `proxy()` lacks ADR-009's promised gates.
- notme-8fb37f: the alarm-defence tests are weak.
- notme-2098f4: `readScopes` doesn't check lengths.
- notme-7aa6dd, notme-7ec6fb, notme-c0db9b, notme-32003c, notme-32270b,
  notme-c071be, notme-3ee3b0, notme-230b40, notme-131c8e.
- CT: notme-a806d0 (warn before the shard closes); notme-afa9d8 (per-cert
  shard by notAfter), which must land **before 2027-06**.

## Stage 3: task-based certificates

What exists:
- renewable tiers and 5-minute task certs;
- subtasks and pause/resume;
- copies detected at renewal (phase 1);
- **landed: phase 2 (notme-bdc850)**, criteria in the cert (`.1.10`),
  enforced at mint and in `task-cert verify`. Commits b06b8ea, b0e9fd8,
  ad1ada8, 2a5dd9b and d9f863e, plus the review-fix commit 6db9196.
  It settles
  **notme-1a5465**: the goal hash and confinementDigest are different facts
  (spec §12, decision 4).

The rest, in order:
1. **notme-bdd7f9:** phase 3, `task-cert serve`, so workloads stop holding
   tier keys.
2. **notme-bdffc7:** phase 5. Make `llo-run/1` mintable, write `.1.7`, and
   have signet and LLO refuse on criteria. Needs LLO's agreement and the PEN
   (stage 1 step 6), plus beads in signet and LLO.
3. **notme-bdeeb5:** phase 4, `deploy/1` approved from your phone, and the
   mount lever.
4. **notme-be1ecd:** branches, counted clones under `replicas:N`.
5. **notme-be13b0:** phase 6, the path key in hardware, plus receipts.
6. **notme-bd2a72:** reshape `mintBridgeCertPair` into `/identity/lease`.
   This is decided after phase 3, which may make it unnecessary.

The order puts phase 5 before phase 4 on purpose. Until a verifier outside
notme refuses, the criteria protect nobody downstream.

## Stage 4: after the release

Epic **notme-a93d47** holds about 27 beads that are real notme features or
research but not release work: the CAS-attested action release, OAuth/OIDC
provider work, WIMSE WIT+WPT, CIMD, federation, the gateway and substrate
threads, the workerd mTLS binding, cloister-facing exports, Socket scanning,
and browser `verify_head`. They aren't promised. Each gets its close
condition written when it's picked up.

## What may not close

These stay open, honestly, until the reason goes away:

| Bead | Why it may not close |
|---|---|
| notme-229dc3 | IANA's timeline, not ours. |
| notme-bc4cd2, notme-396aff, notme-0f38fe | Wait on LLO publishing a tag and wasm artifacts. |
| notme-bdffc7 | Needs another project to agree a field (`.1.7`) and two other repos' verifiers to enforce. notme can only do its half. |
| notme-be13b0 | Hardware custody depends on each host having a Secure Enclave or TPM. Hosts without one stay at "detected", not "refused". |
| notme-1e067f | entire.io would have to list notme as a trusted issuer. That's outside our control. |
| notme-89eeed | An upstream workerd change (C++ in Cloudflare's runtime). We can propose it, not merge it. |
| notme-3314fb, notme-e005a8, notme-d82673 | Wait on the substrate design in another repo. |

## Follow-up work this effort created

Listed so the count doesn't creep up unnoticed:
- **Filed during the CT work (2026-10-29):** notme-c0c9a2, notme-a806d0,
  notme-afa9d8, notme-7aa6dd, notme-7ec6fb.
- **Filed during triage (2026-11-02):** notme-a93d47, a holding epic that is
  not new work. Moved to cloister: notme-32c72f → cloister-c9ab9d, and
  notme-9da488 → cloister-c9cf2d.
- **Rescoped rather than closed:** notme-3dfe15, notme-e005a8, notme-3ee3b0.
- **Closed in triage:** notme-3e6ecc, notme-5464ee, notme-ce0903,
  notme-ea76bb, notme-9087aa, and ten doc-drift beads: notme-3ef3af,
  notme-8e6863, notme-a040c1, notme-be5691, notme-c006aa, notme-c07956,
  notme-c72e03, notme-c16e0d, notme-c7819f, notme-ae3130.
- **Closed by work (2026-11-02):** notme-bad2e5, notme-159805, notme-ad2a7a,
  notme-bdc850, notme-1a5465.
- **Filed from the doc-drift batch (2026-11-02):**
  - notme-bad2e5 and notme-baea8c (proxy gaps);
  - a gen/go scope-check note, added to notme-ea5c65 rather than filed as a
    new bead;
  - notme-8fb37f, kept open (weak tests).
- **From the phase 2 final review (2026-11-02):** one new bead,
  notme-2098f4. The other deferred items became comments on beads that
  already own the area: notme-bdffc7, notme-bdeeb5, notme-070a8f,
  notme-229dc3.
- **From the invite/`/join` security reviews (2026-11-02):** one new bead,
  notme-a2e75d (first-user and claim marks not bound to the browser).
- **Not filed:** the signet enforcement bead already existed
  (signet-be49b9). It now has the final encoding and a testable close
  condition, and notme-bdffc7 depends on it.

Each is added here as it's filed.
