# Remaining work, in order

**Updated:** 2026-11-02 · **Open beads:** 76 in notme (`rsry status --json` →
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

- **notme-bdc850**, mint path phase 2 (criteria in the certificate). Plan:
  `docs/superpowers/plans/2026-11-02-mint-path-phase-2-criteria.md`. Tasks 1–2
  are committed (Task 2 under review); Tasks 3–5 follow.
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
7. **The stage 2 gate:** the release tag waits on the six live-path security
   fixes and the release-pipeline fixes (stage 2 groups H1 and H2).
8. **notme-cf288e → tag → notme-8e8836:** promote staging → canary →
   production (`task ship-prod`, **owner**), then cut the tag. The signed
   trust anchor (8e8836) closes when the release job signs it from that tag.
9. **notme-bed754** closes when 1–8 are closed.

Waiting on someone else: **notme-bc4cd2** (adopt LLO v0.21.0) waits for LLO
to publish the tag.

## Stage 2: hardening

**H1, live-path security.** This gates the release tag.
- notme-3dfe15: `/join` — no server-issued OIDC nonce; the invite token is in
  the URL; the invite is consumed before the passkey verifies. Parts 4/5
  (reserve, then consume on verify) and 2 (token in the fragment) are fixed
  on `fix/h1-invites-join`; part 1 (the nonce) is open — GitHub Actions
  tokens take no nonce, so binding one is an audience-contract decision.
- notme-2131e8: invites survive a passkey reset and have no TTL ceiling.
  Fixed on `fix/h1-invites-join` (reset revokes; 7-day ceiling).
- notme-159805: `authorityHostFromEnv` returns `""` for a hostless URL.
- notme-ad2a7a: an unbounded `timestamp_ms` lets a binding holder backdate.
- notme-c9fc8c: renewal binding v2 doesn't commit to the enrollment, and
  there's a binding-version oracle.
- notme-1629fe: the canonical fixture gate has no integrity anchor.
- notme-bad2e5 (P1): IPv6 hosts bypass the `proxy()` metadata denylist.
  `[fd00:ec2::254]` and `[::ffff:a9fe:a9fe]` both get through.

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
- notme-7aa6dd, notme-7ec6fb, notme-c0db9b, notme-32003c, notme-32270b,
  notme-c071be, notme-3ee3b0, notme-230b40, notme-131c8e.
- CT: notme-a806d0 (warn before the shard closes); notme-afa9d8 (per-cert
  shard by notAfter), which must land **before 2027-06**.

## Stage 3: task-based certificates

What exists:
- renewable tiers and 5-minute task certs;
- subtasks and pause/resume;
- copies detected at renewal (phase 1).

The rest, in order:
1. **notme-bdc850:** phase 2, criteria in the cert, enforced at mint and in
   `task-cert verify`. It closes **notme-1a5465**: the goal hash and
   confinementDigest are different facts.
2. **notme-bdd7f9:** phase 3, `task-cert serve`, so workloads stop holding
   tier keys.
3. **notme-bdffc7:** phase 5. Make `llo-run/1` mintable, write `.1.7`, and
   have signet and LLO refuse on criteria. Needs LLO's agreement and the PEN
   (stage 1 step 6), plus beads in signet and LLO.
4. **notme-bdeeb5:** phase 4, `deploy/1` approved from your phone, and the
   mount lever.
5. **notme-be1ecd:** branches, counted clones under `replicas:N`.
6. **notme-be13b0:** phase 6, the path key in hardware, plus receipts.
7. **notme-bd2a72:** reshape `mintBridgeCertPair` into `/identity/lease`.
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
- **Filed from the doc-drift batch (2026-11-02):**
  - notme-bad2e5 and notme-baea8c (proxy gaps);
  - a gen/go scope-check note, added to notme-ea5c65 rather than filed as a
    new bead;
  - notme-8fb37f, kept open (weak tests).
- **Expected:** one signet bead, for `signet verify` enforcing `.1.10`
  (phase 2 Task 5).

Each is added here as it's filed.
