# The mint path — offline task certificates that copying cannot forge

**Status:** design, awaiting approval (2026-10-28)
**Builds on:** ADR-019 (delegation authority), notme-337d82 (renewable tiers),
notme-9f84e6 (derived tasks), notme-1b46a8 / notme-907299 (transparency),
rosary-056d96 (per-dispatch identity)

## 1. Why

A bearer credential makes three things one: having it, being someone, and
being allowed. Steal it and you get all three. notme exists to pull them
apart. **Identity is proof of origin** (a chain back to the root, usable only
with its private key). **Authorization is a policy decision** (live grants,
scopes, criteria), made where the credential is minted and where it is used.

Renewable tiers and derived tasks (2026-10-28) let a machine mint task
certificates offline, which is what a VM that pauses and resumes needs. They
also leave one gap. Anyone holding a copy of the tier key can mint perfectly
valid task certificates, and nothing distinguishes them from the real
machine's. Copies happen routinely, not just through theft. A microVM
snapshot restores the same memory, and an image with a key baked in hands it
to every run.

This design closes that gap with one principle:

> **The minting path is the identity.** A certificate is acknowledged
> because it came through the one sanctioned path, and it carries proof of
> that. A valid signature made anywhere else is not acknowledged.

Two corollaries, both already true of the chain and extended here:

- **Origin can be chased.** Every certificate names its parent, back to the
  root.
- **Ending bubbles down.** A child never outlives its parent. Expiry
  cascades by construction. Revocation cascades as fast as verifiers check
  the path's standing, which offline is bounded by lifetimes (5 min task,
  1 h tier).

## 2. Goals, non-goals, anti-goals

**Goals**
- A copied tier key (stolen, snapshotted, or baked into an image) is
  detected at the next check-in and refused. The fork is evidence, not a
  glitch.
- Offline minting keeps working: pause and resume, no network at mint time.
- Deliberate cloning (replicas) is supported, counted, and visible.
- Criteria define what a unit of identity is. Three ship built in.
- Revoking an enrollment ends every branch and every certificate beneath it.
- It fits what exists (§8). No existing consumer breaks.

**Non-goals (v1)**
- Defending a host whose machine is taken over. Whoever controls the host
  controls its path. This design catches copies, not takeover (§9).
- Secure Enclave / TPM key custody. Phase 6, later (§10).
- User-defined criteria. The format allows them, but v1 ships three.
- Replacing the GitHub Actions exchange. It stays as is.

**Anti-goals: if any of these happen, it failed even if it works**
- Anything bearer. No credential whose possession alone confers authority.
- Criteria that nothing enforces. A field on the wire that no verifier
  refuses on is decoration (LLO's ADR-0035 found exactly this with
  `confinementDigest`).
- Honest machines shut off by a flaky network. A lost renewal response must
  not look like a clone (§5.1).
- A new standing secret. The path holds a key it generated, never a shared
  secret.

## 3. Prior art and why not SPIRE

SPIRE's agent serves short-lived identities to local workloads over a Unix
socket. It attests the caller and maps what it attests (selectors) to an
identity (registration entries). This design **borrows those patterns**:
attestors, selectors, and registration-entry-shaped criteria.

It **does not run SPIRE**. signet's prior-art decision (jamestexas/agents
`docs/prior-art/spiffe.md`) skipped SPIRE's server-plus-agent topology for
deployment-shape reasons (edge workers, laptops, CI). Hosts running many
microVMs are the consumer that decision deferred to. They are now real, and
this section records why SPIRE still doesn't fit:

1. **JWT-SVIDs are bearer.** Running through SPIRE re-introduces exactly
   what notme removes. notme's HTTP credential is DPoP-bound.
2. **SPIRE issues one key per identity; notme issues a bound pair.** A notme
   bridge credential is a P-256 mTLS certificate plus an Ed25519 signing
   certificate, bound by `.1.6` (peer binding). That pair is how one identity
   moves between mTLS, signing and a DPoP token. SPIRE has no paired-cert
   concept.
3. **Operational weight.** Two daemons and a datastore per host is
   disproportionate for a laptop running one agent session.

Also borrowed: OAuth refresh-token rotation with reuse detection (§5.1), and
Static CT for the receipt format (§5.4).

## 3a. Where this sits: signet, sigid, sigpol, Interlace

signet's ADR-011 names three concerns:

| | Question | Role here |
|---|---|---|
| signet | "prove you hold this key" | verifiers: proof of possession, chain, revocation |
| sigid | "who are you?" | minting: "mint a cert **if** policy allows", plus the verified context a verifier extracts |
| sigpol | "what are you allowed to do?" | the criteria |

The mint path is sigid-side minting and does not add a fourth concern. Three
existing designs carry most of the weight:

- **Criteria are distributed as sigpol data.** The definitions of the
  criteria, their clone policies, and who may approve deploys travel as a
  **Trust Policy Bundle** (signet ADR-011): signed, with an epoch and a
  monotonic seqno for rollback protection, verified offline, and delivered
  over the same path as the CA bundle.
  - A certificate's `.1.10` *names* a criteria; the bundle *defines* it.
  - So verifiers need no hardcoded definitions, and "ship three" means three
    entries in notme's default bundle.
  - The bundle checker exists in signet's `pkg/policy`; SCIM ingestion does
    not, and is not needed here.
- **Verifiers produce sigid-shaped context** (signet `sigid-requirements.md`):
  - `Provenance.Chain` is the lineage: tier, then task, then subtask. "Chase
    the origin" becomes a field.
  - `Environment` carries the criteria's evidence: rootfs or
    `confinementDigest`, and attestations.
  - `Boundary` carries the scope limits.
- **Interlace makes copies visible at the consumer, before any hardware**
  (cloister `interlace-spec/0.1.0`). Its invariant is "silence is evidence":
  every authenticated call is recorded per peer, with counters, and a peer
  can request its own chain back by disclosure.
  - The honest path already keeps a ledger of everything it minted
    (`~/.notme/tasks/ledger.jsonl`).
  - Comparing that ledger against a consumer's disclosed record exposes any
    certificate in use that the path **never minted**: a copy, caught where
    it was used.
  - That is a population check, and it covers the gap left by deferring
    receipts (§5.4): it detects rather than refuses.
  - Known hazard: Interlace and notme overlap on `.1.5` and `.1.6` under the
    shared placeholder arc. LLO tells them apart today; the PEN
    (notme-229dc3) removes the overlap.

## 4. Concepts

| Term | Meaning |
|---|---|
| **Path** | The one process on a host that holds the tier key and mints. Workloads ask it; they never hold the tier. |
| **Criteria** | A named, versioned definition of a unit of identity: what counts as one, the evidence, where minting may happen, clone policy, lifetime, scope ceiling. |
| **Clone policy** | `singleton` (default) or `replicas: N`. Set on the enrollment by the approver. |
| **Generation** | A counter on the enrollment, advanced by each renewal. |
| **Branch** | A counted, sanctioned clone under a `replicas` policy, with its own identity extending the parent's. |
| **Receipt** | An SCT from the path's local append-only log, embedded in every certificate the path mints. |
| **Check-in** | Renewal. It already happens hourly and online. It now also advances the generation and anchors the path's log. |

## 5. Mechanisms

### 5.1 Generation counter: fork detection at renewal

The enrollment row gains `generation INTEGER NOT NULL DEFAULT 0` and
`last_renewal_digest TEXT`.

Renewal binding v2 (domain-separated, new tag; v1 is accepted during
migration, §8):

    "notme/tier-renew/v2\0" || SPKI || uint64be(iat) || uint64be(generation)

- `generation == current` → issue the new tier, store `current + 1` and the
  digest of this request, and return the new generation with the tier.
- **Idempotent retry** *(builder check; my call)*. The client persists the
  exact request bytes before sending, and resends **those bytes** until it
  gets an answer. The server treats a request at `generation == current - 1`
  whose SHA-256 over the full binding bytes equals `last_renewal_digest` as
  a retry. It accepts it for up to **one tier lifetime after the original
  `iat`** (not `RENEWAL_SKEW_S`), and returns a freshly minted equivalent
  tier. The certificate is public, so byte-identity is not needed. A *newly
  signed* request at `current - 1` is not a retry. It is
  indistinguishable from a clone, and is treated as a fork. This is why the
  client must persist and resend.
- Anything else stale is a **fork**. Under `singleton`, the enrollment is
  revoked (`revoked_at`, reason `fork_detected`) and both sides need a
  human. That is the break-glass recovery: re-enroll. The refusal reason
  names it.

The honest limit: if a copy renews first, the honest machine is the one
refused. You still learn of the copy, because the honest refusal is the
alarm.

**Retiring binding v1** *(builder check; my call)*:
- New enrollments accept v2 only.
- An enrollment that has renewed with v2 once never accepts v1 again.
- Enrollments that predate phase 1 keep v1 until their renewal horizon ends,
  at most 30 days, and then re-enroll.

So within one maximum horizon of deploy, no copy can sidestep the counter.

### 5.2 Clone policy on the enrollment

`/enroll` gains a clone-policy control beside the renewal horizon:

- **`singleton`** is the default; a plain approve gets it.
- **`replicas: N`** is break glass. It requires the approver to hold
  `authorityManage`, not only `certMint`. It is recorded on the enrollment
  and shown in `GET /cert/issuing-ca/enrollments` and `task-cert status`.
  The horizon is capped shorter (1 day or 7, never 30). More copies means
  more exposure.
- A machine cannot change its own policy, and nothing loosens it after
  approval. It can only be narrowed, like scopes.

### 5.3 Branches

Under `replicas: N`, a clone requests a branch at check-in:
`POST /cert/issuing-ca/branch`, proving possession of the parent tier key,
with the parent's generation.

- **A branch has its own key** *(builder check; my call)*. The clone
  generates a fresh tier key and proves possession of both: parent and new.
  The branch is its own enrollment row, keyed by the new fingerprint, with
  its own generation counter. Renewal lookup by `key_fingerprint` stays
  unambiguous.
- Under `replicas: N`, every line, the parent and each branch, behaves as a
  singleton for §5.1. A stale generation on any line is a fork of **that
  line**. It revokes that line and everything derived from it, and never
  counts as an implicit branch request. A refused branch N+1 is a refusal,
  not a revocation.
- The branch identity extends the parent's, so prefix revocation and the
  bubble-down reach it.
- Branch N+1 is refused as a fork.
- Revoking the parent enrollment ends all branches.

**How a clone knows it is one.** Where the platform exposes a VM generation
ID that changes on snapshot restore, the path checks it before every mint;
a change means stop minting and branch first. Where it doesn't, as with LLO
runs, each run is a fresh start and never inherits a tier at all (§6). A
clone does **not** branch offline. A self-declared branch is self-attested,
and a thief controls its own generation ID.

### 5.4 Receipts: the path's local log

The path keeps an append-only Merkle log under its data directory, with its
own P-256 log key generated at enrollment. Its public key is registered with
the enrollment.

- Every certificate the path mints carries an **embedded SCT** from that log.
  This uses the existing precertificate flow: `opts.pin` keeps serial and
  validity identical across precert and final, and `worker/src/ct/sct.ts`
  encodes the extension. That flow is already verified end to end against
  azul's independent `sct_validator`.
- **At check-in**, the path submits its signed checkpoint and a consistency
  proof from the last anchored one. notme verifies the consistency and
  stores the checkpoint. **Two checkpoints that do not extend one another
  are a fork**, handled as §5.1. notme may also submit anchored checkpoints
  to its own Static CT log (notme-1b46a8) as a log of logs. That is phase 5.
- **How offline verifiers know the path's standing** *(builder check; my
  call)*. notme stamps the path's log key and the time of its last anchored
  checkpoint into each renewed **tier certificate**, as an extension under
  `.1.11`, allocated in the registry. A verifier reads both from the chain it
  already holds, with no lookup and no bundle-format change. Revocation
  takes effect within one tier lifetime (≤ 1 h), the same bound as today.
  Immediate refusal needs an online check and is out of scope.
- **Verifiers acknowledge a task certificate only if:**
  - its chain is valid;
  - it carries a valid SCT from a log key registered to an enrollment in good
    standing;
  - the SCT's timestamp is no later than the path's last anchor plus the
    tier lifetime. This is the offline grace window, already bounded by the
    1 h tier.

  A certificate minted with a copied tier key outside the path has a valid
  chain and **no receipt**, so it is not acknowledged.
- **The limit the builder check found, and the owner's decision.** If the
  log key sits beside the tier key on disk, a copy of the data directory
  copies both. The copy can then issue receipts that pass every offline rule
  above. Receipts add protection only when the log key is held
  **differently** from the tier key, and without hardware nothing on the host
  can do that. **Decided: receipts move to phase 6, alongside hardware
  custody.** In v1:
  - the path runs as **its own OS user**, so workloads and agents on the
    host cannot read its directory;
  - a copy that happens anyway is caught at its next check-in by the
    generation counter (§5.1).

### 5.5 Criteria in the certificate

A new extension, `.1.10` criteria. It is allocated in the
`cert-authority.ts` sub-arc registry and moves with the arc to the PEN
(notme-229dc3). It carries `SEQUENCE { UTF8String name, INTEGER version }`.

**Binding** *(builder check; my call)*:
- The approver chooses the criteria at `/enroll`, alongside clone policy and
  horizon.
- notme stamps them into the **tier** certificate.
- A task certificate's `.1.10` must name criteria its tier carries. That is
  `task ⊆ tier`, the same rule as scopes, enforced at mint and by verifiers.
  The path's local config can select among the granted criteria, never add
  to them.

The verifier rule is uniform. A certificate is acknowledged only if it
satisfies its stated criteria: lifetime, scope ceiling, and receipt required
or not. A mismatch is refused.
- **Singleton** is not checkable by an offline verifier. It is enforced at
  check-in (§5.1), and the verifier relies on the tier's standing (§5.4).
- **Omitting `.1.10`** is acceptable only under a tier that carries no
  criteria. Under a tier that does, a task certificate without `.1.10` is
  refused. So **legacy** means "issued under a pre-criteria tier", accepted
  until the operator's cutoff (§8).

### 5.6 The path service

`task-cert serve` runs the path as a local service, with one config file
selecting transports and the criteria each serves:

- **Unix socket, the default.** Mode 0600 in a 0700 directory. The caller is
  attested from OS peer credentials: uid and pid via `SO_PEERCRED` /
  `LOCAL_PEERCRED`. Peer credentials identify a process, not a unit, so each
  unit gets its own binding: a **per-unit socket**, or a **unit handle** the
  path issues when the unit starts and the caller presents. "Same user" is
  never sufficient.
- **HTTP / gRPC, opt-in.** Loopback only. A unit handle is required. Host and
  Origin headers are checked to defeat DNS rebinding, so no web page can
  reach it. TCP has no peer credentials, so the handle is the only binding.
  Never "it's localhost, so it's trusted."

**Keys never enter a confined guest.** This follows LLO's ADR-0038:
credentials are attached host-side, never copied into the client
environment. For a confined run, the task certificate's private key stays
with the host. notme's `proxy/` (a cert held in process memory and presented
on the guest's behalf) or an equivalent host-side shim presents it. Copying a
guest yields nothing.

**A second, local revocation lever: the workspace mount.**
- Where the unit's workspace is a content-addressed mount (LLO ADR-0029: a
  manifest of exactly the files the task may touch, named by a BLAKE3 root),
  the host-side shim presents the task's credential **only while that mount
  is live**.
- Pulling the mount is immediate on the host, with no network and no wait
  for certificate expiry.
- Manifests nest, so pulling a parent pulls every child mounted from it.
- The mount's root is the natural `.1.9` goal hash: the certificate names the
  exact content it was issued for.
- It does not reach a certificate already presented off-host, which lives
  out its ≤ 5 min.

*Who can pull a mount (my call, open to override):* notme, at the host's
next check-in, and the host's own daemon or operator, immediately. A local
actor can only revoke or narrow, never grant.

**Streaming consumers.** A consumer that re-authorizes a long-lived stream
with short-lived signed manifests signs each manifest with a path-minted
task certificate.
- The manifest **must cover the channel's handshake transcript**, both
  ephemeral public keys. Otherwise a valid manifest can be replayed into
  another session.
- Revoking the path means no new manifests, so every stream it authorized
  halts within one manifest lifetime.
- How many streams one task may own is set by the criteria, not by this
  design.

**Algorithm agility** *(builder check; my call)*. Binding v2 and the path's
signer dispatch on the key's SPKI algorithm rather than assuming Ed25519, so
phase 6 can move the tier to P-256 without another binding version.

**Language: my call, TypeScript, inside `scripts/task-cert`.** It reuses
`mintTaskCertPair` and the SCT code directly. A Rust or Go reimplementation
of the cert-pair mint would be a second encoder to keep byte-identical
(ADR-010's lesson). The Rust `proxy/` stays the mTLS plane and is not the
path in v1.

## 6. The three shipped criteria

| Criteria | Unit | Evidence | Where it mints | Clone policy | Lifetime |
|---|---|---|---|---|---|
| `agent-session/1` | one agent session (e.g. a Claude Code session) | passkey-approved enrollment | the path on the host, offline | singleton | the session; tier renews through pauses; tasks 5 min |
| `llo-run/1` | one LLO microVM run | the host path's tier plus the run's `confinementDigest` (`.1.7`) | the host path, per run, offline | one per run; a run never holds a tier | the run; tasks 5 min |
| `deploy/1` | one deploy | a passkey approval of that exact deploy (below) | notme, online, once | none (one-shot) | minutes; no renewal |

For `llo-run/1` *(builder check; my call)*:
- The LLO host process supplies the run's `confinementDigest` to the path over
  the socket. The path cannot compute it.
- The path writes it into `.1.7` with **LLO's** registered meaning: the
  32-byte BLAKE3 digest LLO already parses out of notme certificates. notme is
  writing LLO's field as LLO defines it, not re-using the number. Agree this
  with LLO before phase 5 (bead in ley-line-open).

**`deploy/1` approval: push to your phone** *(owner's decision)*. The
passkey is the user's portable identity; a synced passkey is already on the
phone. "Authorized to approve" is a **grant on the principal**
(`deployApprove`), not a property of a device. The flow follows the shape of
OpenID CIBA:
1. An agent requests a `deploy/1` certificate, naming the commit, the
   environment and the requesting task.
2. notme holds the request and pushes a notification to the approver.
   Delivery uses a Web Push subscription the phone registers once from the
   installed notme web app; that is a delivery address, not an identity.
3. The approval page shows the commit, the environment, the requesting
   agent's identity, and a short matching code also shown to the requester.
   Number matching defeats push fatigue, as `/enroll`'s fingerprint compare
   does.
4. The approver taps. The WebAuthn challenge is a hash of **that exact
   request**, so the assertion cannot approve a different one.
5. notme mints the `deploy/1` certificate, with the commit in `.1.9`'s goal
   hash.

*Default (my call, open to override):* one tap per deploy. An optional
approval window, "this task may deploy this repo for up to 1 h", is break
glass: opt-in, shown on the approval and recorded.

`llo-run/1` is the clone story solved by construction. The guest never holds
anything that can mint. Copying a guest yields one run's 5-minute
certificate. The host's tier is a `singleton` path, guarded by §5.1 and §5.4.

The GitHub Actions run is **not** one of the three. It already works online
through `/cert/gha` and `/token` exchange, and it exercises nothing new.

## 7. The proof — real-world, not a lab test

On a host running LLO:

1. `task-cert serve` runs as the host path (singleton, 7-day horizon).
2. Two LLO runs start from the **same image**. Each gets its own `llo-run/1`
   task certificate with its own `confinementDigest`. Both are acknowledged.
3. An agent session pauses past its tier's lifetime, resumes, renews
   (generation advances), and keeps minting. It is acknowledged.
4. **The copy.** The host's tier key and data directory are copied to a
   second host.
   - **v1.** The first of the two to renew advances the generation. The
     other's renewal is detected as a fork, and the enrollment is shut off,
     ending both lines and everything beneath them. Certificates the copy
     minted before that live out their lifetimes: ≤ 5 min for tasks, ≤ 1 h
     for the tier. The honest host's refusal names `fork_detected`.
   - **Phase 6.** With the path key in hardware, the copy cannot sign
     receipts at all, and its certificates are refused at verify time.
5. **Shutdown.** Revoking the enrollment refuses every subsequent certificate
   from that path and its branches.
6. A `deploy/1` certificate presented after its window is refused by its
   criteria.

Acceptance:
- Each step has an automated test that fails when the mechanism is removed.
  This is the mutation discipline this repo already uses.
- Step 4 and the lost-response case of §5.1 each have a negative control.

## 8. Fit with what exists

| Existing piece | What changes | What keeps working untouched |
|---|---|---|
| `tier_enrolments` (signing-authority.ts) | adds `generation`, `last_renewal_digest`, `clone_policy`, `log_key`, `last_checkpoint`; branch rows | existing rows default to generation 0, `singleton`, no log (legacy) |
| `/cert/issuing-ca/renew` | binding v2 with generation; fork handling | v1 binding accepted for enrollments with no log key, until they re-enroll |
| `/enroll` page | clone-policy control; `replicas` gated on `authorityManage` | renewal horizon, fingerprint compare |
| `mintTaskCertPair` (cert-authority.ts) | optional SCT embedding (existing `opts.pin` + `ct/sct.ts`); `.1.10` | `.1.9` task scope, narrowing, parent/subtask rules |
| `task-cert` CLI | `serve`; local log; checkpoint at renew | `enroll`, `mint`, `renew`, `revoke`, `verify`, `status` |
| OID registry | `.1.10` allocated | `.1.1`–`.1.9`; `.1.7` stays LLO's |
| revocation levers | fork detection is a fifth, automatic lever | the four in the README |
| signet `verify` | must enforce `.1.10` against the sigpol bundle's definition, and later receipts, to acknowledge | `.1.8` discriminator (signet-751af3 fix) |
| signet `pkg/policy` (sigpol) | a criteria section in the Trust Policy Bundle | epoch, seqno, offline checking |
| Interlace (cloister) | the path's ledger is compared against Interlace disclosure | leases, counters, "silence is evidence" |
| LLO `cert_chain.rs` | reads `.1.10`; `llo-run/1` binds the run's digest | marker-based profile detection |
| cloister | inherits the availability coupling (§9) | fails closed as today |
| rosary-056d96 | dispatch identity becomes `agent-session/1` tasks | — |
| GitHub Actions exchange | none | `/cert/gha`, `/token` exchange |
| `trust/` anchor | none | signed at release (notme-8e8836) |

**Legacy cutoff.** Verifiers accept certificates without `.1.10` or receipts
until an operator-set date. That date is announced in release notes and
enforced as configuration in each verifier, never hardcoded.

## 9. Honest limits

- **Host takeover.** Whoever controls the host controls its path: key, log
  and socket. Copies are caught; takeover is not. It is bounded by tier
  lifetime and revocation, as today.
- **Offline authorization travels in the certificate.** A task certificate
  minted offline carries its scopes, because there is nobody to ask. It is
  not bearer (it needs its key), and it is bounded by 5-minute lifetimes,
  narrowing, criteria, and bubble-down revocation.
- **The honest side can lose the race** (§5.1). Detection is guaranteed;
  which side keeps working is not.
- **Availability coupling.** Fork detection shuts honest machines off when it
  fires. cloister fails closed, so a false fork is a downstream outage. That
  is why idempotent retry (§5.1) is a gate, not a nicety.
- **Enforcement lives in verifiers.** Until signet and LLO refuse on `.1.10`
  and receipts, this protects only consumers that do.
- **Scope of this plan** *(builder check; my call)*. The plan covers notme,
  with `task-cert verify` as the reference verifier. Changes to signet
  `verify`, LLO `cert_chain.rs` and notme-ct are filed as beads in those
  repositories. So steps 1–6 of §7 are provable from this repository against
  the reference verifier, and the step that LLO itself refuses waits on
  LLO's bead.

## 10. Phasing

| Phase | What | Value on its own |
|---|---|---|
| 1 | generation counter + idempotent retry + clone policy (worker only) | copied tiers detected at renewal, no client changes beyond the v2 binding |
| 2 | `.1.10` criteria + the three definitions + `task-cert verify` enforcement | a "deploy" certificate that's two hours old is refused |
| 3 | `task-cert serve` over UDS (per-unit sockets / handles); HTTP/gRPC opt-in | workloads stop holding tiers |
| 4 | `deploy/1` push approval (`deployApprove` grant, Web Push, request-bound WebAuthn) and the host-side mount lever | approve an agent's deploy from your phone; pull a task's workspace instantly |
| 5 | LLO integration (`llo-run/1`); signet and LLO enforcement; criteria in a sigpol Trust Policy Bundle; ledger-vs-Interlace-disclosure population check (§3a); log of logs into notme-ct | the §7 proof end to end, with copies detected where they are used |
| 6 | Secure Enclave / TPM custody of the path key (P-256 tier) **plus receipts**: local log, embedded SCTs, checkpoint anchoring (§5.4) | the key cannot leave the host, and certificates minted outside the path are refused at verify time |

## 11. Left to the builder

- Exact table and column names, and the migration mechanics.
- The branch identity segment syntax. It must extend the parent identity and
  be prefix-revocable.
- The unit-handle format and its lifetime.
- The local log's storage layout. Use RFC 6962 / tlog semantics. Reusing a
  library is preferred over writing a Merkle tree.
- Config file format for `serve`.
- How `task-cert status` displays generation, policy and branches.

## 12. Decisions recorded

1. **Receipts before hardware custody?** No. They move to phase 6, and in v1
   the path runs as its own OS user (§5.4).
2. **Deploy approval:** push to the approver's phone, signed with their
   passkey over the exact request (§6). Per-deploy by default, with an
   opt-in window as my call.
3. **Who can pull a workspace mount:** notme at check-in, and the host
   locally. Local actors can only revoke. My call (§5.6).
