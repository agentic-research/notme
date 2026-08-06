<!--
@doc-check
@endpoints: POST /cert, POST /cert/gha, POST /cert/passkey
-->
# ADR-019: Typed principals and bounded delegation

**Status:** proposed
**Beads:** `notme-600df1` (this decision), `notme-77438b` (ceremony-varying identity), `notme-2c4209` (registration policy), `notme-77a024` (revocation unit), `notme-acc822` (chain constraints), `notme-9f84e6` (correlation key)
**Answers:** cloister ADR-0066 Q1 and Q2
**Serves:** `notme-bed754` criterion (B); unblocks (C) and (D)
**Supersedes within this ADR:** an earlier draft argued notme names "delegated authority exercised unattended". That was a category error and is corrected below.

## Context

Cloister's ADR-0066 asks notme to say what its identities name, offering two
readings: a **human authority bootstrapping workload identity**, or a
**workload authority**. Cloister binds its own acceptance criteria; it cannot
bind notme's naming, so the question came here.

The dichotomy is too small, because notme already names two different kinds of
thing in the same URI position:

| Route | Identity emitted | What the slot after the domain holds |
|---|---|---|
| `POST /cert/gha` | `wimse://<domain>/gha/<owner>/<repo>` (`worker.ts:746`) | a **platform attestation mechanism**, then what is running |
| `POST /cert/passkey` | `wimse://<domain>/<authMethod>/<principalId>` (`worker.ts:2307`) | an **authentication ceremony**, then a UUID |
| `POST /cert` | same shape as above (`cert-exchange.ts:244`) | same |

A verifier reading `/gha/` and `/passkey/` finds two different *kinds* of fact
in the same position, and neither is the subject.

### The live defect

`worker.ts:2307` interpolates the session's auth method beside a **stable**
principal id. `/join` issues a session with `authMethod: "invite"`
(`worker.ts:1997`); passkey login issues one with `authMethod: "passkey"`
(`worker.ts:885`, `:929`) — **for the same principal**. One human who joins by
invite and later authenticates with a passkey mints **two different identities
for one subject** (`notme-77438b`).

This is downstream of `notme-ebc9af`, which replaced a hardcoded `authMethod`
with the real one. That fix was correct — a stable lie is worse than visible
instability — but it made the modelling defect *observable* rather than
relieving it.

### What notme already records and discards

`principals.created_by`, `capability_grants.granted_by`, `invites.created_by`.
Storage knows who granted what to whom. The certificate carries the principal
and its scopes and **nothing about the grant**, so when an agent acts, no
verifier can learn on whose behalf. Accountability does not survive the
handoff, which in an agent world is the handoff that matters most.

## Decision

> **notme is an authority for typed principals and bounded delegation.**
> Humans, agents, workloads, and organizations may have stable principal
> identities. A delegated credential identifies the key-holding **actor**, any
> **represented principal**, and the **grant chain** authorizing the action.
> Authentication ceremony, platform attestation, runtime, and task are
> credential or execution attributes — **not substitutes for stable identity**.

### The entities, and why the earlier draft was wrong

An earlier draft said "the interesting principal is delegated authority
exercised unattended," and described the bridge as delegating *the human to the
machine*. Both are category errors. **Delegated authority is not a principal**
— the agent is the principal, and delegation is the *relationship* that gives
that agent authority. A bridge does not delegate a human; it delegates *some
authority from* a human or organization *to* an agent.

```
human H ── grant G ──▶ agent A ── executes ──▶ task T
                         │
                         └── runs within workload / runtime W
```

- **Human and agent are stable principals.** Both are independently
  identifiable and independently accountable.
- **The grant** says what A may do on behalf of H.
- **The workload** says where and how A is running.
- **The task** says what bounded work A is performing.
- **The credential** binds these facts to the key being used.

This is **delegation, not impersonation**: the actor retains its own identity
while acting for another subject. RFC 8693 §4.1 draws the same distinction and
represents it with separate subject (`sub`) and actor (`act`) information, with
`act` nestable to express a chain. notme should not invent a different shape
for a problem OAuth token exchange already models.

### D1 — Seven roles, named separately

Conflating any two of these is how the current design went wrong.

| Role | Who | Notes |
|---|---|---|
| **actor** | the agent holding and exercising the credential | the subject of the certificate |
| **represented_principal** | human or organization on whose behalf it acts | absent for un-delegated workloads |
| **grantor** | the principal or policy authority that issued the grant | **not** the attester |
| **attester** | GitHub OIDC, passkey authenticator, TPM | asserts *facts*; does not decide authority |
| **issuer** | notme, or a delegated bridge CA | mints the credential |
| **runtime** | the workload carrying the agent | where it runs |
| **task** | bounded execution context | what work is in scope |

The prior draft's table listed the platform as a *granter* for the GHA path.
That is wrong: **GitHub attests facts about a workflow run; it does not decide
what authority should be granted.** The grantor for a CI-obtained credential is
whoever configured the policy that maps an attested identity to scopes — an
organization principal, not GitHub.

### D2 — Identity names a stable subject; kind and assurance are claims

The URI carries the subject and nothing else:

```
wimse://notme.bot/principal/<stable-id>
```

with signed extensions carrying:

```
principal_kind  = human | agent | workload | organization
authentication  = passkey | invite | …          (how a human proved presence)
attestation     = gha-oidc | tpm | …            (how a workload was attested)
```

An earlier draft proposed `wimse://notme.bot/workload/gha/<owner>/<repo>`.
That repeats the very defect it was fixing: **GHA is how the workload was
attested, not what the workload is.** Kind and assurance mechanism are
different axes and must not share a slot.

### D3 — The grant is a first-class object with a defined payload

The prior draft required only a granting subject and a grant time. That is not
enough to authorize anything. The minimum useful grant:

```
grant_id
actor_principal
represented_principal
parent_grant_id              ← what makes it a chain
scopes
audience / resources
purpose or goal_hash         ← what makes it task-scoped
issued_at / expires_at
delegable                    ← may the actor delegate onward at all
remaining_delegation_depth   ← the rank function, carried in the payload
```

**A five-minute TTL is only a time bound.** It does not make a credential
task-scoped, and the earlier claim that the TTL was "implicitly modelling task
scope" was wishful. `purpose`/`goal_hash` is what scopes a credential to work;
`expires_at` merely stops it outliving the work.

Note `remaining_delegation_depth` sits in the grant payload *and*
`pathLenConstraint` sits in the certificate. That redundancy is deliberate: the
first is enforced by anything reading the grant, the second by every conformant
X.509 validator whether or not it understands grants.

### D4 — Depth is bounded by a rank function, not by scope narrowing

ADR-008 already specifies three tiers and `notme-20f88b` widened the root to
`pathlen=1` for exactly this. The middle tier was never built:
`cert-authority.ts` stamps `CA=false` on every cert notme mints, so **the
authority issues two levels while its root advertises room for three.**

An earlier draft argued that monotone scope narrowing made depth bound itself.
**That was wrong:**

- `verifyScopeChain` accepts equality by design, so the relation is reflexive,
  hence a preorder, hence never well-founded — the constant chain admits
  infinite descent.
- Even forbidding equality bounds a chain only at `|S|+1`, a limit set
  accidentally by whoever last added a scope string.
- Once scopes are hierarchical (`sign:git` → `sign:git:repo` → …), infinite
  *strictly* decreasing chains exist too.
- Macaroons and Biscuit permit unbounded attenuation **because** authority
  cannot grow, and both bound depth **separately** — Biscuit by block count,
  macaroon deployments by caveat cap.

Terminating a chain whose scopes may stay equal requires another component that
strictly decreases: a rank function into a well-founded set. RFC 5280 §6.1.4(l)–(m)
is exactly that — a loop variant, decremented and min'd along the path. Chains
terminate because ℕ has no infinite descent. RFC 2693's boolean delegation bit
is the degenerate case, and `delegable` above is that bit.

**So the tier IS formalised — as a relative budget, never an absolute number.**
A certificate sits at different absolute depths under different trust anchors,
so an absolute tier is not well-defined per certificate.

Two caveats: §6.1.4(l) does **not** decrement for self-issued certificates, so
pathlen bounds distinct *organisational* tiers rather than literal chain
length; and §6.1.1 excludes the anchor's own certificate from path processing
(RFC 5937 makes applying anchor constraints optional), so a root's pathlen is
enforced when it appears as an intermediate and typically ignored when it is
the anchor.

### D5 — Three bounds, with honest enforcement labels

| Bound | Mechanism | Enforcement | Built? |
|---|---|---|---|
| **Authority** — what a credential may *do* | `scopes ⊆ parent` (`auth/scope-chain.ts`) | **cooperative** — relying parties MUST; nothing compels them | yes |
| **Depth** — how far it may *pass that on* | `pathLenConstraint` + `remaining_delegation_depth` | **intrinsic** for pathlen | root only; middle tier missing |
| **Namespace** — which identities it may *name* | see below — **not** URI `nameConstraints` | **cooperative** unless hosts are split | no |

**The namespace bound cannot be done the way ADR-008 §299 says.** That section
proposes `permittedSubtrees: URI:wimse://notme.bot/agent/*`. RFC 5280 §4.2.1.10
is explicit: *"For URIs, the constraint applies to the host part of the name.
The constraint MUST be specified as a fully qualified domain name and MAY
specify a host or a domain."* **Path segments are not constrained.** A
conformant validator will happily accept `wimse://notme.bot/anything` under
that constraint.

Constraining kinds therefore requires one of:

1. **Distinct constrained hosts** — `agents.notme.bot`, `workloads.notme.bot`.
   The only option enforced intrinsically by stock validators, at the cost of
   putting kind back into the name.
2. **An `otherName` with a registered OID**, constrained via
   `permittedSubtrees` on that `otherName` type. Standards-shaped, needs the
   PEN (`notme-229dc3`).
3. **A custom critical extension plus a validator that understands it.** Marking
   it critical makes non-understanding verifiers *reject* rather than ignore —
   which is safe, but means it is enforced by notme's own verifier, not by
   everyone's.

This is an open question, not a decision. ADR-008 §299 should be corrected
regardless of which is chosen.

## What follows, already built

- `auth/scope-chain.ts` — the authority bound, applied at
  `certScopesForSession`, with six previously-orphaned attenuation tests now
  bound to it.
- `delegation-depth.do.test.ts` — the depth gap pinned as `it.fails`, going red
  the moment the middle tier lands.
- `auth/correlation-key.ts` — `<principal>/<bridge>/<task>`, keyed on the
  stable principal and the pair binding (not a serial: a bridge is two certs
  with two independent serials, so no serial names it).
- `receipts/commitment.ts` — an optional ninth `delegation` field, verified
  against what the authority derived. Proposed to cloister as
  `cloister-c10ff2`; inert until adopted.

## What it requires that is not built

1. **The grant as a stored, referenceable object** with the D3 payload. Today
   there are three `*_by` columns and no grant identity.
2. **The middle tier** — a mint path producing `CA=true, pathlen=0`.
3. **A namespace mechanism**, per D5's open question.
4. **A task-credential producer**, which gives the correlation key its third
   segment and the receipt field a value. Note the subject of a task credential
   should be the **agent or agent instance**, with `task_id`/`goal_hash` as
   bounded context — a task is execution context, not an entity capable of
   holding a key, unless it genuinely generates and controls its own.
5. **An OID arc** (`notme-229dc3`), which also has a live collision with
   cloister's Interlace extensions.

## Consequences

**Registration policy (`notme-2c4209`)** follows from D2: "may a stranger
register" becomes "which *kinds* may self-register", answerable per kind.

**The revocation unit (`notme-77a024`)** is a grant. The hierarchy:

```
revoke a PRINCIPAL → every grant naming it as actor or represented falls
revoke a GRANT     → every credential minted under it, and its child grants
revoke a TASK      → only that bounded context
```

**This does not happen by itself, and the mechanism must be named.** Revoking a
bridge collapses descendant validation *only when verifiers receive and enforce
fresh revocation state.* RFC 5280 requires status be determined via CRLs, OCSP,
or an out-of-band mechanism — and that information still has to reach the
verifier. Recording "revoked" inside notme does not intrinsically invalidate an
offline chain someone already holds.

What notme has today is **epoch-based bundle revocation** (`revocation.ts`):
coarse (a whole issuance class), pull-based, and gated on `BUNDLE_MAX_AGE_MS`.
There is no CRL, no OCSP, and no per-credential status. So the honest current
answer is **TTL-only for anything finer than an epoch**, and the ADR says so
rather than implying the hierarchy above already works. Choosing among signed
revocation epochs, a CRL distribution point, OCSP, or trust-bundle refresh is
`notme-77a024`'s remaining work.

**Issuance transparency (`notme-907299`)** gains a subject worth logging: "X
delegated to Y at time T, for purpose P" is a materially stronger record than
"a cert was issued."

### Task completion is a grant, not a new object

A grant authorizes an attempt; it does not settle whether the work is done.
Five distinct claims hide behind the word "done", and collapsing any two is a
defect:

| Claim | Who makes it | Speech act |
|---|---|---|
| **delegation** — you may attempt this | grantor | directive |
| **promise** — you undertake this exact task | actor | commissive |
| **submission** — the work is finished | actor | commissive |
| **verification** — the evidence satisfies the predicate | verifier | assertive |
| **acceptance** — it is done | task authority | **declarative** |

**An agent's `end_turn`, clean exit, or "done" message is only SUBMISSION.**
Only an authority can perform a declarative, which is why acceptance cannot be
self-signed — the same reasoning APAS already applies to orchestrator
self-attestation. In Promise Theory terms an agent can promise its own
behaviour and never impose an obligation on another, so the verifier must make
its own separate promise to evaluate.

**Acceptance needs no new credential type.** It is a grant with
`scopes: ["accept:<taskHash>"]`, inheriting `grant_id`, `parent_grant_id`,
expiry and `delegable` from D3. That closes a recursion a standalone
`verifierPolicy` field would leave open — *who authorised the verifier* — and
makes "who may accept" revocable by the same mechanism as everything else.

Three constraints that follow, and are easy to get wrong:

1. **The verifier must sit outside the actor's blast radius.** CI passing
   against a commit digest looks like independent evidence and often is not:
   CI is itself an agent executing configuration from the repository under
   test. If the workflow definition is within the actor's write scope, CI is
   self-attestation with extra steps — the same defect class as a workflow
   whose outputs were structurally always empty, and an action that pinned
   itself. Qualification is checkable and should be a stated precondition.
2. **A close condition is either machine-evaluable or human-judged, and must
   say which.** Hashing a predicate commits to its *wording*; it does not make
   it evaluable. Most interesting conditions are human judgement wearing a
   machine-checkable costume, and the distinction must be forced at authoring
   time rather than discovered at verification time.
3. **Liveness predicates are not settled by a signature.** "The SLO held for 24
   hours" is continuously falsifiable, so acceptance carries a validity window
   and is itself a lease — `submitted → verified → accepted` stops being
   monotonic. Either exclude liveness predicates or say so.

**Enforcement is a short lease, never "valid until done."** A credential whose
lifetime is defined by task state requires every verifier to know that state —
the same error as assuming a recorded revocation invalidates a chain someone
already holds. Instead: minutes-long credentials, a controller that renews only
while the task is active, and acceptance stops the renewal. Immediate
termination still needs online revocation or an introspecting tool boundary.

**Where this lives.** An acceptance attestation is structurally a receipt: a
signed statement about an event with derived-not-received fields.
`ReceiptSigner` already carries the master key, canonical CBOR, and the
validate-then-sign discipline that refuses caller-supplied bytes. The
`delegation` field on the commitment is the **attribution** half; acceptance is
the **satisfaction** half over the same surface.

**Open, and it should be settled before building:** in-toto **layouts** already
express "these steps, these expected materials and products, and these
functionary keys may sign each step" — a task contract and verifier policy in
one signed artifact, with `in-toto-verify` as the evaluator. It is CNCF and
already in the SLSA ecosystem. The honest question is not "what object is
missing" but **what APAS adds that a layout does not** — plausibly the
delegation chain, the represented principal, and an actor that was itself
delegated to mid-execution, none of which in-toto's functionary model covers.
Extending that model is a stronger position than a parallel format.

**Federation** is a separate, horizontal axis and is out of scope here. notme
already emits trust-domain-qualified identities; the accept side is missing.
SPIFFE Federation is the model. Cross-signing is worse here because it makes a
foreign root indistinguishable from a local one, destroying the attribution
this ADR exists to preserve.

## Alternatives considered

**A — "Human authority bootstrapping workload identity"** (cloister's D2).
Describes the dominant flow correctly. Rejected as the authority's *nature*: it
says nothing about what happens after bootstrap, so adopting it resolves the
naming and leaves the revocation unit unbuildable.

**B — "Workload authority"** (SPIFFE-shaped). Rejected: it makes
`/cert/passkey` the anomaly, when that ceremony is the root of trust for
everything notme issues outside CI.

**C — Typed principals and bounded delegation** (chosen). Subsumes both, and
additionally names the agent as an accountable principal rather than treating
it as a machine that inherits a human's identity.

**D — Do nothing, document the current shape as intended.** Rejected:
`notme-77438b` is a live defect under any reading, and
`gen/go/verify/identity.go` already carries a "never split this string" comment
— a symptom treatment for exactly this cause.

## Open questions

1. **Addition or cut?** Changing the session-minted URI shape is a *blocking*
   cross-repo change per ADR-018's matrix. Cloister's D4 (they decline to parse
   WIMSE segments) and D5 (they will consume an alongside identity) permit an
   **addition**. **Signet has not been asked.**
2. **Which namespace mechanism** — distinct hosts, `otherName`, or a custom
   critical extension (D5).
3. **Which revocation mechanism** reaches verifiers (Consequences, above).
4. **Is `agent` a kind, or a role a principal plays?** The taxonomy should be
   settled once rather than grown.
5. **Does the middle tier mint at notme or sign locally?** With
   `CA=true, pathlen=0` the machine can sign locally with no round trip and the
   chain still validates to notme's root — putting notme in the revocation path
   without being in the issuance path. Stated here so it is argued before it is
   built.
6. **Does APAS extend in-toto layouts or stand parallel to them?** See "Task
   completion is a grant". This is a standardisation-strategy question as much
   as a technical one, and it should be answered before an acceptance
   attestation is specified.

   **External alignment, checked 2026-08-06.** NIST's NCCoE concept paper
   *"Accelerating the Adoption of Software and AI Agent Identity and
   Authorization"* (Feb 2026) frames agent identity across four dimensions —
   identification, authorization, auditing, and **non-repudiation**, the last
   defined as *"accountability that links agent actions to the human authority
   that sanctioned them."* That is this ADR's subject, named by an external
   body.

   Its proposed stack is OAuth 2.0/OIDC (with RAR, PAR and **DPoP**),
   SCIM, SPIFFE/SPIRE and ABAC. notme already implements the load-bearing
   pieces — DPoP per ADR-006, and WIMSE-shaped identities. **But that stack
   does not close the non-repudiation dimension it names**: OAuth binds
   delegation at authorization time and retains nothing after; SPIFFE issues a
   workload identity with no delegation chain at all. Neither yields a durable
   signed record of "agent A did X under grant G from human H" — which is what
   D3's grant object and `notme-9f84e6`'s correlation key are for.

   So two independent bodies now describe the same hole from opposite sides:
   in-toto has the verifier-policy machinery and no delegation model; NIST
   names the delegation requirement and proposes standards that don't carry it.
   Positioning this work as *extending* both beats standing parallel to either.
   Relevant timing: CAISI's AI Agent Interoperability Profile is planned for
   Q4 2026; COSAiS overlays for single- and multi-agent systems remain in
   development. These are voluntary frameworks — they bind through procurement
   flow-down, not by their own force. Recorded in full on `notme-907299`.

## Adopting this

Change **Status** to `accepted`. That satisfies `notme-bed754` criterion (B)
for the recorded-answer half only. The code half — `notme-77438b` — is a
separate change gated on open question 1.
