<!--
@doc-check
@endpoints: POST /cert, POST /cert/gha, POST /cert/passkey
-->
# ADR-019: What notme's identities name — a delegation authority

**Status:** proposed
**Beads:** `notme-600df1` (this decision), `notme-77438b` (ceremony-varying identity), `notme-2c4209` (registration policy), `notme-77a024` (revocation unit), `notme-acc822` (chain constraints), `notme-9f84e6` (correlation key)
**Answers:** cloister ADR-0066 Q1 and Q2
**Serves:** `notme-bed754` criterion (B); unblocks (C) and (D)

## Context

Cloister's ADR-0066 asks notme to say what its identities name, offering two
readings: a **human authority bootstrapping workload identity**, or a
**workload authority**. Cloister can bind its own acceptance criteria
unilaterally; it cannot bind notme's naming, so the question came here.

Answering it as posed would leave the actual defect unfixed, because the
dichotomy assumes the authority names one kind of thing. notme demonstrably
names two already:

| Route | Identity emitted | What the slot after the domain holds |
|---|---|---|
| `POST /cert/gha` | `wimse://<domain>/gha/<owner>/<repo>` (`worker.ts:746`) | a **workload class**, then what is running |
| `POST /cert/passkey` | `wimse://<domain>/<authMethod>/<principalId>` (`worker.ts:2307`) | an **authentication ceremony**, then a UUID |
| `POST /cert` | same shape as above (`cert-exchange.ts:244`) | same |

A verifier reading `/gha/` and `/passkey/` finds two different *kinds* of fact
in the same position. The identity cannot say which it is.

### The defect this produces today

`worker.ts:2307` interpolates the session's auth method beside a **stable**
principal id. `/join` issues a session with `authMethod: "invite"`
(`worker.ts:1997`); passkey login issues one with `authMethod: "passkey"`
(`worker.ts:885`, `:929`) — **for the same principal**. So one human who joins
by invite and later authenticates with a passkey mints **two different
identities for one subject**. A field that should be stable across
authentications varies by authentication (`notme-77438b`).

This is downstream of `notme-ebc9af`, which replaced a hardcoded `authMethod`
with the real one. That fix was correct — a stable lie is worse than visible
instability, because the lie is trusted precisely because nothing contradicts
it — but it made the modelling defect *observable* rather than relieving it.

### What the agent case adds

In a system where humans and agents both operate, the interesting principal is
neither a human nor a workload. It is **delegated authority exercised
unattended**: an agent acting with authority a human granted, without that
human present, for a bounded piece of work.

That is what the hardcoded 5-minute TTL at the session-cert path is implicitly
modelling — a credential scoped to roughly the length of a task, because
nothing else bounds it. Note the asymmetry that already exists and is nowhere
stated: the GHA (workload) TTL is configurable via `GHA_CERT_TTL_MS`, while the
session (human-ceremony) TTL is hardcoded. The code already treats the two
cases differently while the naming treats them the same.

### The finding that makes this concrete

**notme already records delegation and discards it at the credential
boundary.** Three columns exist today: `principals.created_by`,
`capability_grants.granted_by`, `invites.created_by`. Storage knows who granted
what to whom. The certificate carries the principal and its scopes and
**nothing about the grant** — so when an agent acts, the cert says "principal
X, scopes Y" and no verifier can learn "on behalf of human Z, granted at time
T". Accountability does not survive the handoff, which in an agent world is the
handoff that matters most.

## Decision

**notme is a delegation authority.** It names subjects, records what *kind*
each subject is, and mints short-lived credentials that carry the delegation
chain they were minted under.

Cloister's D2 reading — "human authority bootstrapping workload identity" —
describes the *dominant flow* correctly and is the right reading of
`cloister-f2338f`. It is wrong as a statement of the authority's nature,
because it has nothing to say about the hop that happens after bootstrap.

### The chain is two hops, with different granters

> The bridge delegates the human to the machine. And the machine delegates to
> each task.

| Hop | Granter | Subject | Credential | Built? |
|---|---|---|---|---|
| 1 | human (passkey ceremony) or platform (GHA OIDC attestation) | **machine** | bridge cert | **yes** |
| 2 | machine | **task** | task cert | **no** |

Hop 2 does not exist. There is no route that accepts a bridge *certificate* as
authorization to mint anything; every mint path is gated on a **session**.
`certMint` is granted to the bootstrap principal (`cert-exchange.ts:140`),
excluded from certs by policy, and **checked nowhere** — the vocabulary
anticipated hop 2 and the implementation never arrived.

### D1 — The identity names a stable subject, not the ceremony

The advertised identity MUST NOT vary with how a principal authenticated.
`authMethod` describes the *credential*, not the *subject*, and belongs in an
extension — where it already is (`OID_AUTH_METHOD`).

### D2 — The kind is explicit, and each kind is attested appropriately

A human identity's assurance comes from a human-presence ceremony; a workload
identity's comes from platform attestation. These are different assurance
types, and a verifier must be able to tell them apart **without parsing a
ceremony name out of a path**. Proposed shapes, to be argued:

```
wimse://notme.bot/human/<principalId>
wimse://notme.bot/workload/gha/<owner>/<repo>
wimse://notme.bot/agent/<principalId>      + a delegation extension
```

### D3 — Delegation is representable in the credential

A granting subject and a grant time, sourced from data notme already stores.
This is the agent-world requirement and the one currently missing entirely.

### D4 — Delegation depth is bounded by a budget, not by scope narrowing

ADR-008 §"BasicConstraints and path length" already specifies the three tiers,
and `notme-20f88b` widened the root to `pathlen=1` for exactly this reason.
The middle tier was never built: `cert-authority.ts` stamps `CA=false` on every
cert notme mints, so **the authority issues two levels while its root
advertises room for three**.

An earlier draft of this ADR argued that monotone scope narrowing made depth
bound itself, so no tier needed formalising. **That was wrong**, and the
correction matters:

- `verifyScopeChain` accepts equality by design, so the relation is reflexive,
  hence a preorder, hence never well-founded — the constant chain admits
  infinite descent.
- Even forbidding equality bounds a chain only at `|S|+1`, a limit set
  accidentally by whoever last added a scope string.
- Once scopes are hierarchical (`sign:git` → `sign:git:repo` → …), infinite
  *strictly* decreasing chains exist too.
- Macaroons and Biscuit permit unbounded attenuation **because** authority
  cannot grow, and both bound depth **separately** — Biscuit by block count,
  macaroon deployments by caveat cap — since chain length is a
  verification-cost problem even when authority is safe.

Terminating a chain whose scopes may stay equal requires another component that
strictly decreases: a rank function into a well-founded set. X.509 carries it
already. RFC 5280 §6.1.4(l)–(m) is a loop variant, and chains terminate because
ℕ has no infinite descent. SPKI/SDSI (RFC 2693) carries the degenerate case as
a boolean delegation bit — which **is** this two-hop design.

**So the tier IS formalised, as a relative budget, never an absolute number.**
A certificate sits at different absolute depths under different trust anchors,
so an absolute tier is not well-defined per certificate; "remaining hops below
me" is cert-local and anchor-independent, which is why RFC 5280 composes it by
decrement-and-min. Two caveats to carry: §6.1.4(l) does **not** decrement for
self-issued certificates, so pathlen bounds distinct *organisational* tiers
rather than literal chain length; and §6.1.1 excludes the anchor's own
certificate from path processing (RFC 5937 makes applying anchor constraints
optional), so a root's pathlen is enforced when it appears as an intermediate
and typically ignored when it is the anchor.

### D5 — Three independent bounds, none substituting for another

| Bound | Mechanism | Enforcement | Built? |
|---|---|---|---|
| **Authority** — what a credential may *do* | `scopes ⊆ parent` (`auth/scope-chain.ts`) | **cooperative** — relying parties MUST, nothing compels them | yes |
| **Depth** — how far it may *pass that on* | `pathLenConstraint` | **intrinsic** — every conformant validator | root only; middle tier missing |
| **Namespace** — which identities it may *name* | `nameConstraints` (ADR-008 §299) | **intrinsic** | **no** |

The enforcement asymmetry is why all three are needed: the weaker cooperative
mechanism does not make the stronger intrinsic ones redundant.

## What follows, already built

- `auth/scope-chain.ts` — the authority bound, in production, applied at
  `certScopesForSession`, with the six previously-orphaned attenuation tests
  now bound to it.
- `delegation-depth.do.test.ts` — the depth gap pinned as `it.fails`, so it
  goes red the moment hop 2 lands.
- `auth/correlation-key.ts` — `<principal>/<bridge>/<task>`, keyed on the
  **stable principal** and the **pair binding** (not a serial: a bridge is two
  certs with two independent serials, so no serial names it).
- `receipts/commitment.ts` — an optional ninth `delegation` field, verified
  against what the authority derived, refused when it cannot verify it.
  Proposed to cloister as `cloister-c10ff2`; inert until they adopt it.

## What it requires that is not built

1. **The middle tier** — a mint path producing `CA=true, pathlen=0,
   keyCertSign`. This is the whole of hop 2.
2. **`nameConstraints`** on any CA=true cert. Blocked on (1): there is nothing
   to constrain until an intermediate exists.
3. **A task-credential producer**, which is what gives the correlation key its
   third segment and the receipt field a value.
4. **`OID` for the delegation extension**, inheriting `notme-229dc3`'s
   placeholder-PEN blocker *and* its live arc collision with cloister.

## Consequences

**Registration policy (`notme-2c4209`)** follows from D2 rather than from an
inline comment: if identities are typed, "may a stranger register" becomes
"which kinds may self-register", which is answerable per kind instead of
globally.

**The revocation unit (`notme-77a024`)** is a delegation. The hierarchy falls
out and is exactly the granularity between "wait out the TTL" and "revoke
everything":

```
revoke a PRINCIPAL → every machine and every task under it falls
revoke a BRIDGE    → that machine's tasks fall; sibling bridges survive
revoke a TASK      → only that task
```

Note this needs no new mechanism for the subtree case: revoking a bridge cert
fails every task cert beneath it **by issuer**, which is intrinsic path
validation. What the correlation record adds is *enumeration* — answering what
a revocation affected, which is an incident-response question.

**Issuance transparency (`notme-907299`)** gains a subject worth logging. A log
of "a cert was issued" is weaker than a log of "X delegated to Y at time T".

**Federation** is a *separate axis* and is deliberately out of scope here.
Delegation depth is vertical; two organisations each running an authority is
horizontal. notme already emits trust-domain-qualified identities
(`wimseTrustDomain`), which is the hard part; what is missing is the accept
side. SPIFFE Federation is the model to copy. Cross-signing is the X.509
alternative and is worse here, because it makes a foreign root
indistinguishable from a local one in the chain — destroying the attribution
this ADR exists to preserve.

## Alternatives considered

**A — "Human authority bootstrapping workload identity"** (cloister's D2).
Describes the dominant flow correctly. Rejected as the authority's *nature*: it
says nothing about hop 2, so adopting it resolves the naming and leaves the
revocation unit unbuildable.

**B — "Workload authority"** (SPIFFE-shaped). Rejected: it would make
`/cert/passkey` the anomaly, when the passkey ceremony is the root of trust for
everything notme issues outside CI.

**C — Delegation authority** (chosen). Subsumes both: hop 1 is exactly A, and
the model additionally names hop 2, which A and B are both silent about.

**D — Do nothing, document the current shape as intended.** Rejected because
the shape is not self-consistent: `notme-77438b` is a live defect under any
reading, and `gen/go/verify/identity.go` already carries a "never split this
string" comment — a symptom treatment for exactly this cause.

## Open questions

1. **Addition or cut?** Changing the session-minted URI shape is a *blocking*
   cross-repo change per ADR-018's compatibility matrix. Cloister's ADR-0066 D4
   (they decline to parse WIMSE segments at all) and D5 (they will consume an
   alongside identity) mean this can land as an **addition**. Signet has not
   been asked.
2. **What kinds exist?** `human` / `workload` / `agent` is a taxonomy decision
   that should be made once rather than grown.
3. **Does hop 2 mint at notme or sign locally?** With the bridge at
   `CA=true, pathlen=0` the machine can sign task certs locally with no round
   trip and the chain still validates to notme's root — offline and edge run
   the identical check. notme is then in the *revocation* path without being in
   the *issuance* path, which is the resolution this ADR assumes. It should be
   stated explicitly before hop 2 is built.

## Adopting this

Change **Status** to `accepted` and this ADR satisfies `notme-bed754`
criterion (B) for the recorded-answer half. The code half of (B) —
`notme-77438b`, the ceremony-varying identity — is a separate change gated on
open question 1.
