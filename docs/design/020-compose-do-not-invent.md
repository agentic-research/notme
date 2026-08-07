<!--
@doc-check
@endpoints: POST /cert, POST /cert/gha, POST /cert/passkey
-->
# ADR-020: Compose, do not invent

**Status:** proposed
**Beads:** `notme-600df1` (the delegation model this constrains), `notme-9f84e6` (correlation/attribution), `notme-8eb592` (the human-acceptor gap), `notme-907299` (transparency)
**Relationship to ADR-019:** ADR-019 decides *what notme names*. This decides *what notme may build to express it*. Split out of ADR-019 D6 so the composition constraint can be argued and adopted on its own — it binds work far beyond the identity decision.

## Context

notme sits in a stack where five other systems already own facts it needs:
signet owns the protocol and capability vocabulary, cloister owns Interlace
receipts, ley-line owns content addressing, rosary owns task state, and the
wider ecosystem owns DSSE, in-toto and X.509. Each time a gap appears — task
scoping, completion, attribution — there is a pull toward solving it *here*,
because here is where the identity already lives.

That pull has to be resisted deliberately, because every format notme invents
is one more thing five repos must implement, one more thing a standards
reviewer will ask why it exists, and one more surface that cannot be verified
by tools anyone already has.

**This is not a new constraint.** APAS §3.4 already states it of itself:
*"APAS does not define its own key format — it delegates to that role's
existing specifications."* The spec references DSSE and in-toto throughout.
This ADR applies the same discipline to notme.

## Decision

> notme MUST represent delegation by **composing** standardized certificates,
> attestations, capabilities and content references, and MUST make the
> resulting graph **walkable offline by a party that does not trust notme**.
>
> It MUST NOT introduce a new signing algorithm, authorization token,
> hash-chain format, task store, or task-completion state machine, and MUST
> NOT be required as a verifier of any statement it did not issue.
>
> It MUST own the lifecycle of the credentials and grants it issues, because
> that is revocation.

### The composition, and who owns each layer

| Layer | Answers | Standard | Owner |
|---|---|---|---|
| X.509 path (root → bridge → task) | who may act, how far it may pass that on | RFC 5280 | **notme** |
| APAS statement (DSSE / in-toto) | the bounded obligation: revision, constraints, predicate, acceptor | DSSE, in-toto | signet |
| Capability references | permitted actions and resources | signet | signet |
| Content addresses | task, inputs, outputs, verification roots | LLO | ley-line |
| Interlace receipts | that execution was admitted | ADR-014 / RECEIPTS.md | cloister |
| Acceptance statement | whether the evidence satisfies the predicate | **does not exist** | — |

The last row is not an oversight. Verified against the APAS spec: `acceptor`
and `acceptance` appear **zero** times. The layer everyone reaches for is
genuinely absent, which is why `notme-8eb592` exists.

### Keep the certificate compact

Issuer and subject keys, ownership linkage, validity, delegation budget, scope
attenuation, key binding, and a **digest** of the task statement. Rich
semantics belong in the signed statement, not the certificate.

Certificates are poor containers for semantics: they are size-sensitive, every
field widens the parsing surface, revocation granularity is the whole
certificate, and each addition is something every X.509 verifier must tolerate.
A digest costs 32 bytes and moves the semantics somewhere they can evolve
without a certificate profile change.

## Two clarifications, without which this constraint is wrong

### Composition surface is not verification surface

An earlier phrasing had notme "present and verify" the whole graph. **Verifying
it would defeat Goal Zero criterion (D).** A third party verifying *without
trusting notme at the moment of the check* cannot get there by trusting notme's
verification instead of its issuance — that is the same dependency wearing a
different hat.

notme makes the graph **walkable**: every node carries the digest of the next,
and references are self-contained. Each verifier then walks the parts it cares
about, offline. There is a practical argument too — verifying everything would
require notme to understand DSSE, in-toto, LLO addressing, Interlace receipts
and capability semantics, so a format change in any of five systems would break
the authority.

### Task state is not grant state

"No completion state machine" is correct about **tasks**:
`submitted → verified → accepted` belongs to rosary or to the human, not here.

It must not be read as forbidding **grant** state. Grant lifecycle *is*
revocation, and Goal Zero criterion (C) requires exactly that. notme owns
`issued → revoked` for what it issues, and nothing else. Read without this
distinction, the constraint would forbid the revocation unit the epic demands.

## The unresolved joint: DSSE ↔ X.509

DSSE signatures carry `keyid` and `sig`. in-toto references subjects by digest.
The certificate path yields a key carrying a WIMSE identity. **Nothing binds
"this DSSE keyid is that certificate's subject key."**

Sigstore solves it by embedding the certificate in the bundle. notme has no
equivalent rule, so "the bridge or task key signs that statement" currently has
no wire format — and it is the first thing an implementer hits. This must be
pinned before any acceptance or attestation work; see `notme-8eb592`.

## What this rules out, concretely

Recorded because each was proposed at some point in the design conversation:

- A notme-specific task store or bead mirror. rosary owns task state.
- A "promise token" or bespoke completion credential. Acceptance is a grant
  (ADR-019), expressed with the credentials that already exist.
- A notme hash-chain or transparency format of its own invention.
  `notme-907299` targets the **Static CT API** — tiled, existing tooling — not
  RFC 6962, whose logs shut down 2026-02-28, and not something new.
- A parallel attestation format alongside in-toto. The gap in-toto leaves is
  the delegation chain and the represented principal; **extending** its
  functionary model is a stronger position than standing beside it.

## What this does NOT rule out

Application-level **vocabulary** — an APAS predicate schema, a scope name, a
capability URI shape — is not a cryptographic primitive and is not forbidden.
The line is between defining *what a field means* (allowed, and unavoidable)
and defining *how bytes are signed, chained, or verified* (forbidden, because
those already exist).

## External alignment

NIST's NCCoE concept paper *"Accelerating the Adoption of Software and AI Agent
Identity and Authorization"* (Feb 2026) proposes exactly this posture —
adapting OAuth 2.0/OIDC, SCIM, SPIFFE/SPIRE and ABAC to agents rather than
minting new mechanisms. Its four dimensions are identification, authorization,
auditing and **non-repudiation**, the last defined as *"accountability that
links agent actions to the human authority that sanctioned them."*

Worth noting precisely because it supports this ADR *and* limits it: the
proposed stack does **not** close the non-repudiation dimension it names. OAuth
binds delegation at authorization time and retains nothing after; SPIFFE issues
a workload identity with no delegation chain. So composing existing primitives
is right, and it will not be sufficient on its own — the delegation chain is
the part nobody else carries, and it is the part notme legitimately adds.

## Consequences

Every future proposal in this repo has a first question: **which existing
standard already does this, and why is it insufficient?** A design that cannot
answer it is not ready, and "it would be simpler to define our own" is not an
answer — it is the cost being moved from notme onto every consumer.

## Open questions

1. **How is the DSSE↔X.509 binding expressed?** Embed the certificate
   Sigstore-style, or a keyid derivation rule. Blocks `notme-8eb592`.
2. **Is `did:web` worth adopting** as an identifier form? It requires no
   ledger, and `/.well-known/` already serves the shape it needs. The W3C
   Verifiable Credentials issuer/holder/verifier separation and its
   offline-presentation semantics are the parts worth borrowing — **not** the
   self-sovereign framing, which does not describe an authority that mints
   credentials, and not the ledger-anchored DID methods.
3. **Does this ADR bind signet and cloister**, or only notme? It is written as
   notme's constraint; the layer table asserts ownership that those repos
   should confirm rather than inherit.
