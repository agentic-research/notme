<!--
@doc-check
@endpoints: POST /cert, POST /cert/gha, POST /cert/passkey
-->
# ADR-021: Registration is a policy question, and the answer is a bundle

**Status:** accepted (2026-08-30)
**Beads:** `notme-2c4209` (this decision), `notme-77438b` (the identity it
registers), `notme-addef9` (how the first one gets in)
**Serves:** `notme-bed754` criterion (B)'s registration clause
**Composes:** signet ADR-011 (trust policy bundles / `sigpol`)

## Context

Until 2026-08-30, only the *first* user needed anything. Everyone else
registered a passkey freely, received a session carrying `bridgeCert`, and
exchanged it at `/cert/passkey` for a real CA-signed certificate pair.

That is an **open-registration certificate authority**, and it was recorded
nowhere except an inline comment reading *"Everyone else can register freely
— gets bridgeCert scope only"*. Meanwhile the invite system
(`POST /invites` → `/join`) existed and implied the opposite. Shipping a CA
whose registration policy exists only as a comment is deciding by omission,
which is the failure this ADR exists to end.

Rate limiting bounds the *rate* of abuse. It does not answer the question.

## The question, as signet already asked it

signet ADR-011 §2 lists three questions an authority must answer, and names
the third as the one it cannot:

> 1. "Does this request prove possession of a private key?"
> 2. "Has this key been revoked?"
> 3. **"Is this OIDC subject allowed to get a certificate in the first place?"**

Question 3 *is* `notme-2c4209`. Two repos found the same gap from opposite
sides, which is the strongest available evidence that it is real and that it
should have one answer rather than two.

## Decision

**Registration is gated. The gate is a policy decision about a subject, and
notme does not own the subject registry.**

Three parts, in the order they bind:

### 1. The eventual gate is the trust policy bundle (`sigpol`)

signet ADR-011 §5.3 specifies exactly the check notme needs, in the
certificate issuance path:

```
subject, err := policyChecker.GetSubject(ctx, claims.Subject)
  → SubjectNotProvisioned  → refuse
  → !subject.Active        → refuse
caps := policyChecker.ResolveCapabilities(subject.Groups)
```

Provisioned by SCIM, compiled into a signed, versioned bundle, distributed
over the same transport as the CA bundle, verified with the same signature,
seqno-monotonicity and epoch checks notme already implements for revocation.

**notme MUST NOT grow a second subject registry to answer this.** ADR-011
§2.1 argues that case ("Why Not Just a User Database?") and ADR-020 forbids
it here: a parallel answer to "who exists" is precisely the invention that
moves cost onto every consumer.

### 2. The gate TODAY is an invite

`sigpol`'s compiler and checker ship in signet's `pkg/policy/`; its SCIM
endpoints and bundle distribution do not. So the interim mechanism is the
invite flow that already exists and is already tested:
`POST /auth/passkey/register/options` requires a valid, unexpired,
single-use invite for every user after the first.

**Scopes come from the invite, never from the request.** A caller that could
name its own scopes would make the gate decorative — the same reason
`/cert/gha` hardcodes its scopes and `canGrant` refuses to pass on authority
the granter does not hold.

This is an interim *mechanism*, not an interim *decision*. Both answers say
registration is gated; they differ only in who supplies the policy.

### 3. Which KINDS may self-register is a separate axis

ADR-019 D2 makes this askable by putting `principal_kind` in its own
extension, and the answer differs by kind:

| Kind | May self-register? | Gate |
|---|---|---|
| **human** | no | invite today, `sigpol` subject when it lands |
| **workload** | yes, by attestation | `/cert/gha`: a GitHub-signed OIDC token plus `GHA_ALLOWED_OWNERS` — already a policy gate, and already enforced |
| **agent** | no — it is *delegated*, not registered | the Issuing CA tier (ADR-019 D4); its authority is bounded by its parent, not by a registration |
| **organization** | n/a | not minted as a credential holder today |

Worth stating because it explains why the workload path looks ungated and
is not: attestation *is* the gate there, and it has been since `/cert/gha`
shipped. "Open registration" was only ever true of the human path.

## De-authorization, which the decision is incomplete without

A registration policy that cannot be reversed is half a policy. As of
`notme-77a024` (2026-08-28) it can be:

- capability grants are the revocation unit — `POST /principals/:id/revoke`
- **every** authority gate reads the grant store live (`liveScopes`), so a
  revocation takes effect on the target's next request, not at cookie expiry
- passkey users are principals with grants; `passkey_users.is_admin` no
  longer decides anything after enrollment

Before that, revoking a grant did nothing to a passkey user — so this ADR
could not have been written honestly, whichever way it decided.

## Consequences

- An operator must issue an invite to onboard a human. `GET /invites` is the
  page for it; `notme-4838ae` is the reason a second admin credential is
  worth having before you need one.
- Anything that assumed open registration breaks loudly (403), not quietly.
- When `sigpol` lands, the invite becomes one provisioning path into the
  bundle rather than a separate mechanism to retire — the decision does not
  change, only its source of truth.

## What this does NOT decide

Whether notme should *run* SCIM endpoints, or consume a bundle signet
publishes. That is a boundary question for signet ADR-011's authors, and
naming it here would be notme deciding another repo's shape — the mistake
ADR-020 §"Composition surface is not verification surface" warns about.
