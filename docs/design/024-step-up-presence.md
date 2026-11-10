# ADR-024: Step-up presence is a certificate notme mints for one action

**Status:** proposed (2026-11-09)
**Beads:** `notme-070b21` (this decision); related: `notme-8eb592` (a human
acceptor cannot sign DSSE), `notme-bdeeb5` (mint path phase 4: deploy
approval from a phone), `notme-1b46a8` (issuance log)
**Composes:** the mint-path spec (`docs/superpowers/specs/2026-10-28-mint-path-design.md`,
§5.5 criteria, §6 `deploy/1`), ADR-019 (delegation authority), ADR-020
(compose, do not invent); signet ADR-004 (bridge certificates), ADR-009
(presence-gated signer), ADR-011 (`sigpol` policy bundles)

## Context

notme has passkeys, but no way to say "the principal re-confirmed presence,
just now, for this action". Policy wants that for high-risk actions ("touch
your security key before this deploy"). *Beyond Zero* (Valente and
Zalewski, arXiv 2605.22985) names it in §4.4 as a policy-linked challenge,
and in §6.2 asks that agent actions be attributable to an agent, a
controlling user and a task.

**The gate on this ADR** was "codify what the demo proves, do not design
ahead of it". The demo ran in session on 2026-11-04 against production:
a notme cert issued and then verified offline with `signet verify` (v0.3.1)
against the notme root. What that run proves, and what this ADR builds on,
is that a notme-minted X.509 credential is checkable by a third party with
nothing but the root. Nothing in the demo exercised presence. That is the
gap.

### What already exists

- **`deploy/1`** (mint-path §6, `worker/src/criteria.ts`): an
  authority-minted criteria, 900 s, no renewal. Its approval is a WebAuthn
  assertion whose challenge is a hash of **that exact request**, so the tap
  cannot approve a different one. That is a step-up proof for one action
  type, designed but not yet minted.
- **Passkey verification** (`worker/src/auth/passkey.ts`) runs with
  `userVerification: "preferred"`.
- **`.1.9` task scope**: task id plus goal hash. **`.1.10` criteria**:
  `task ⊆ tier`, checked by `checkCriteria` at mint and by verifiers.
- **signet ADR-009** puts presence on the *signing key* (a Secure Enclave
  key that only signs after Touch ID). That proves presence to whoever holds
  the key's public half. It does not travel to a third party on its own.
- **signet ADR-011 (`sigpol`)** distributes policy as signed bundles:
  subjects, groups, capability tokens, `maxCertTTL`. It has no field for
  presence.

### Why a raw WebAuthn assertion is not the proof

A verifier holding an assertion still needs the credential's public key,
the RP ID, the expected origin and the challenge's preimage. Only notme
holds the credential key. Shipping raw assertions would make every verifier
a WebAuthn relying party for notme's credentials. It is the same mismatch
`notme-8eb592` records for DSSE: a WebAuthn assertion signs
`authenticatorData ‖ SHA-256(clientDataJSON)`, not an arbitrary payload.

## Decision

### D1. The proof is a certificate notme mints after verifying the assertion

notme verifies the assertion online and mints a short-lived certificate
that states the result. The certificate is the portable, offline-checkable
proof. notme is the verifier of record for the assertion. This is
`deploy/1`'s mechanism, generalised. `deploy/1` becomes its first instance,
not a separate mechanism.

New criteria **`step-up/1`** in `criteria.ts`:

| field | value |
|---|---|
| `mintedBy` | `authority` (online; a tier cannot mint it) |
| `maxLifetimeS` | 300 |
| `scopeCeiling` | `bridgeCert` only |
| renewal | none |
| `grantable` | false (never offered at `/enroll`) |

### D2. The challenge is the action, so one tap approves one action

```
action    = canonical CBOR (RFC 8949 §4.2; ADR-010 makes it the signing
            input everywhere) of
            { type, params, task_id, requester_spki_sha256, nonce }
challenge = SHA-256("notme-step-up-v1:" ‖ action)
```

- `type`/`params` name the action (`deploy`: commit and environment).
- `task_id` and `requester_spki_sha256` tie it to one task and one key.
- `nonce` is the requester's, so two identical actions get two approvals.

The approval page shows `type`, `params`, the requesting agent's identity
and a short matching code also shown to the requester (mint-path §6:
number matching against push fatigue). Delivery is §6's Web Push flow.

### D3. The certificate certifies the task's key, so it attaches to the task

A step-up certificate's subject public key is the **requesting task
certificate's key** (`requester_spki_sha256` must match the key in the
request). No new key exists. A guarded action presents:

1. the task certificate (root → tier → task, minted offline by the path);
2. the step-up certificate (root → step-up, minted online by notme),

and the verifier checks that both carry the same SPKI and the same `.1.9`
task id. The task chain says *who and which task*; the step-up certificate
says *a human re-confirmed this action*. Neither alone suffices, and a
copied step-up certificate is useless without the task key.

### D4. What the certificate carries

- `.1.1` subject: the requesting agent's identity, as on its task cert.
- `.1.9` task scope: the task id; goal hash = SHA-256 of `action` (D2).
- `.1.10` criteria: `step-up/1` (or `deploy/1` for that type).
- **`.1.11` approval** (new, allocated in the `cert-authority.ts` registry
  and moving with the arc to the PEN, `notme-229dc3`; checked free in
  signet, ley-line-open and cloister on 2026-11-09):

  ```asn1
  Approval ::= SEQUENCE {
    approver     UTF8String,        -- principal id of the human
    method       UTF8String,        -- "passkey-uv" | "passkey-up"
    assertedAt   GeneralizedTime    -- when the assertion verified
  }
  ```

  Non-critical, like every notme extension: enforcement is in verifiers.
- `.1.4` epoch, `.1.2` issuance time, `.1.8` principal kind: as today.

This is the attribution *Beyond Zero* §6.2 asks for: agent (`.1.1`),
controlling user (`.1.11 approver`), task (`.1.9`).

### D5. User verification is required unless policy says presence only

A step-up ceremony sets `userVerification: "required"` and records `UV` in
`method`. Login stays at `"preferred"`. A policy may accept `passkey-up`
(touch only) for keys without a PIN. The default is `passkey-uv`, and
notme refuses to mint `passkey-uv` when the authenticator's UV flag is
clear.

### D6. Policy demands it through sigpol; notme enforces at mint

`sigpol` gains a presence requirement keyed by capability token or by
action type (a signet change, filed there):

```cddl
? 5: { * tstr => presence-req },   ; group: action type → requirement
presence-req = { 1: tstr,          ; method: "passkey-uv" / "passkey-up"
                 2: uint }         ; maxAge: seconds since assertedAt
```

- **notme** refuses to mint a certificate for a guarded action type
  without a step-up, and refuses a step-up whose method is weaker than
  policy.
- **Verifiers** (signet, LLO's wasm) refuse a guarded action unless a
  step-up certificate passes D7.

Until sigpol carries it, notme's own policy is the interim source:
`deploy` requires `passkey-uv` with `maxAge` 300.

### D7. Offline verification

Given the task certificate, the step-up certificate, the canonical action
and the notme root, a verifier:

1. chains both certificates to the root (the step-up certificate is signed
   by the root directly, as bridge certificates are today);
2. checks `.1.10` is `step-up/1` (or the action's specific criteria) and
   `checkCriteria` passes;
3. recomputes SHA-256 of the canonical action and compares it to `.1.9`'s
   goal hash; compares task ids and SPKIs (D3);
4. checks `.1.11 method` meets policy, and that
   `assertedAt + maxAge ≥ the action's time`;
5. checks revocation by epoch (`.1.4`), as for every notme cert.

No network calls. The raw assertion (credential id, authenticatorData,
clientDataJSON, signature) is kept in notme's issuance record, and in the
issuance log once `notme-1b46a8` is live, for audit, not for verification.

### D8. Lifetime and replay

300 s, no renewal, one action: the goal hash fixes the action, and the
requester's nonce makes each approval distinct. Replaying a step-up
certificate inside its window replays the same action by the same task
key. A verifier guarding a non-idempotent action records the step-up
serial as spent, as receipts do (mint-path §5.4).

## Composition with signet ADR-009

A presence-gated signing key (Secure Enclave plus Touch ID) proves
presence to the machine. A step-up certificate proves it to anyone holding
the notme root. They compose: a machine tier whose key is
presence-gated still needs a step-up certificate for a guarded action.
The tier's gate is local and the policy is not.

## Composition with notme-8eb592 (human acceptance)

The same primitive answers it. Set `type = "accept"`,
`params = { statement_sha256 }`, and the step-up certificate attests that
the human approved exactly that DSSE payload. The certificate's key signs
the DSSE envelope (it is the task key, D3). Whether acceptance uses
this, or notme counter-signs the statement, is decided on that bead.

## Consequences

- One new extension (`.1.11`), one new criteria, no new key type.
  `deploy/1` (phase 4) is built on this, not beside it.
- Verifiers gain a two-certificate check for guarded actions. The task
  path stays offline, and only the step-up is online, which is inherent:
  presence is a fresh human act.
- A cross-repo change in signet (sigpol field, verifier check), filed
  there.

## Not decided here

- Which action types beyond `deploy` and `accept` are guarded: policy's
  call, per deployment.
- The approval window ("may deploy this repo for 1 h"): mint-path §6's
  break-glass option, unchanged.

## Implementation beads (filed with this ADR)

1. notme: `.1.11` encoding and registry entry, the `step-up/1` criteria, a
   request/approve/mint flow with `userVerification: "required"`, and the
   D7 checker in `criteria.ts`. Tests: wrong action digest, SPKI mismatch,
   UV clear under `passkey-uv`, expired `maxAge`, and a step-up for
   another task id, each refused with a positive control.
2. signet: the `sigpol` presence field and the verifier check (D6, D7).
