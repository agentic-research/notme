<!--
@doc-check
@types: CertScope
-->
# ADR-016: Rules for any surface that signs with an authority key

**Status:** Accepted (2026-08-04) — **normative**
**Supersedes nothing; generalizes** ADR-014 (receipt signing) and ADR-015 (delegated JWT signing)
**Prompted by:** cloister, who pointed out that the same refusal had now happened twice and lived nowhere reusable

## Why this exists

Two consumers asked for a signing endpoint. Both specs were, as written, a
compromise of the certificate authority. Both were refused for the same
reason, and each refusal was recorded only inside the ADR for that one
feature:

- **`/internal/sign-receipt`** (ADR-014) — "sign these commitment bytes with
  the master key" is a universal forgery oracle: submit a crafted DER
  `TBSCertificate`, get a signature, assemble a certificate that chains to
  this authority for any identity and any scopes.
- **`/internal/sign-jwt`** (ADR-015) — "sign this JWS input with the master
  key" is worse: notme's own access tokens are `at+jwt` signed by that key,
  and `verifyAccessToken` leaves `issuer` unchecked by default, so the caller
  mints a token every notme resource server accepts.

Cloister recorded the first refusal in their own source and did not
generalize it, which is exactly why the second request was written the same
way and sat unmigrated until it 404'd. Their words: *"the rule is clearly
load-bearing and clearly reusable; if it lived somewhere normative on your
side rather than in two separate refusals, a third instance would not need
discovering."*

So this is the normative version, and `signing-surfaces.do.test.ts` enforces
the mechanical parts. A rule that only exists as prose gets rediscovered.

## The rules

### 1. A signing surface is never a fetch route

`/internal/` is **not** a private namespace. `/internal/ca-bundle` is
registered before host enforcement and answers from the public internet — fine
for a public CA bundle, catastrophic for anything that signs.

No header, shared secret, or `request.cf` inspection reliably distinguishes a
service-binding fetch from an internet request, and an authority key is not
the place to bet on one. Use a `WorkerEntrypoint` RPC method: it has no URL,
so non-routability is **structural rather than enforced**.

Refuse the HTTP path explicitly rather than leaving it absent, so a caller
built against an older spec is told where it went instead of falling through
to the asset handler.

### 2. One dedicated binding per signing entrypoint

Never add `entrypoint = "..."` to an existing plain service binding. Setting
`entrypoint` routes that binding's `fetch()` to the named class — so pinning
it on a binding already used as a fetch proxy silently redirects that traffic
to a class with no `fetch` handler.

ADR-014 originally told integrators to do exactly this on cloister's `NOTME`
binding, which is live for the `/identity/*` proxy. Cloister caught it before
anyone followed it.

A dedicated entrypoint is also least privilege: a binding to `ReceiptSigner`
grants receipt signing and nothing else. That claim is only true if it is
tested — see `rpc-surface.do.test.ts`.

### 3. Never sign bytes a caller handed you

The authority signs what it constructed from a structure it validated, never
the caller's buffer. Two ways to get there, and **which one is available is
decided by whether something external pins the signable set**:

| The format is… | Then… | Instance |
|---|---|---|
| **Closed** — an external spec fixes the fields | Decode → validate → canonically re-encode → **require byte-for-byte equality with the input** → sign | ADR-014 receipts (RECEIPTS.md pins eight fields) |
| **Open** — arbitrary claims are the point | You cannot close it. Use a **separate key** so the output is cryptographically unrelated to anything else this authority signs | ADR-015 JWTs (a JWT payload has no schema) |

Do not attempt the first on an open format. Validating claims you have no
basis to judge **looks like a control while being none** — it leaves a
reviewer believing the authority vets what it signs, when the caller simply
picks values that pass.

### 4. Facts about the authority are derived, never received

Anything the payload asserts *about this authority* — `actor_fp`, `epoch`,
`iss`, `kid` — is computed here and the request is rejected if it disagrees.
A caller asserting them can attribute output to another actor, pin it to a
retired key, or impersonate the issuer.

This is notme-6ad276's invariant ("identity and scopes are DERIVED, never
RECEIVED"), which has now been the answer three times.

### 5. Return a result union, not a throw

`{ ok: true, … } | { ok: false, code, message }` with `code` an **exported
union type**, so a caller's `switch` gets exhaustiveness from the compiler.

An RPC rejection surfaces as an uncaught exception in the callee's context —
enough to fail a test run — and stringifies the error, leaving a caller
nothing but message text to branch on. Export which codes are retryable
alongside, so a caller cannot infer retryability by pattern-matching a name.

### 6. Return the signature, not the envelope

Raw signature bytes. The caller assembles the compact JWS, the receipt
envelope, the certificate chain. Two implementations of one wire format is how
canonical encodings drift apart — and when they do, the failure is an opaque
verification error with nothing pointing at encoding.

### 7. Test the interop against the real counterparty

A fixture built with the encoder under test is a **fixed point**, not a
conformance check: any self-consistent implementation satisfies it, including
a wrong one. Pin against the spec's own vectors, or against bytes the actual
counterparty produced.

This is not hypothetical. ADR-014 shipped with 17 green tests over a
`timestamp_ms` encoded as a float64 — forbidden outright by RECEIPTS.md §3.1 —
because every fixture came from the same encoder being validated. It was found
by running cloister's real output through notme's validator.

## Applying this to a new request

1. Is it a fetch route? → make it an RPC entrypoint (rule 1), with its own
   binding (rule 2).
2. Is the format closed or open? → re-encode-and-compare, or separate key
   (rule 3). Get this one wrong and the rest does not save you.
3. What does the payload claim about *us*? → derive it (rule 4).
4. Shape the result and the errors (rules 5, 6).
5. Get a vector from the counterparty before believing the tests (rule 7).
