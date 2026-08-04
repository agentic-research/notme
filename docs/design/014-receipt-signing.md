<!--
@doc-check
@types: CertScope
-->
# ADR-014: Receipt signing without a signing oracle

**Status:** Accepted (2026-08-03)
**Bead:** notme-c1b7fd
**Relates to:** cloister's Interlace 0.2.0 `RECEIPTS.md` §2.1/§2.4 (the wire contract this serves), notme-6ad276 / PR #54 (the "derive, never receive" invariant this reuses), notme-d87ef2 (`/internal/sign-jwt`, same hazard class, still unbuilt)
**Standards:** RFC 8032 (Ed25519), RFC 8949 §4.2 (Core Deterministic Encoding)

## The ask

> `POST /internal/sign-receipt` — in: canonical commitment bytes (cloister
> computes them); out: raw Ed25519 signature, signed with the SigningAuthority
> master. Sign-only — no operation returns key material. Caller-authenticated
> via service binding; `/internal/` must not be externally routable.

Cloister today reads a `RECEIPT_SIGNING_KEY` from its own env. Moving the key
into notme is the right direction. Implemented literally, though, the ask
produces something considerably worse than the problem it solves.

## Why the literal reading is a CA compromise

The SigningAuthority master Ed25519 key signs three things today:

1. X.509 certificates — Ed25519 over the DER `TBSCertificate`.
2. Access tokens — Ed25519 over `base64url(header).base64url(payload)`.
3. CA bundles — Ed25519 over canonical CBOR (`bundleCanonical`).

Interlace receipts would be a fourth, and the spec signs the commitment CBOR
**with no domain separator**:

```
signature = Ed25519_Sign(A.master_sk, commitment_cbor)
```

An endpoint that signs arbitrary caller-supplied bytes with that key is a
universal forgery oracle for all four formats. A caller submits a crafted DER
`TBSCertificate` as "commitment bytes", receives a signature, and assembles a
certificate that chains to the authority — for any identity, any scopes.
`derive-credentials.ts` verifies certs against this exact key, so the forged
cert passes. That is total compromise of the CA, reachable by anyone who can
call the endpoint.

**Domain separation does not rescue this.** Prefixing the signing input would
work cryptographically, but Interlace verifiers (`P` live, `V` at audit)
compute over `commitment_cbor` directly and resolve the key via `actor_fp =
SHA-256(master pubkey)`. Both the bytes and the key are pinned by a spec
notme does not own. Changing either breaks every verifier in the ecosystem.

**A separate signing key does not rescue it either**, for the same reason:
`actor_fp` binds the receipt to the master identity, and `.well-known` resolves
it. It must be the master key.

## Decision

Two changes to the ask, both load-bearing.

### 1. Not a fetch route — an RPC entrypoint

`ReceiptSigner extends WorkerEntrypoint`, reached as
`env.NOTME_RECEIPTS.signReceipt(...)` over a DEDICATED binding (see integrator
notes).

The ask says `/internal/` "must not be externally routable." The existing
`/internal/ca-bundle` (worker.ts) does not achieve that — it is a plain fetch
route registered *before* host enforcement, so `https://notme.bot/internal/ca-bundle`
answers from the public internet. That is fine for a public CA bundle and a
trap for anything else. The bead points at it as the pattern to follow; this
ADR explicitly declines to.

There is no header, secret, or `request.cf` check that reliably distinguishes
a service-binding fetch from an internet request, and a CA key is not the
place to bet on one. An RPC method has **no URL at all** — non-routability is
structural rather than enforced. A dedicated entrypoint rather than a method
on `AuthService` keeps least privilege: a binding to `ReceiptSigner` grants
receipt signing and nothing else.

Cost: cloister adds a **dedicated** binding. Not an `entrypoint` on an
existing one — see the integrator notes below, where an earlier version of
this ADR got that wrong in a way that would have broken identity traffic.

### 2. Not a signing oracle — parse, re-encode, then sign our own bytes

`signReceipt` never signs the bytes it is handed. It:

1. Decodes them as CBOR.
2. Validates the map has **exactly** the eight `RECEIPTS.md` §2.1 keys, with
   the right major types and byte lengths.
3. **Derives** `actor_fp` and `epoch` rather than accepting them (below).
4. Canonically **re-encodes** (RFC 8949 §4.2).
5. Requires the re-encoded bytes to equal the input **byte for byte**, and
   rejects otherwise.
6. Signs the re-encoded bytes.

Step 5 is what makes step 6 safe. The signature is only ever over bytes notme
constructed from a structure it validated. A DER certificate fails at (1) or
(2). A JWT signing input is ASCII and fails at (1). Non-canonical CBOR — the
obvious smuggling route, where a caller hides attacker-chosen bytes in
indefinite-length encodings or non-shortest integers — fails at (5).

The equality check also gives the caller a real guarantee: a receipt notme
signed is canonically encoded, so a verifier recomputing the digest gets the
same answer. Cloister's own encoder is checked rather than trusted.

### `actor_fp` and `epoch` are derived, never received

This is the notme-6ad276 invariant again, in a new place. Both fields are
facts about **notme**, not about the caller:

- `actor_fp` is `SHA-256(A's master pubkey)`. notme holds that key. A caller
  asserting it could mint receipts attributed to a different actor.
- `epoch` is the authority's current key epoch. A caller asserting it could
  produce a receipt that resolves against a different (perhaps retired) key.

So notme computes both and rejects any commitment disagreeing with them,
rather than signing what it was told. The wire shape is unchanged — a correct
caller sends correct values and nothing happens — but a lying one is refused
instead of served.

## What is deliberately not built

- **No `/internal/sign-jwt`** (notme-d87ef2). Identical hazard class and it
  should get the same treatment, but it is a separate contract with a
  separate consumer; bundling them would hide one behind the other.
- **No key material export, ever.** `signReceipt` returns a signature and an
  epoch. `CryptoKey` is not Structured Cloneable and cannot cross the RPC
  boundary regardless — that is a property of the platform, not a check we
  perform, and it is worth not undermining by adding an export path later.
- **`/internal/sign-receipt` as an HTTP path is explicitly refused**, not
  merely absent, so a caller following the bead's original wire shape gets a
  clear 404 with a pointer instead of falling through to the asset handler.


## Integrator notes (answers to cloister's questions, cloister-35ccf7)

### The binding must be its own — CORRECTED

An earlier draft said "add `entrypoint = "ReceiptSigner"` to your `NOTME`
binding." **That instruction would have broken the first integrator to follow
it**, and cloister caught it with the evidence: `NOTME` is live for the
`/identity/*` fetch proxy (cloister `config.capnp:207`, typed `Fetcher` at
`types.ts:113`). Setting `entrypoint` on a binding routes its `fetch()` to
that entrypoint, and `ReceiptSigner` has no `fetch` handler — identity traffic
would have gone to a class that cannot serve it.

Declare a second binding to the same service:

```capnp
( name = "NOTME_RECEIPTS",
  service = "notme-bot",
  entrypoint = "ReceiptSigner" ),
```

leaving `NOTME` exactly as it is.

### 1. Is `receiptFacts()` on the same entrypoint?

Yes. Both `receiptFacts()` and `signReceipt()` are methods on `ReceiptSigner`,
so **one** dedicated binding covers both.

### 2. The full error-code set

Exported as `CommitmentErrorCode` from `worker/src/receipts/commitment.ts`, so
a `switch` gets exhaustiveness from the compiler rather than from a guess:

| Code | Meaning | Retryable |
|---|---|---|
| `EMPTY_INPUT` | zero-length input | no |
| `NOT_CBOR` | undecodable — where DER certs and JWT signing inputs land | no |
| `NOT_A_MAP` | decoded to something other than a CBOR map | no |
| `WRONG_KEY_COUNT` | not exactly 8 keys | no |
| `MISSING_KEY` | a required key absent | no |
| `FIELD_NOT_BYTES` | byte-string field wasn't one | no |
| `FIELD_NOT_UINT` | uint field wasn't a non-negative integer | no |
| `FIELD_WRONG_LENGTH` | digest field not exactly 32 bytes | no |
| `NONCE_TOO_SHORT` | `nonce` under 16 bytes | no |
| `STATUS_NOT_2XX` | `status` outside 200..299 | no |
| `TIMESTAMP_OUT_OF_RANGE` | outside ±300s of the authority clock | no* |
| `ACTOR_FP_MISMATCH` | `actor_fp` isn't this authority's | no |
| `EPOCH_MISMATCH` | `epoch` isn't current | **YES — once** |
| `NOT_CANONICAL` | bytes aren't the canonical encoding of the structure | no |

\* not retryable *unchanged*; a caller whose clock has drifted must correct it,
not resubmit.

`RETRYABLE_CODES` is exported alongside, and contains exactly
`EPOCH_MISMATCH`. **Fail closed on any code you do not recognise** — the set
can grow.

### 3. What crosses the wire

`signReceipt(commitmentBytes)` → `{ ok: true, signature, epoch }`, where
`signature` is the **raw 64-byte Ed25519 signature**. Not an envelope.

Deliberate: cloister already owns a `ReceiptEnvelope` encoder, and a second
one here would be two implementations of a single wire format — which is
precisely how canonical encodings drift apart. notme signs; the caller
assembles.

### 4. `actor_fp` comes back already hashed

`receiptFacts()` returns `actorFp` as the 32-byte **SHA-256 of the raw Ed25519
master public key** — drop it into the commitment verbatim.

Returning the pubkey instead would hand the caller a derivation that notme
then validates against, recreating exactly the drift this method exists to
kill. The hash is computed on the enforcing side, once.

### 5. Caching and invalidation

`receiptFacts()` is cacheable and **should** be cached — it is a DO round-trip
and would otherwise run on every proxied response.

Only two things invalidate it:

1. **`EPOCH_MISMATCH` from `signReceipt`.** This is the signal. Re-read, retry
   once.
2. **An explicit `rotate()`**, which is an operator action over admin RPC.

No TTL is needed and polling is the wrong shape: `alarm()` calls
`generateBundle()`, never `rotate()`, so the epoch does not move on a timer.
(An earlier version of this ADR and a code comment both said rotation was
"alarm-driven" — that was drift; corrected.)

### Bound the retry — one attempt

Re-read facts and retry **at most once**, then surface the code.

Rotation can move again between the re-read and the retry, so an unbounded
loop can flap. This call sits in a `finally` on cloister's response path,
where spinning would stall a proxied request that already succeeded upstream.
A receipt is evidence about a response that has already been served; failing
to attach one must never cost the response itself.
