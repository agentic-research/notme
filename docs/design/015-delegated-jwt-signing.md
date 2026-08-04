<!--
@doc-check
@types: CertScope
-->
# ADR-015: Delegated JWT signing on a separate key

**Status:** Accepted (2026-08-04)
**Bead:** notme-d87ef2
**Relates to:** ADR-014 (receipt signing — same hazard class, different resolution), notme-6ad276 (derive-never-receive), cloister `src/routes/well-known-identity.ts` (`/oauth/token`, `/.well-known/jwks.json`)
**Standards:** RFC 7515 §3.1 (JWS signing input), RFC 8037 (EdDSA in JWK/JWS), RFC 9068 (`at+jwt`)

## The ask

> `POST /internal/sign-jwt` — `{alg, header_b64, payload_b64}`. Decode the
> header, verify `alg === "EdDSA"`, sign `header_b64 + "." + payload_b64` with
> the master Ed25519 key, return `sig_b64`.

Cloister mints OAuth tokens at `/oauth/token` and deliberately does not
re-import a signing key. Delegating the signature is right. Signing whatever
it sends, with the master key, checking only `alg`, is a **complete
authentication bypass of notme itself** — not merely a forgery oracle.

## Why this is worse than ADR-014

notme's own access tokens are `at+jwt`, `iss: https://auth.notme.bot`, signed
with the master Ed25519 key (`worker/src/auth/token.ts`). A caller of a
blind-signing endpoint submits:

```json
{"typ":"at+jwt","alg":"EdDSA","kid":"<notme's kid>"}
{"iss":"https://auth.notme.bot","sub":"anyone","scope":"authorityManage","aud":"https://auth.notme.bot"}
```

and receives a valid signature. That token verifies against
`/.well-known/jwks.json`, so **every notme resource server accepts it**, with
any subject and any scope. Worse, `verifyAccessToken`'s `issuer` option is
optional and unchecked by default — a deliberate choice so the SDK works
against self-hosted deployments — so most verifiers will not even notice the
issuer is being impersonated.

Receipts (ADR-014) could be made safe on the shared key because the Interlace
spec pins an eight-field schema: validate the structure, re-encode, compare,
and the signable set is closed. **A JWT payload has no such schema.** It is an
open JSON object by design. There is no equivalent of "re-encode and compare"
that leaves a useful token-issuance surface, because the useful surface *is*
arbitrary claims.

So the resolution has to be different.

## Decision

### 1. A separate key per delegated issuer — this is the load-bearing part

notme generates and holds a distinct Ed25519 keypair for each delegated
issuer. The CA master key never signs a delegated JWT.

This is available precisely because, unlike receipts, nothing pins the key.
Cloister's JWKS handler publishes whatever public key its
`manifest.actor.pubkeyBinding` holds, and derives `kid` from the manifest
fingerprint rather than from the key — so it is already indifferent to which
key it publishes. It just needs a public key notme holds the private half of,
which was the actual requirement all along ("cloister deliberately does not
re-import the master key").

What separation buys, that no amount of claim validation can:

- A token signed for cloister **cannot** verify against notme's JWKS. Wrong
  key. Not "wrong claims that we hope someone checks" — cryptographically
  unrelated.
- Compromise of cloister's issuance path cannot mint a notme credential, and
  vice versa. The blast radii stop being the same radius.
- Revocation is per-issuer. Retiring cloister's key does not rotate the CA.

### 2. Claim validation anyway — defence in depth, not the primary control

A separate key already closes the bypass. These are cheap and close the
remaining self-inflicted footguns:

- `alg` must be `EdDSA`. One algorithm, no negotiation surface.
- `kid`, if present, must be the delegated key's. A caller must not be able to
  advertise notme's `kid` and have a verifier fetch the wrong key.
- `typ` must **not** be `at+jwt`. That type is notme's own access token
  (RFC 9068); reserving it keeps the two token families distinguishable to a
  human reading a decoded token, not just to a verifier checking a signature.
- `cnf` is rejected. A delegated issuer must not mint DPoP-bound tokens that
  claim key-binding this authority did not establish.
- `iss` must equal the issuer the key is bound to — derived from the binding,
  never read from the payload. This is notme-6ad276 again: the caller does not
  get to say who issued the token.

### 3. RPC entrypoint, not a route

Identical reasoning to ADR-014, and it applies unchanged: `/internal/` is not
a private namespace (`/internal/ca-bundle` answers from the public internet),
and no header or `request.cf` check reliably separates a service-binding fetch
from an internet request. `JwtSigner` has no URL.

**It needs its own dedicated binding** — `NOTME_JWT` — for the same reason
`ReceiptSigner` does: cloister's `NOTME` binding is live for the `/identity/*`
fetch proxy, and pinning an `entrypoint` on it would redirect that traffic.

## What is deliberately not built

- **No key export.** `JwtSigner` returns a signature and a `kid`. The public
  JWK is available separately for cloister to publish; the private half never
  leaves the DO.
- **No arbitrary-`alg` support.** EdDSA only.
- **No issuer self-registration.** The delegated-issuer allowlist is operator
  configuration (`DELEGATED_JWT_ISSUERS`), not something a caller can extend.
  A caller that could register an issuer could register notme's own.

## Migration note for cloister

Cloister's `manifest.actor.pubkeyBinding` must be set to the **delegated**
public key (available from `JwtSigner.issuerPublicKey()`), not notme's master
pubkey. Publishing the master while signing with the delegated key would make
every issued token fail verification — loudly and immediately, which is the
right failure direction, but worth doing in the right order.
