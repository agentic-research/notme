# `@agentic-research/dpop`

Verify DPoP-bound access tokens ([RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449))
on a resource server. Built for services that accept tokens issued by notme
(`auth.notme.bot`), including self-hosted deployments.

If you are protecting an API endpoint, the function you want is
[`verifyDPoPToken`](#verify-a-dpop-bound-token). It takes the access token, the
DPoP proof, and the request's method and URL, and either returns the verified
claims or throws a `DPoPVerificationError` with a stable `code`.

Zero runtime dependencies. Uses only Web Crypto (`crypto.subtle`), `fetch`, and
`URL`, so it runs on Cloudflare Workers, Node, Deno, and browsers. Apache-2.0.

## Install

```bash
npm install @agentic-research/dpop
```

```bash
pnpm add @agentic-research/dpop
```

## Verify a DPoP-bound token

```ts
import { verifyDPoPToken } from "@agentic-research/dpop";

const claims = await verifyDPoPToken({
  token, // the access_token, without the "DPoP " prefix
  proof, // the DPoP proof JWT from the request's DPoP header
  method: request.method, // preserve the request method's case
  url: request.url, // pass the full request URL
  jwksUrl: "https://auth.notme.bot/.well-known/jwks.json",
  audience: "your-resource-server", // required and non-empty
  issuer: "https://auth.notme.bot",
  checkAndRecordJti: (jti) => ledger.checkAndRecord(jti), // true when already recorded
});

// claims: { sub, scope, aud, exp, jti }
```

`audience` is required and enforced at runtime, not just in the types. A
resource server that omits it would accept a token minted for a *different*
resource server by the same issuer — a confused-deputy. An empty string or
empty array throws `CONFIG_AUDIENCE_REQUIRED`.

`issuer` is optional and unchecked by default, so the SDK works against
self-hosted notme deployments on other domains. Set it if you know it.

### `checkAndRecordJti` is the replay boundary

A DPoP proof is single-use. This hook is the only thing that makes that true,
and it must **atomically** check and record the proof's `jti` in durable,
shared storage. Return `true` if the `jti` was already present; record it and
return `false` otherwise. A read-then-write KV sequence is not atomic and two
concurrent replays can both observe "not seen."

The hook is optional. Without it, nothing but the proof's ±60-second `iat`
window bounds replay.

The verifier calls the hook **last**, only after every stateless token and
proof check has passed, so a malformed or forged request cannot burn a
legitimate proof's `jti`.

### What `verifyDPoPToken` checks

In order, throwing `DPoPVerificationError` on the first failure:

1. **Access token** — three-part JWT, EdDSA signature against the JWKS key,
   header `typ` pinned to `at+jwt`, and an `exp` claim present.
2. **Token claims** — `exp`, `nbf`, `iat`, `iss`, `aud`, and a required `sub`,
   via the shared `validateClaims`. Clock tolerance defaults to 60 seconds;
   pass `clockTolerance: 0` to tighten it.
3. **Proof** — header `typ` of `dpop+jwt`, an `alg` of `ES256` or `EdDSA`, an
   embedded public `jwk`, and a valid signature. A proof JWK carrying private
   members (`d`, `p`, `q`, …) is rejected.
4. **Proof claims** — `jti` required; `iat` required and within ±60 seconds;
   `htm` compared case-sensitively against `method`; `htu` compared against
   `url` after normalization (query and fragment stripped, percent-encoding
   canonicalized); `ath` required and matched against the base64url SHA-256 of
   the exact token string.
5. **Key binding** — the token's `cnf.jkt` must equal the RFC 7638 thumbprint
   of the proof's JWK.
6. **Replay** — `checkAndRecordJti`, when provided.

## Handle errors by code

```ts
import { DPoPVerificationError, verifyDPoPToken } from "@agentic-research/dpop";

try {
  const claims = await verifyDPoPToken(options);
} catch (error) {
  if (error instanceof DPoPVerificationError) {
    console.error(error.code, error.message);
  }
  throw error;
}
```

Match on `error.code`, never on the message. Every code is a member of the
exported `VerifyErrorCode` union — `PROOF_REPLAY`, `CNF_JKT_MISMATCH`,
`CLAIM_AUD_MISMATCH`, and so on. Messages are for humans and may be reworded.

## Redirect-only Bearer tokens

Use `verifyAccessToken` only for an unbound token received through a redirect
flow, where the DPoP keypair was ephemeral and is gone by the time the token
arrives. It verifies the signature and claims but not a proof.

It **rejects** any token carrying a `cnf` claim with
`BEARER_TOKEN_DPOP_BOUND`. Without that check, stripping the DPoP header from
a stolen bound token would downgrade it to a Bearer token that this function
would happily accept.

## Cache the JWKS

Both verifiers accept an optional `kv` store and cache the fetched JWKS under
one key for one hour. The `KVLike` interface is just `get` and `put` — it is
compatible with Cloudflare KV without being coupled to it.

```ts
await verifyDPoPToken({ ...options, kv: env.MY_KV });
```

Passing `publicKey` (an imported Ed25519 `CryptoKey`) instead skips the JWKS
fetch entirely, which is useful in tests.

## PKCE (RFC 7636)

*Added in 0.4.0.*

PKCE is a two-sided protocol: one party derives a challenge from a verifier,
the other recomputes it and compares. The two sides must agree byte for byte,
and when they don't, the drift is invisible — a padded base64 or a different
length bound produces a challenge that never matches, and the only symptom is
an opaque `invalid_grant`. These helpers are exported so both sides can run
the same function instead of two implementations that agree until they don't.

Only `S256` is supported. `plain`, where the verifier *is* the challenge,
would put the verifier in the URL and defeat the purpose.

**Client** — starting an authorization-code flow:

```ts
import { generateCodeVerifier, codeChallengeS256 } from "@agentic-research/dpop";

const verifier = generateCodeVerifier(); // 43 chars, 32 CSPRNG bytes as base64url
const challenge = await codeChallengeS256(verifier); // unpadded, per §4.2

// Keep `verifier` server-side. Send only `challenge` in the authorize URL.
```

**Authority** — validating:

```ts
import {
  isValidCodeChallenge,
  isValidCodeVerifier,
  sha256Base64url,
} from "@agentic-research/dpop";

// Check the challenge where the flow STARTS, so a malformed one is a
// diagnosable error here instead of an invalid_grant a round-trip later.
if (!isValidCodeChallenge(challenge)) return badRequest();

// Check the verifier's shape rather than assuming it. PKCE's security
// argument is the verifier's entropy, so accepting a short one hands back a
// working flow with none of the protection.
if (!isValidCodeVerifier(verifier)) return badRequest();

const ok = (await sha256Base64url(verifier)) === storedChallenge;
```

`isValidCodeVerifier` enforces the §4.1 length range
(`MIN_CODE_VERIFIER_LENGTH` 43 to `MAX_CODE_VERIFIER_LENGTH` 128, both
exported) and the unreserved alphabet, rejecting `+`, `/`, and `=`.
`isValidCodeChallenge` requires exactly 43 unreserved characters, the only
length a base64url-encoded 32-byte digest can have. Both are TypeScript type
guards and both reject non-strings.

`codeChallengeS256` is pinned in the test suite against the RFC 7636
Appendix B vector rather than round-tripped through this package's own code —
a self-consistent but wrongly-encoded implementation passes a round-trip test
and then fails against every real peer.

`sha256Base64url` is also useful for storing an authorization code as a digest
rather than in the clear: a code is a live credential until redeemed, so a
read of your storage should not yield redeemable ones.

<details>
<summary>Full export surface</summary>

**Verifiers** — `verifyDPoPToken`, `verifyAccessToken`

**Errors** — `DPoPVerificationError`, `VerifyErrorCode` (type)

**Types** — `VerifyDPoPTokenOptions`, `VerifyAccessTokenOptions`,
`VerifiedTokenClaims`, `KVLike`, `ValidateClaimsOptions`

**Claim validation** — `validateClaims`, for verifying JWT claims
(`exp`/`nbf`/`iat`/`iss`/`aud`/`sub`) outside the two token verifiers.

**Thumbprints** — `computeJwkThumbprint`, an RFC 7638 JWK thumbprint over
`EC`, `RSA`, and `OKP` keys.

**PKCE** — `generateCodeVerifier`, `codeChallengeS256`, `sha256Base64url`,
`isValidCodeVerifier`, `isValidCodeChallenge`, `MIN_CODE_VERIFIER_LENGTH`,
`MAX_CODE_VERIFIER_LENGTH`

**Encoding** — `base64urlEncode`, `base64urlDecode`, `jsonParseSafe`

</details>

## Guides

<!-- These links are pinned to the release TAG, not main, so a reader of a
     published version sees the docs that shipped with it. npm renders only
     README.md — never docs/*.mdx — so these links are the entire discovery
     path from the package page. Bump the tag when cutting a release; the
     `docs links pinned to release tag` test in scripts/ guards the drift. -->
- [Verification](https://github.com/agentic-research/notme/blob/dpop-v0.4.0/packages/dpop/docs/verification.mdx)
- [Replay protection](https://github.com/agentic-research/notme/blob/dpop-v0.4.0/packages/dpop/docs/replay-protection.mdx)
- [Errors](https://github.com/agentic-research/notme/blob/dpop-v0.4.0/packages/dpop/docs/errors.mdx)
- [Migrating to 0.3](https://github.com/agentic-research/notme/blob/dpop-v0.4.0/packages/dpop/docs/migration-0.3.mdx)

## Breaking changes in 0.3

- `seenJti` is renamed to `checkAndRecordJti` and must be atomic.
- DPoP proofs require `ath`; `audience` must be non-empty.
- Access-token clock tolerance defaults to 60 seconds (set `0` explicitly for none).
- `htu` is normalized, `htm` remains case-sensitive, and errors expose stable codes.

## License

Apache-2.0
