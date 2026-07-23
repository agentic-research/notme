# `@agentic-research/dpop`

DPoP ([RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)) utilities and a
resource-server verifier SDK for notme-issued access tokens.

Zero runtime dependencies, pure Web Crypto (`crypto.subtle`) and `fetch` — it
runs unchanged on Cloudflare Workers, Node, Deno, and in browsers. notme itself
mints with these primitives and resource servers verify with them, so both sides
of the protocol share one implementation.

## Exports

| export | what it does |
|---|---|
| `computeJwkThumbprint()` | RFC 7638 JWK thumbprint |
| `verifyDPoPToken()` | full RFC 9449 verify — token signature, `typ`, claims, proof signature, `jti` (+ optional replay hook), `htm`/`htu` exact match, `cnf.jkt` binding |
| `verifyAccessToken()` | token-only path for redirect flows; rejects DPoP-bound tokens to prevent downgrade (RFC 9449 §3) |
| `validateClaims()` | `exp` / `nbf` / `iat` / `iss` / `aud` / `sub` validation with clock tolerance |
| `base64urlEncode` / `base64urlDecode` | chunked base64url |
| `jsonParseSafe` | JSON parse that rejects non-object results |
| `KVLike` | minimal CF-KV-shaped interface for JWKS caching |

## Verifying a token

```ts
import { verifyDPoPToken } from "@agentic-research/dpop";

const claims = await verifyDPoPToken({
  token, proof,
  method: request.method,
  url: request.url,
  jwksUrl: "https://auth.notme.bot/.well-known/jwks.json",
  audience: "your-resource-server",   // REQUIRED — see below
  issuer: "https://auth.notme.bot",
  seenJti: (jti) => ledger.has(jti),  // durable single-use ledger, yours to own
  clockTolerance: 60,                 // seconds; see below
});
```

**`audience` is required.** Without it, a token minted for a different resource
server by the same issuer and key would verify here — the confused-deputy case
this parameter exists to close. Pass `[]` only if you genuinely want no pinning.

**`clockTolerance` defaults to 0.** notme mints `nbf: iat` on every access token,
so a verifier whose clock trails the issuer's rejects a legitimate token at
`nbf`. Zero is the right default (fail-closed, and correct for a same-host
verifier); a resource server on separate infrastructure should set a small
non-zero value. It widens `exp` as well as `nbf`, so keep it to tens of seconds.

**`seenJti` is optional but load-bearing.** The SDK is agnostic about where a
durable seen-`jti` ledger lives. Without one, only the 60s `iat` freshness
window bounds replay — not true single-use.

## Consuming it

In-repo, via the workspace:

```json
{ "dependencies": { "@agentic-research/dpop": "workspace:*" } }
```

Downstream repos currently **vendor a copy** of this file, because until it moved
here there was no package to depend on. Publishing to a registry is the step that
lets those copies be deleted — tracked in `notme-18450e`.

Patterns adapted from [jose](https://github.com/panva/jose) (MIT, Filip Skokan).
