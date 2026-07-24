# `@agentic-research/dpop`

DPoP ([RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)) utilities and a
resource-server verifier SDK for notme-issued access tokens.

Zero runtime dependencies, pure Web Crypto (`crypto.subtle`) and `fetch` — it
runs unchanged on Cloudflare Workers, Node, Deno, and in browsers. notme itself
mints with these primitives and resource servers verify with them, so both sides
of the protocol share one implementation.

## Exports

| export                                | what it does                                                                                                                                           |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `computeJwkThumbprint()`              | RFC 7638 JWK thumbprint                                                                                                                                |
| `verifyDPoPToken()`                   | full RFC 9449 verify — token signature/claims, proof signature, required `jti`/`htm`/`htu`/`iat`/`ath`, `cnf.jkt` binding, optional atomic replay hook |
| `verifyAccessToken()`                 | token-only path for redirect flows; rejects DPoP-bound tokens to prevent downgrade (RFC 9449 §3)                                                       |
| `validateClaims()`                    | `exp` / `nbf` / `iat` / `iss` / `aud` / `sub` validation with clock tolerance                                                                          |
| `base64urlEncode` / `base64urlDecode` | chunked base64url                                                                                                                                      |
| `jsonParseSafe`                       | JSON parse that rejects non-object results                                                                                                             |
| `KVLike`                              | minimal CF-KV-shaped interface for JWKS caching                                                                                                        |

## Verifying a token

```ts
import { verifyDPoPToken } from "@agentic-research/dpop";

const claims = await verifyDPoPToken({
  token,
  proof,
  method: request.method,
  url: request.url,
  jwksUrl: "https://auth.notme.bot/.well-known/jwks.json",
  audience: "your-resource-server", // REQUIRED — see below
  issuer: "https://auth.notme.bot",
  checkAndRecordJti: async (jti) => ledger.checkAndRecord(jti), // true if already present
});
```

**`audience` is required.** Without it, a token minted for a different resource
server by the same issuer and key would verify here — the confused-deputy case
this parameter exists to close. The SDK rejects missing, empty-string, and
empty-array audience configuration at runtime.

**`clockTolerance` defaults to 60 seconds.** It applies only to the access
token's `exp` / `nbf` / `iat` claims, matching the deployed cloister and
canonical-hours verifier configuration. Set it explicitly to `0` to tighten
that window. The DPoP proof freshness window remains independently fixed at
±60 seconds; the two windows are not added together.

**`checkAndRecordJti` is optional but load-bearing.** The SDK is agnostic about where a
durable seen-`jti` ledger lives. The hook must atomically check and record:
return `true` when the JTI already exists; otherwise insert it and return
`false`. It runs only after token, proof, `ath`, and key-binding validation, so
invalid requests cannot consume replay state. Without a durable hook, only the
60s proof `iat` window bounds replay — not true single-use.

**`htu` is normalized by the verifier.** Callers may pass the full request URL;
query and fragment are removed before comparison, as RFC 9449 requires. HTTP
method tokens remain case-sensitive per RFC 9110.

**`ath` is required and computed internally.** The verifier hashes the exact
presented compact access-token string with SHA-256 and rejects missing or
mismatched proof hashes. Callers must not supply a separately computed expected
hash.

## Consuming it

In-repo, via the workspace:

```json
{ "dependencies": { "@agentic-research/dpop": "workspace:*" } }
```

Downstream repos install the public npm package and pin its resolved integrity in
their lockfiles. Release upgrades must update proof fixtures and compatibility
tests together with the dependency.

Patterns adapted from [jose](https://github.com/panva/jose) (MIT, Filip Skokan).
