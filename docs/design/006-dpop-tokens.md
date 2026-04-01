<!--
@doc-check
@types: CertScope
@endpoints: POST /token, GET /.well-known/jwks.json, GET /.well-known/signet-authority.json
-->
# ADR-006: DPoP Sender-Constrained Tokens

**Status:** Accepted
**Date:** 2026-04-01
**Bead:** notme.bot-2b0d41

## Context

Bridge certs (X.509 + mTLS) work for CLI and CI but not for browsers. Mobile Safari and Chrome can't do mTLS with JS-generated keys. We need a browser-friendly proof-of-possession format for admin flows (e.g. rosary.bot/admin/setup-github).

RFC 9449 (DPoP) solves this: sender-constrained tokens where the client generates an ephemeral keypair and every request includes a signed proof. Stolen token without the key is useless.

## Decision

Add a `/token` endpoint to auth.notme.bot that issues DPoP-bound JWT access tokens. Same Ed25519 master key signs both bridge certs and access tokens. Same principal model, same scopes, different wire format.

Three proof-of-possession formats, three contexts:

| Context | Mechanism | Key lifecycle |
|---|---|---|
| Mobile/browser admin | DPoP (RFC 9449) | Ephemeral per-session (Web Crypto) |
| CLI / MCP clients | Bridge cert (mTLS) | Short-lived (5min-24h) |
| GHA CI/CD | OIDC → bridge cert | Per-run (5min) |

## Token Format

### DPoP Proof JWT (client-generated, ES256)

```
Header: { "typ": "dpop+jwt", "alg": "ES256", "jwk": { P-256 public key } }
Payload: {
  "jti": "<unique>",
  "htm": "<HTTP method>",
  "htu": "<request URL>",
  "iat": <unix timestamp>,
  "nonce": "<server-issued, if required>",
  "ath": "<base64url(SHA-256(access_token))>"  // at resource server only
}
```

### Access Token JWT (server-issued, EdDSA)

```
Header: { "typ": "at+jwt", "alg": "EdDSA", "kid": "<authority keyId>" }
Payload: {
  "sub": "<principalId>",
  "iss": "https://auth.notme.bot",
  "aud": "<requested audience>",
  "iat": <unix timestamp>,
  "nbf": <unix timestamp>,
  "exp": <iat + 300>,
  "jti": "<unique>",
  "scope": "bridgeCert authorityManage",
  "cnf": { "jkt": "<RFC 7638 JWK Thumbprint of client P-256 key>" }
}
```

Response: `{ "access_token": "<jwt>", "token_type": "DPoP", "expires_in": 300 }`

## Endpoints

### POST /token (auth.notme.bot)

**Auth:** Session cookie (`notme_session`) + `DPoP` header with proof JWT.
**Body:** `{ "audience": "https://rosary.bot" }` (required).
**Response:** JWT access token bound to the DPoP key.
**Rate limit:** 20 tokens/principal/hour via KV.

### GET /authorize (auth.notme.bot)

**Redirect flow for cross-origin.** Query params: `redirect_uri`, `audience`, `state`.
If no session: redirects to /login. Otherwise: browser JS generates keypair, mints token, redirects back with `?token=<jwt>&state=<state>`.

### GET /.well-known/jwks.json (auth.notme.bot)

Ed25519 public key in JWK format. Cached 1hr. Updates on key rotation (epoch change).

```json
{ "keys": [{ "kty": "OKP", "crv": "Ed25519", "x": "<b64url>", "kid": "<keyId>", "use": "sig", "alg": "EdDSA" }] }
```

### Updated: /.well-known/signet-authority.json

Add `token_endpoint`, `jwks_uri`, `dpop_signing_alg_values_supported`.

## Verification (Resource Server)

1. Parse DPoP proof → extract JWK
2. Verify proof signature (ES256)
3. Check: jti unique, htm matches, htu matches, iat within 60s, nonce valid, ath = SHA-256(token)
4. Parse access token → verify signature (EdDSA) against JWKS
5. Check: exp, iss, aud, cnf.jkt matches thumbprint of proof JWK
6. Extract sub + scope → authorize

## JWK Thumbprint (RFC 7638)

Canonical computation — shared function used by both issuer and verifier:

1. Extract required members for key type (EC: `crv`, `kty`, `x`, `y` — sorted)
2. JSON.stringify with no whitespace
3. SHA-256 hash
4. Base64url encode (no padding)

This is the #1 implementation bug risk. Must be tested against RFC 7638 Section 3.1 vector.

## Client-Side

DPoP keypair generated in browser via Web Crypto:

```typescript
const kp = await crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  false,  // private key NOT extractable
  ["sign"]
);
```

Public key exported separately for the JWK header. Keypair lives in JS memory (ephemeral — page close kills it).

## Security Properties

**What DPoP protects:** Token theft. If the access token leaks (logs, proxies, error messages), it cannot be used without the corresponding private key.

**What DPoP does NOT protect:** Session cookie compromise. An attacker with the session cookie can generate their own keypair and request tokens. The session cookie is the root of trust after passkey auth. This is acceptable: `HttpOnly`, `Secure`, `SameSite=Strict` mitigate cookie theft. DPoP's value is after token issuance.

**Non-extractable keys:** `extractable: false` on the private key prevents JS exfiltration. An XSS attacker can still call `crypto.subtle.sign` in the victim's context but cannot export the key material to a remote server.

## Nonce Mechanism

Server issues `DPoP-Nonce` header in responses. Client includes it in next proof. Prevents clock manipulation attacks. Nonce is HMAC of a server-side counter — cheap to issue, stateless to verify.

On first request without nonce: server returns 401 with `{ "error": "use_dpop_nonce" }` + `DPoP-Nonce` header. Client retries with nonce. Subsequent responses include fresh nonces.

## Error Responses

| Condition | Status | Error |
|---|---|---|
| No session | 401 | `session_required` |
| Missing DPoP header | 400 | `dpop_proof_required` |
| Invalid proof signature | 401 | `invalid_dpop_proof` |
| JTI replay | 401 | `proof_reused` |
| iat too old | 401 | `proof_expired` |
| Nonce mismatch | 401 | `use_dpop_nonce` (+ new nonce in header) |
| Rate limited | 429 | `rate_limit` |
| Invalid audience | 400 | `invalid_audience` |

## Files

| File | Change |
|---|---|
| `worker/src/auth/dpop.ts` | New — proof validation, nonce, JWK thumbprint |
| `worker/src/auth/token.ts` | New — JWT access token minting (EdDSA) |
| `worker/worker.ts` | Routes: /token, /authorize, /.well-known/jwks.json |
| `worker/src/signing-authority.ts` | Add `getPublicKeyJwk()`, `mintAccessToken()` |
| `gen/ts/dpop.ts` | New — shared `computeJwkThumbprint()` |
| `worker/src/__tests__/dpop.test.ts` | New — TDD tests first |
| `worker/src/__tests__/token.test.ts` | New — TDD tests first |

## Relationship to Signet

Signet design doc 007 (http-pop.md) explicitly references RFC 9449. Signet uses CBOR/COSE, DPoP uses JWT — different wire formats, same proof-of-possession principle. The `/token` endpoint is the JWT bridge for contexts where CBOR doesn't fit (browsers).

## Implementation Approach

TDD. Tests written first for:
1. JWK thumbprint computation (against RFC 7638 test vector)
2. DPoP proof validation (signature, claims, replay, nonce)
3. Access token minting (signature, claims, binding)
4. /token endpoint integration (happy path, error cases)
5. /authorize redirect flow
