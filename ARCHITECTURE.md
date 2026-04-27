# Architecture

notme is an identity authority that gives AI agents their own cryptographic identity — scoped, ephemeral, revocable, distinct from the human who deployed them.

## Deployment targets

Same code runs in three environments:

```
Local dev    →  workerd serve config.capnp    →  localhost:8788
Container    →  docker run notme:latest       →  localhost:8788
CF Workers   →  wrangler deploy               →  auth.notme.bot
```

Key storage differs by environment: ephemeral (in-memory only, local/CI), cf-managed (CF handles encryption, production). See `NOTME_KEY_STORAGE` in `docs/design/007-secretless-local-proxy.md`.

## Subsystems

```
worker.ts                    HTTP routing + CORS + host enforcement
├── src/signing-authority.ts   SigningAuthority DO — CA key, cert/token minting, passkey state
│   ├── src/auth/token.ts        JWT mint + verify (Ed25519, 5-min TTL)
│   ├── src/auth/passkey.ts      WebAuthn registration + authentication
│   ├── src/auth/principals.ts   Principal/capability/invite management
│   ├── src/auth/connections.ts  Federated identity linking
│   ├── src/auth/timing-safe.ts  HMAC-based constant-time comparison
│   └── src/cert-authority.ts    X.509 bridge cert generation (@peculiar/x509)
├── src/cert-exchange.ts       Generalized proof → cert pair or token exchange
├── src/auth/dpop.ts           DPoP proof validation (ES256, RFC 9449)
├── src/auth/dpop-handler.ts   /token endpoint handler + JWKS builder
├── src/auth/verify-proof.ts   OIDC + X.509 proof verification (trusted issuer allowlist)
├── src/auth/session.ts        HMAC session cookies (24h TTL)
├── src/gha-oidc.ts            GitHub Actions OIDC validation (RS256, Zod schema)
├── src/platform.ts            Platform abstraction (CacheStore, key storage mode, ED25519)
└── src/revocation.ts          RevocationAuthority DO — epoch-based CA rotation

gen/ts/dpop.ts               Shared SDK — base64url, validateClaims, computeJwkThumbprint
schema/identity.capnp         Cap'n Proto type definitions (CABundle, GHAClaims, etc.)
gen/go/                       Go bindings from capnp

vault/                        Separate Worker — credential vault (HKDF + AES-GCM envelope encryption)
action/src/index.ts           GHA action — OIDC → access token (zero secrets)
packages/                     Container image pipeline (melange + apko, 40MB OCI)
```

## Data flow

### Authentication → token issuance

```
Agent authenticates (passkey, GHA OIDC, bootstrap code)
  → worker.ts routes to handler
    → proof verified (verify-proof.ts or gha-oidc.ts)
      → SigningAuthority DO mints access token (Ed25519, 5-min TTL)
        → signing key never leaves DO process memory (extractable:false)
          → DPoP-bound token returned to agent (proof-of-possession, not bearer)
```

### GHA CI flow

```
GHA runner requests OIDC token (audience: notme.bot)
  → action/src/index.ts POSTs to /cert/gha with OIDC JWT + DPoP proof
    → worker.ts validates: RS256 signature, audience, owner allowlist, JTI replay
      → validates DPoP proof, computes JWK thumbprint
        → SigningAuthority.mintDPoPToken(jkt) — signs inside DO, binds to caller's key
          → action outputs: notme_url + notme_token (DPoP-bound, useless without proof key)
```

### Key lifecycle (ephemeral mode)

```
workerd starts
  → first request hits SigningAuthority DO
    → crypto.subtle.generateKey("Ed25519", extractable:false)
      → key lives in BoringSSL, not V8 heap
        → public SPKI stored in SQLite (for JWKS), private_jwk = "" (empty)
          → cat *.sqlite | strings | grep '"d"' → nothing
            → workerd exits → key dies
```

## Security model

**Two enforcement planes:**
- **Local plane** (workerd) — holds credentials, enforces scope before requests leave
- **Edge plane** (CF WAF / auth.notme.bot) — validates independently, rate limits, revocation

**Secretless invariants** (verified by adversarial tests):
1. No plaintext private key on disk
2. `crypto.subtle.exportKey()` on signing key throws
3. `NOTME_KEY_STORAGE=encrypted` without KEK = hard startup error
4. No private key material in any response or error message
5. JTI replay protection on all platforms
6. Constant-time comparison for security-sensitive strings

See `docs/design/007-secretless-local-proxy.md` for the full design spec.

## Platform abstraction

`src/platform.ts` provides a unified interface across runtimes:

| API | CF edge | Local workerd |
|-----|---------|---------------|
| `cache.get/put` | KV namespace | MemoryCache (Map + TTL) |
| `rateLimit` | CF rate limiter | Not available |
| `keyStorage` | `cf-managed` | `ephemeral` |
| Cache API | `caches.default` | Disabled (no backend) |

Detection is automatic via `NOTME_KEY_STORAGE` env var and `detectKeyStorage()`.

## Key files

| File | Lines | What |
|------|-------|------|
| `worker/worker.ts` | ~1800 | HTTP fetch handler (monolith — split planned via notme-9f51fa) |
| `worker/src/signing-authority.ts` | ~720 | SigningAuthority DO — the security kernel |
| `worker/src/platform.ts` | ~180 | Platform abstraction + MemoryCache |
| `gen/ts/dpop.ts` | ~550 | Shared JWT/crypto SDK |
| `vault/src/vault.ts` | ~200 | Credential vault DO |
| `action/src/index.ts` | ~90 | GHA action |

## Testing

```bash
npx vitest run             # 116 unit tests
bash test-local.sh         # workerd smoke test (endpoints + invariant #1)
bash test-e2e.sh           # Playwright e2e with virtual authenticator (11 contract tests)
```

Test categories:
- **Adversarial** (29 tests): key extraction, token forgery, confused deputy, DPoP injection, JTI replay, scope escalation, error message leaks, mode downgrade
- **Contract** (11 tests): discovery shape, JWKS fields, CA cert PEM, error response codes, passkey registration + authenticated access
- **Unit** (87 tests): signing, token mint/verify, DPoP, sessions, connections, passkeys, routes, platform detection
