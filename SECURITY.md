# Security Policy

## Status

**This project is experimental / proof-of-concept.** It is under active development and has not been audited. Do not use it to protect production systems without independent review.

## Reporting Vulnerabilities

Email: security@notme.bot

Please include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment

We will acknowledge reports within 48 hours and provide a timeline for resolution.

## Scope

notme is an identity authority that issues ephemeral bridge certificates. Security-relevant components:

- **SigningAuthority DO** — Ed25519 CA key generation and storage (born in CF, never exported)
- **Passkey/WebAuthn** — registration and authentication flows
- **DPoP token issuance** — RFC 9449 sender-constrained tokens
- **Bridge cert minting** — X.509 certificate generation and signing
- **Revocation** — epoch-based CA key rotation
- **GHA OIDC exchange** — GitHub Actions token validation

## Design Principles

- **Secretless** — client private keys exist only in process memory (`extractable: false` CryptoKey). No key material in `$GITHUB_OUTPUT` or crossing the wire. The authority's own CA key is the exception: it is stored in DO SQLite, as a plaintext JWK in `cf-managed` mode or KEK-sealed in `encrypted` mode (see Key Storage Modes). See `docs/design/007-secretless-local-proxy.md`.
- **Two enforcement planes** — local workerd holds credentials and enforces scope; CF edge validates independently. Neither trusts the other.
- **Proof-of-possession over bearer tokens** — DPoP binding makes stolen tokens useless without the proof key.
- **Short-lived by default** — 5-minute workload certs (`GHA_CERT_TTL_MS`, default 300 000) that are not renewed, just expire. Machine tier certs are the exception: they renew, and each renewal is a proof of the machine's key.
- **Zero stored secrets** — CA key born in Durable Object, session secrets auto-generated. In ephemeral mode (local/CI), the private JWK is never written to SQLite.
- **Minimal blast radius** — epoch-based revocation: `POST /admin/revoke-epoch` advances the epoch, and every cert from an older epoch is refused.

## Key Storage Modes

| Mode | When | Private key on disk? |
|---|---|---|
| `ephemeral` | Local dev, CI | No — in-memory only, dies with process |
| `encrypted` | Any deployment with `NOTME_KEK_SECRET` set (built, `worker/src/key-encryption.ts`; not yet enabled in production, `notme-41d0d3`) | Wrapped with HKDF-derived KEK |
| `cf-managed` | Production CF Workers | CF manages DO SQLite encryption |

Set via `NOTME_KEY_STORAGE` env var. Default: `cf-managed`, unless `NOTME_KEK_SECRET` is set, which selects `encrypted` (`worker/src/platform.ts:46-55`). Local workerd config sets `ephemeral`.

## Threat Model & Tests

- Server-side threat model: [`worker/THREAT_MODEL.md`](worker/THREAT_MODEL.md). Each row's `test` column maps to a named test in `worker/src/__tests__/`.
- Executable threat-model + cross-repo contract assertions: [`worker/src/__tests__/threat-model.test.ts`](worker/src/__tests__/threat-model.test.ts). Encodes the 11 consumer↔server contract assumptions surfaced by the 2026-05-16 security review (OIDC audience, trusted issuers, CABundle CBOR canonical bytes, revocation seqno monotonicity, DPoP proof shape, scope vocabulary, AuthService RPC surface, redirect-URI normalization, GHA fork-PR boundary, and AuthService per-session credential isolation). Cross-repo invariants needing server-produced fixtures are marked `it.todo` and name the fixture.

## Known Limitations

- WebAuthn implementation has not been independently audited
- DPoP nonces on `/token` (RFC 9449 §8) are implemented but off by default; `DPOP_REQUIRE_NONCE=true` turns them on (`worker/src/auth/dpop-nonce.ts`)
- An OIDC proof at `/join` can be bound to its invite: `POST /join/challenge` returns a per-deployment audience carrying a nonce bound to that invite, and a token minted for it works nowhere else (ADR-023). The plain `notme.bot` audience is still accepted and counted until `JOIN_REQUIRE_NONCE=true` (`worker/src/auth/join-nonce.ts`)
- `encrypted` key storage mode is implemented but not yet turned on in production; that waits on the KEK rehearsal (`scripts/kek-rehearsal.sh`, `notme-41d0d3`, open). Selecting `encrypted` without `NOTME_KEK_SECRET` is a startup error
- Older design-time threat tables live in `docs/design/007-secretless-local-proxy.md`; canonical threat model is `worker/THREAT_MODEL.md`.

## Ed25519 typing workaround

The TypeScript DOM lib does not yet enumerate Ed25519 as a valid `SubtleCrypto`
algorithm identifier, and `@cloudflare/workers-types` does not extend the
algorithm union for it. CF Workers' WebCrypto runtime nevertheless implements
Ed25519 fully (BoringSSL).

All production Ed25519 sign/verify call sites import the single constant
`ED25519` from `worker/src/platform.ts`, which carries the `as any` cast and
documents the gap. This means:

- Reviewers see exactly one cast in production code rather than chasing a
  string literal across the codebase.
- When the lib types catch up, removing the workaround is a one-line change
  in `platform.ts`.
- Tests retain their own inline casts because they construct distinct
  algorithm objects per call (e.g. `importKey` requires the object form,
  `sign` accepts the string form).

Tracked in bead `notme-ae1030`.
