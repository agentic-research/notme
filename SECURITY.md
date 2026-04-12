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

- **Secretless** — private keys exist only in process memory (`extractable: false` CryptoKey). No key material on disk, in `$GITHUB_OUTPUT`, or crossing the wire. See `docs/design/007-secretless-local-proxy.md`.
- **Two enforcement planes** — local workerd holds credentials and enforces scope; CF edge validates independently. Neither trusts the other.
- **Proof-of-possession over bearer tokens** — DPoP binding makes stolen tokens useless without the proof key.
- **Ephemeral by default** — 5-minute token/cert TTL, no renewal, just expire.
- **Zero stored secrets** — CA key born in Durable Object, session secrets auto-generated. In ephemeral mode (local/CI), the private JWK is never written to SQLite.
- **Minimal blast radius** — epoch-based revocation (one KV write revokes all certs from an epoch).

## Key Storage Modes

| Mode | When | Private key on disk? |
|---|---|---|
| `ephemeral` | Local dev, CI | No — in-memory only, dies with process |
| `encrypted` | Self-hosted (not yet implemented) | Wrapped with HKDF-derived KEK |
| `cf-managed` | Production CF Workers | CF manages DO SQLite encryption |

Set via `NOTME_KEY_STORAGE` env var. Default: `cf-managed`. Local workerd config sets `ephemeral`.

## Known Limitations

- WebAuthn implementation has not been independently audited
- DPoP token endpoint does not yet implement nonce mechanism (defense-in-depth)
- `encrypted` key storage mode is designed but not yet implemented (startup error if configured)
- Threat model is documented in `docs/design/007-secretless-local-proxy.md` (adversarial test tables)
