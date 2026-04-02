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

- **Proof-of-possession over bearer tokens** — stolen certs are useless without the private key
- **Ephemeral by default** — 5-minute cert TTL, no renewal, just expire
- **Zero stored secrets** — CA key born in Durable Object, session secrets auto-generated
- **Minimal blast radius** — epoch-based revocation (one KV write revokes all certs from an epoch)

## Known Limitations

- `workerLoader` binding is experimental (CF workerd)
- WebAuthn implementation has not been independently audited
- DPoP token endpoint does not yet implement nonce mechanism (defense-in-depth)
- Rate limiting on `/token` not yet implemented
- No formal threat model document (planned)
