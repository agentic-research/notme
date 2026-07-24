# `@agentic-research/dpop`

DPoP ([RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)) verification
utilities for notme-issued access tokens. It has zero runtime dependencies and
uses only Web Crypto (`crypto.subtle`) and `fetch`, so it works in Cloudflare
Workers, Node, Deno, and browsers.

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
  token,
  proof,
  method: request.method, // preserve the request method's case
  url: request.url, // pass the full request URL
  jwksUrl: "https://auth.notme.bot/.well-known/jwks.json",
  audience: "your-resource-server", // required and non-empty
  issuer: "https://auth.notme.bot",
  checkAndRecordJti: (jti) => ledger.checkAndRecord(jti), // true when already recorded
});
```

`checkAndRecordJti` is a security boundary: it must atomically check and record
the proof JTI in durable shared storage. Return `true` for an existing JTI and
`false` after recording a new one. A read-then-write KV sequence is not atomic.

## Handle stable errors

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

Match `error.code`, not the human-readable message.

## Redirect-only Bearer tokens

Use `verifyAccessToken` only for an unbound token received through a redirect
flow. It rejects tokens with a DPoP `cnf` binding, preventing a missing proof
from downgrading a DPoP-bound token to Bearer authentication.

## Guides

- [Verification](docs/verification.mdx)
- [Replay protection](docs/replay-protection.mdx)
- [Errors](docs/errors.mdx)
- [Migrating to 0.3](docs/migration-0.3.mdx)

## Breaking changes in 0.3

- `seenJti` is renamed to `checkAndRecordJti` and must be atomic.
- DPoP proofs require `ath`; `audience` must be non-empty.
- Access-token clock tolerance defaults to 60 seconds (set `0` explicitly for none).
- `htu` is normalized, `htm` remains case-sensitive, and errors expose stable codes.
