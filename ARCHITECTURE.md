# Architecture

notme is an identity authority that gives AI agents their own cryptographic identity — scoped, ephemeral, revocable, distinct from the human who deployed them.

## Deployment targets

Same code runs in three environments:

```
Local dev    →  workerd serve config.capnp                      →  localhost:8788
Container    →  docker run ghcr.io/agentic-research/notme:0.1.0  →  localhost:8788
CF Workers   →  wrangler deploy                                  →  auth.notme.bot
```

Key storage differs by environment: ephemeral (in-memory only, local/CI), cf-managed (CF handles encryption, production). See `NOTME_KEY_STORAGE` in `docs/design/007-secretless-local-proxy.md`.

## Subsystems

```mermaid
graph TD
    classDef entry fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000
    classDef kernel fill:#ffebee,stroke:#c62828,stroke-width:2px,color:#000
    classDef auth fill:#e8f5e9,stroke:#2e7d32,stroke-width:1px,color:#000
    classDef sep fill:#f3e5f5,stroke:#7b1fa2,stroke-width:1px,color:#000

    W["<b>worker.ts</b><br/>HTTP routing, CORS, host enforcement"]:::entry

    SA["<b>signing-authority.ts</b><br/>SigningAuthority DO — CA key,<br/>cert/token minting, passkey state<br/><i>the security kernel</i>"]:::kernel
    RA["<b>revocation.ts</b><br/>RevocationAuthority DO —<br/>epoch rotation, seqno rollback"]:::kernel

    CA["cert-authority.ts<br/>X.509 generation (@peculiar/x509)"]:::auth
    CX["cert-exchange.ts<br/>proof → cert pair or token"]:::auth
    POP["auth/pop.ts<br/>proof-of-possession, one verifier<br/>for all three cert routes"]:::auth
    SC["auth/scope-chain.ts<br/>scopes ⊆ parent — the AUTHORITY bound"]:::auth
    CK["auth/correlation-key.ts<br/>&lt;principal&gt;/&lt;bridge&gt;/&lt;task&gt;"]:::auth
    TOK["auth/token.ts + dpop.ts + dpop-handler.ts<br/>Ed25519 JWT, DPoP (RFC 9449), JWKS"]:::auth
    PK["auth/passkey.ts + session.ts<br/>WebAuthn, HMAC session cookies"]:::auth
    PR["auth/principals.ts + connections.ts<br/>capabilities, invites, federated identity"]:::auth
    VP["auth/verify-proof.ts + gha-oidc.ts<br/>OIDC/X.509 proofs, issuer allowlist"]:::auth
    RC["receipts/<br/>Interlace commitment — canonical CBOR,<br/>validate-then-sign"]:::auth
    PF["platform.ts<br/>CacheStore, key storage mode, ED25519"]:::auth

    PX["proxy/src/main.rs<br/>Rust mTLS forward proxy —<br/>holds the bridge key in memory"]:::sep
    AC["action/src/index.ts<br/>GHA action, zero secrets"]:::sep
    VA["vault/<br/>separate Worker — HKDF + AES-GCM"]:::sep
    SDK["packages/dpop<br/>shared SDK"]:::sep
    SCH["schema/identity.capnp → gen/go/<br/>Cap'n Proto + Go bindings"]:::sep

    W --> SA
    W --> RA
    W --> CX
    W --> TOK
    W --> VP
    W --> PF
    SA --> CA
    SA --> PK
    SA --> PR
    SA --> RC
    CX --> CA
    CX --> POP
    W --> POP
    CX --> SC
    RC -.->|carries| CK
    CA -.->|binding| CK
    AC -->|OIDC + PoP| W
    PX -->|mTLS| W
    TOK -.-> SDK
    AC -.-> SDK
    SCH -.-> RA
```

The DOs are the security kernel: private keys are generated inside `SigningAuthority` and never leave it. Everything else is routing, validation, or encoding.

## Data flow

### GHA CI flow — OIDC to bridge cert

```mermaid
sequenceDiagram
    autonumber
    participant R as GHA runner
    participant A as action/src/index.ts
    participant W as worker.ts
    participant P as auth/pop.ts
    participant DO as SigningAuthority DO

    R->>A: OIDC token (audience notme.bot)
    A->>A: generate P-256 + Ed25519 keypairs<br/>(extractable:false — private keys never leave)
    Note over A: proofs sign the binding PRE-IMAGE,<br/>never its digest — WebCrypto ECDSA<br/>hashes internally (notme-a011d2)
    A->>W: POST /cert/gha — OIDC JWT + SPKIs + PoP proofs
    W->>W: RS256 signature, audience, owner allowlist, JTI replay
    W->>P: verifyPopProofs(bindingInput, ...)
    P-->>W: ok, binding: pre-image | digest
    W->>DO: mint cert pair
    DO->>DO: sign inside the DO — CA key never exported
    DO-->>W: mTLS cert + signing cert (shared binding extension)
    W-->>A: cert pair + WIMSE identity + expiry
    A-->>R: certs only — no private key ever written to $GITHUB_OUTPUT
```

### Key lifecycle (ephemeral mode)

```mermaid
graph LR
    classDef step fill:#e8f5e9,stroke:#2e7d32,color:#000
    classDef proof fill:#fff3e0,stroke:#ef6c00,color:#000

    A["workerd starts"]:::step --> B["first request hits<br/>SigningAuthority DO"]:::step
    B --> C["generateKey('Ed25519',<br/>extractable: false)"]:::step
    C --> D["key lives in BoringSSL,<br/>not the V8 heap"]:::step
    D --> E["SQLite holds public SPKI<br/>for JWKS; private_jwk = ''"]:::step
    E --> F["strings on the .sqlite file<br/>finds no private key — nothing to leak"]:::proof
    E --> G["workerd exits<br/>→ key dies"]:::step
```

### Delegation chain — the target shape

`ADR-008` specifies three tiers. Only the outer two are built; the middle tier is unimplemented, which is why task-scoped revocation has no unit (`notme-600df1`, `notme-77a024`).

```mermaid
graph TD
    classDef built fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000
    classDef gap fill:#ffebee,stroke:#c62828,stroke-width:2px,stroke-dasharray:5 4,color:#000

    ROOT["<b>root CA</b><br/>CA=true, pathlen=1<br/>keyCertSign, cRLSign"]:::built
    BRIDGE["<b>orchestrator bridge</b> — the MACHINE<br/>CA=true, pathlen=0, keyCertSign<br/><i>NOT BUILT — every mint stamps CA=false</i>"]:::gap
    TASK["<b>agent session</b> — the TASK<br/>CA=false (leaf), digitalSignature<br/><i>no producer until the tier above exists</i>"]:::gap
    LEAF["<b>bridge cert pair</b> (today)<br/>CA=false — mTLS + signing<br/>issued directly by the root"]:::built

    ROOT -->|"issues today"| LEAF
    ROOT -.->|"pathlen budget<br/>allocated, unspent"| BRIDGE
    BRIDGE -.->|"machine delegates<br/>to each task"| TASK

    SCOPES["auth/scope-chain.ts<br/>scopes ⊆ parent<br/><b>AUTHORITY</b> bound (cooperative)"]:::built
    PATH["pathLenConstraint<br/>RFC 5280 §6.1.4<br/><b>DEPTH</b> bound (intrinsic)"]:::built
    NAMES["nameConstraints<br/>ADR-008 §299<br/><b>NAMESPACE</b> bound — NOT BUILT"]:::gap

    SCOPES -.-> BRIDGE
    PATH -.-> BRIDGE
    NAMES -.-> BRIDGE
```

The three bounds are independent and none substitutes for another: scopes bound what a credential may **do**, pathlen bounds how far it may **pass that on**, nameConstraints bounds which identities it may **name**.

## Security model

**Two enforcement planes**, and the bridge cert is the contract between them — each validates independently, so neither has to trust the other:

```mermaid
graph LR
    classDef local fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000
    classDef edge fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px,color:#000
    classDef seam fill:#fff3e0,stroke:#ef6c00,stroke-width:2px,color:#000

    subgraph LP["LOCAL PLANE (workerd + proxy)"]
        AG["agent Worker<br/>no globalOutbound —<br/>cannot fetch() at all"]:::local
        PXY["notme-proxy<br/>holds bridge cert + key<br/>in process memory"]:::local
        AG -->|service binding only| PXY
    end

    CERT["<b>bridge cert</b><br/>the seam"]:::seam

    subgraph EP["EDGE PLANE (auth.notme.bot)"]
        WAF["CF WAF + rate limiters"]:::edge
        VER["signature, epoch, TTL, scope"]:::edge
        REV["revocation — epoch + seqno"]:::edge
    end

    PXY -->|attaches on outbound TLS| CERT
    CERT --> WAF --> VER --> REV
```

Because the agent has no `globalOutbound` (ADR-009) and the proxy performs every outbound request, the proxy is a chokepoint the agent cannot route around — which is what lets it stamp an unforgeable correlation key, the way journald attaches `_SYSTEMD_UNIT` rather than trusting a process to report its own.

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
| `worker/worker.ts` | ~3350 | HTTP fetch handler (monolith — split planned via notme-9f51fa) |
| `worker/src/signing-authority.ts` | ~2110 | SigningAuthority DO — the security kernel |
| `proxy/src/main.rs` | ~1030 | mTLS forward proxy (TCP + UDS listen) |
| `packages/dpop/src/index.ts` | ~1100 | Shared JWT/crypto SDK |
| `worker/src/platform.ts` | ~210 | Platform abstraction + MemoryCache + ED25519 typing constant |
| `action/src/index.ts` | ~190 | GHA action |

## Testing

```bash
cd worker && npx vitest run    # 526 tests, 38 files (unit + adversarial + shared-SDK)
cd worker && npm run test:do   # 122 real-Durable-Object tests, 15 files (vitest-pool-workers)
bash test-local.sh             # workerd smoke test (endpoints + invariant #1)
bash test-e2e.sh               # Playwright e2e with virtual authenticator (contract tests)
cd ../proxy && cargo test      # Rust tests (listen-addr parser, UDS bind, perms, round-trip)
task worker:verify             # live endpoint checks against production or staging
```

Test categories (worker):
- **Adversarial**: key extraction, token forgery, confused deputy, DPoP injection, JTI replay, scope escalation, error-message leaks, mode downgrade
- **Real-DO** (vitest-pool-workers): boots real workerd + DO SQLite via `runInDurableObject` — rotation grace window, seqno rollback/isolation, `checkRevocation`, bootstrap, cert minting
- **Contract** (e2e): discovery shape, JWKS fields, CA cert PEM, error codes, passkey registration + authenticated access
- **Unit**: signing, token mint/verify, DPoP, sessions, connections, passkeys, routes, platform detection, canonical CBOR

Two conventions worth knowing before reading the suite:

- **`it.fails` marks a gap, not a bug.** `delegation-depth.do.test.ts` asserts the middle delegation tier is still missing, so it goes red the moment someone builds it — that is the signal to delete the `.fails`. A `todo` would sit inert and tell nobody. These show as "expected fail" in the DO run.
- **Some fixtures are deliberately foreign.** `pop-preimage.test.ts` and the hand-encoder in `receipt-commitment.test.ts` build inputs WITHOUT the code under test, because a fixture built by the encoder it validates is a fixed point rather than a conformance check. Both existing bugs of that shape — the double-hashed PoP and the float64 CBOR timestamp — survived review precisely because their tests were self-consistent.

Threat-model coverage is enumerated in `worker/THREAT_MODEL.md` — each row links to the test that defends it.
