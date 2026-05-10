# action

GitHub Action — `agentic-research/notme/action@<sha>`. Exchanges a GHA OIDC token for a bridge cert pair (P-256 mTLS + Ed25519 signing) at `auth.notme.bot/cert/gha`.

zero secrets. private keys never leave the runner process memory; cert outputs are public data.

## what this is

the third runtime plane of notme:

```mermaid
graph LR
    classDef plane fill:#1c1810,stroke:#00d4e8,stroke-width:2px,color:#e8dcc8
    classDef this fill:#1c1810,stroke:#f0d040,stroke-width:3px,color:#f0d040

    subgraph edge ["worker/ — edge plane (CF)"]
        W["auth.notme.bot<br/>CF Worker + Durable Objects<br/>mints certs, holds CA"]:::plane
    end

    subgraph local ["proxy/ — local plane (Rust)"]
        P["mTLS forward proxy<br/>bridge cert lives in process memory<br/>workerd fetch() through it"]:::plane
    end

    subgraph ci ["action/ — CI plane (TS, this directory)"]
        A["GHA action<br/>OIDC → bridge cert pair<br/>ephemeral keys in step memory"]:::this
    end

    A -->|"POST /cert/gha"| W
    P -->|"mTLS"| W
```

distinct from the other two planes: this one runs *inside someone else's CI runner*. there's no persistent process, no secret store, no file to write a key to. the OIDC JWT is the only credential, and it's redeemed once per step.

## the exchange

```mermaid
sequenceDiagram
    autonumber
    participant Step as GHA Step (action)
    participant GHA as token.actions.<br/>githubusercontent.com
    participant Worker as auth.notme.bot<br/>(worker/)
    participant DO as SIGNING_AUTHORITY<br/>(Durable Object)
    participant Octo as octo-sts<br/>(optional)

    Note over Step: permissions: id-token: write
    Step->>GHA: getIDToken(audience=notme.bot)
    GHA-->>Step: RS256 JWT (claims: repo, ref, sha, actor, jti)

    Note over Step: generate ephemeral keypairs<br/>P-256 + Ed25519, extractable:false
    Step->>Step: binding = SHA-256(<br/> mtls_spki ‖ signing_spki ‖ SHA-256(jwt))
    Step->>Step: sign binding with both private keys (PoP)

    Step->>Worker: POST /cert/gha<br/>Authorization: Bearer <jwt><br/>{ public_keys, proofs }

    Worker->>GHA: GET /.well-known/jwks (cached 1h)
    GHA-->>Worker: JWKS
    Worker->>Worker: validateGHAToken<br/>(iss, exp, aud, RS256 sig, Zod claims)
    Worker->>Worker: allowlist check<br/>(GHA_ALLOWED_OWNERS)
    Worker->>Worker: jti replay check (KV)
    Worker->>Worker: rate limit (per-repo)
    Worker->>Worker: verify PoP<br/>(P-256 + Ed25519 over binding)

    Worker->>DO: mintBridgeCertPair({ identity, scopes, ... })
    DO-->>Worker: { mtls cert, signing cert, expires_at, binding }

    Worker-->>Step: 200 { certificates, identity, expires_at, claims }

    Note over Step: setOutput notme_cert, notme_signing_cert,<br/>notme_identity, expires_at — never private keys

    opt octo_sts_scope set
        Note over Step,Octo: not yet wired in TS action — see<br/>.github/workflows/gha-identity.yml
        Step-->>Octo: federated token request
        Octo-->>Step: scoped GitHub token
        Step->>Step: setOutput github_token
    end

    Note over Step: step exits<br/>private keys garbage-collected
```

binding payload includes `SHA-256(jwt)` so the PoP signatures are inseparable from the OIDC token they were minted against. swapping in a different JWT invalidates the binding.

## inputs

| input | default | purpose |
|---|---|---|
| `audience` | `notme.bot` | OIDC audience for the identity exchange — matches `GHA_CERT_AUDIENCE` on the worker |
| `authority_url` | `https://auth.notme.bot` | authority base URL — override for self-hosted CF or local workerd |
| `skip_bridge_cert` | `false` | skip identity exchange (octo-sts-only flows) |
| `octo_sts_scope` | `''` | octo-sts scope `org/repo` — empty skips. *not yet wired in TS action* |
| `octo_sts_identity` | `default` | octo-sts trust policy identity name |

`authority_url` is force-rejected if it starts with `http://` and isn't `localhost`/`127.0.0.1` — an http URL would transmit the OIDC JWT in plaintext.

## outputs

| output | purpose |
|---|---|
| `notme_url` | authority URL for subsequent API calls |
| `notme_cert` | P-256 bridge cert PEM — mTLS transport auth (public data) |
| `notme_signing_cert` | Ed25519 bridge cert PEM — git commit signing + APAS attestations (public data) |
| `notme_identity` | WIMSE identity URI: `wimse://notme.bot/gha/{owner}/{repo}` |
| `expires_at` | cert expiry (Unix timestamp). worker default TTL is 5 minutes |
| `github_token` | scoped GitHub token from octo-sts (empty if not requested) |

private keys are **never** an output. they exist only in the step's process memory and are garbage-collected when the step exits. for cross-step usage, run the action again — each invocation gets its own keypair.

## usage

```yaml
permissions:
  id-token: write       # required for getIDToken()
  contents: read

steps:
  - uses: actions/checkout@v4
  - uses: agentic-research/notme/action@<commit-sha>
    id: notme
    with:
      audience: notme.bot
  - run: |
      echo "identity: ${{ steps.notme.outputs.notme_identity }}"
      echo "expires:  ${{ steps.notme.outputs.expires_at }}"
```

self-hosted authority:

```yaml
  - uses: agentic-research/notme/action@<commit-sha>
    with:
      authority_url: https://auth.example.com
      audience: example.com
```

## pin by SHA

always pin by full commit SHA, never by tag:

```yaml
- uses: agentic-research/notme/action@a1b2c3d4...   # good
- uses: agentic-research/notme/action@v1            # bad — mutable
```

tags are mutable. an attacker who pushes to the action repo can move `v1` to a malicious commit and every consumer pinned by tag executes attacker code on the next CI run. the Trivy/Aqua incident (March 2026) was exactly this. SHA pinning makes the dependency content-addressed.

## entrypoints

| file | role |
|---|---|
| `action.yml` | manifest GitHub reads — declares 5 inputs, 6 outputs, `runs: node20`, `main: dist/index.js` |
| `src/index.ts` | source — keypair generation, PoP construction, exchange, output wiring |
| `dist/index.js` | committed bundle — what GitHub actually executes |

## build / release

```bash
cd action
npm install
npm run build      # esbuild src/index.ts → dist/index.js (bundled, node20)
git add dist/      # consumers run dist/, not src/
```

`dist/` is committed deliberately. GitHub Actions does not run `npm install` for action consumers — it just executes `main` from `action.yml`. shipping the bundle is the actions convention. dist drift is a real bug class: changes to `src/index.ts` without a matching dist rebuild are invisible to consumers.

## related

- [`../worker/worker.ts`](../worker/worker.ts) — `/cert/gha` route handler (`handleCertGHA`)
- [`../worker/src/gha-oidc.ts`](../worker/src/gha-oidc.ts) — RS256 JWT validator + Zod claims schema
- [`../worker/src/cert-exchange.ts`](../worker/src/cert-exchange.ts) — generalized cert exchange (passkey / OIDC / bootstrap)
- [`../docs/design/008-bridge-cert-csr-wimse.md`](../docs/design/008-bridge-cert-csr-wimse.md) — bridge cert format, WIMSE URI, PoP binding
- [`../README.md`](../README.md) — top-level repo overview, three runtime planes
- [`../schema/identity.capnp`](../schema/identity.capnp) — schema source of truth (TS bindings in `../gen/ts/`)
