# schema

Cap'n Proto schemas — declared single source of truth for **type definitions** across TypeScript, Go, and Rust in the notme identity stack. **Wire formats are NOT defined here.**

## the layering (read this first)

| Layer | What it owns | Where |
|---|---|---|
| **Protocol** | wire formats, cryptographic operations, canonical-bytes-for-signing | [signet/](https://github.com/agentic-research/signet) (Go, the spec + reference implementation) |
| **Implementation** | secure deployed reference impl of the signet protocol on CF Workers | `notme/` (this repo) |
| **Type sync** | cross-language type definitions in lockstep | this directory — `schema/*.capnp` |

Capnp is the schema language for type sync. The wire format of any given message is determined by the protocol implementation (signet ADR-002 §2.3 for CABundle, RFC 5652 DER for CMS, RFC 9449 for DPoP, etc.).

## wire format split (per ADR-010)

| Surface | Format |
|---|---|
| HTTP API (request bodies, response bodies) | JSON |
| KV storage (`CA_BUNDLE_CACHE`) | JSON |
| DO SQLite blob columns | JSON |
| DPoP / JWT tokens | JSON-in-base64 (RFC 7515 / 9449) |
| **Cryptographic canonical bytes (Ed25519 sign/verify input)** | **canonical CBOR (RFC 8949 §4.2)** |

This matches signet exactly. signet's CABundle struct has `json:"..."` tags and is transported as JSON over HTTPS (`pkg/revocation/cabundle/https_fetcher.go`); the canonical CBOR form is computed in-memory via `cbor.CanonicalEncOptions().EncMode()` only at the moment a signature is produced or verified (`pkg/revocation/checker.go:168-188`).

## TS-side canonical-bytes encoder — alignment shipped

**Status (2026-05-10): aligned.** `worker/src/revocation.ts::bundleCanonical()` produces canonical CBOR with integer-keyed map (`{1:Epoch, 2:Seqno, 3:Keys, 4:KeyID, 5:PrevKeyID, 6:IssuedAt}`) per RFC 8949 §4.2 — byte-for-byte matching signet's `pkg/revocation/checker.go:168-188`. Hand-computed fixtures at `worker/src/__tests__/bundle-canonical.test.ts` lock the byte shape.

The previous JSON-of-sorted-keys path was a closed-loop-but-incompatible alternative; bundles now interoperate across signet implementations. Implemented per ADR-010 (`docs/design/010-cross-language-canonical-encoding.md`).

**If you are touching CABundle signature verification, oracle responses, or anything that assumes byte-equality of canonical bytes across languages — read ADR-010 first.**

## still open: schema sync drift (separate concern)

**(P1) capnp-to-ts.ts silent degradation** — the hand-rolled TS generator silently drops fields it doesn't recognize. Independent of the wire-format question (this is type-sync correctness, not signature canonicalization). Tracked in its own bead.

## flow

```mermaid
flowchart LR
    src["schema/identity.capnp<br/>fileId @0xb8e3f1a2c4d5e6f7"]

    subgraph go_path["go path (real capnp)"]
        capnpc_go["capnpc-go<br/>(upstream)"]
        gen_go["../gen/go/identity.capnp.go"]
        signet_pkg["signet/pkg/revocation<br/>(signs CABundle)"]
        worker_verify["../gen/go/verify/<br/>worker Go-side"]
    end

    subgraph ts_path["ts path (hand-rolled)"]
        capnp_to_ts["codegen/capnp-to-ts.ts<br/>regex parser, ~280 LOC"]
        gen_ts["../gen/ts/identity.ts<br/>interfaces + Zod"]
        worker_ts["../worker/src/<br/>revocation.ts, cert-exchange.ts"]
        action_ts["github action<br/>(notme-action)"]
    end

    src --> capnpc_go --> gen_go
    gen_go --> signet_pkg
    gen_go --> worker_verify

    src --> capnp_to_ts --> gen_ts
    gen_ts --> worker_ts
    gen_ts --> action_ts

    signet_pkg -. "signs canonical CBOR (RFC 8949 §4.2)" .-> worker_ts
    worker_ts -. "verifies canonical CBOR (matches byte-for-byte)" .-> signet_pkg

    classDef warn fill:#fee,stroke:#c00,stroke-width:2px
    class capnp_to_ts warn

    divergence["⚠ different toolchains, different wire forms<br/>see notme-803923"]
    capnpc_go -.-> divergence
    capnp_to_ts -.-> divergence
```

## type catalog

Every struct + enum in `identity.capnp`, grouped by section.

### revocation

| type | role |
|---|---|
| `CABundle` | The signed bundle of active CA keys. `epoch` mass-revokes on rotation, `seqno` is monotonic for rollback detection, `signature` is Ed25519 over the canonical bundle (excluding the signature field itself). The cross-language byte-equality of "canonical bundle" is the bug above. |
| `KeyEntry` | One CA public key inside a CABundle: `kid` + raw 32-byte Ed25519 `publicKey`. |
| `TokenClaims` | Embedded in issued tokens — pins the `keyId` + `epoch` they were issued under so the verifier can detect epoch drift. |
| `RevocationReason` (enum) | Why a token was rejected: `epochMismatch`, `unknownKey`, `rollbackAttack`, `bundleInvalid`, `bundleStale`. |
| `RevocationResult` | `{revoked, reason}` pair returned by the revocation check. |

### certificates (008)

| type | role |
|---|---|
| `BridgeCertResult` | **Legacy** single-cert result. `privateKey` field is deprecated-but-kept (always empty in 008+) for wire compat with old `DispatchPredicate.signingCert`. New code uses `BridgeCertPair`. |
| `BridgeCertPair` | The 008 dual-cert result: P-256 mTLS cert + Ed25519 signing cert + WIMSE identity URI + `binding` hash (SHA-256 over both SPKIs) proving they came from the same exchange. Carries `epoch` and `authMethod`. |
| `CertScope` (enum) | `bridgeCert` (standard agent), `authorityManage` (rotate epoch / register creds), `certMint` (delegated authority to issue certs). |
| `AuthorityState` | Worker's current `{epoch, keyId}` — published so signers know which epoch to bind to. |

### authentication

| type | role |
|---|---|
| `CertPairRequest` | 008 PoP cert exchange request. Bundles `{proof, publicKeys, proofs}`. |
| `CertPairPublicKeys` | The two SPKIs the caller wants signed: P-256 (mTLS) + Ed25519 (signing). |
| `CertPairPoP` | Two signatures over the binding payload — ES256 over the P-256 SPKI, EdDSA over the Ed25519 SPKI. Proves the caller holds both private keys. |
| `CertRequest` | **Legacy** single-cert request. `{scopes, proof}`. Replaced by `CertPairRequest` in 008. |
| `Proof` (union) | How the caller authenticated: `ghaOidc` (GHA OIDC token claims), `passkey` (WebAuthn credential ID), `bootstrapCode` (one-shot bootstrap string). |
| `GHAClaims` | The 16 fields lifted from a GitHub Actions OIDC JWT — issuer, sub, audience, jti (replay protection), repository, ref, sha, actor, workflow, jobWorkflowRef, runId, eventName, environment, etc. |

### APAS attestation

| type | role |
|---|---|
| `DispatchPredicate` | The DSSE payload signed when an agent is dispatched onto a bead. Carries `beadRef`, `agent`, `pipeline`, plus both legacy `signingCert :BridgeCertResult` (@3) and 008 `certPair :BridgeCertPair` (@4) for migration. |
| `BeadRef` | `{repo, beadId, contentHash}` — pins the bead and its content hash at dispatch time. |
| `AgentIdentity` | `{name, provider, model, definition}` — provider is `anthropic` / `openai` / etc., `definition` is the sha256 of the agent definition file. |
| `PipelineContext` | `{phases, currentPhase, pipelineId}` — UUID-pinned pipeline state. |
| `HandoffPredicate` | Phase-to-phase handoff DSSE payload. Carries `previousChainHash` + `chainHash` for the audit chain, plus both `signingCert` and `certPair` for the same migration reason as `DispatchPredicate`. |

### signing oracle (ssh-agent pattern)

The oracle protocol is the request/response between an agent and a key holder. The agent does its own TLS handshake but delegates the `CertificateVerify` signature to the oracle so the private key never enters the agent's process. Transport is whatever (UDS / service binding / HTTP); these structs are the protocol.

| type | role |
|---|---|
| `SignRequest` | `{digest, algorithm, purpose}`. `purpose` is an audit string (`tls-client-auth`, `git-commit`, `dsse-attestation`). |
| `SignResponse` | `{signature, identity}`. `identity` is the WIMSE URI of the signer for audit correlation. |
| `OraclePublicKey` | Public key + algorithm + bridge cert PEM + WIMSE identity + expiry. Public data only. |
| `OracleInfo` | What the oracle can do: `{keys, scopes, epoch}`. Typically two keys (P-256 + Ed25519). |

## schema evolution rules

Standard capnp discipline plus the workerd / Sandstorm conventions documented in the RTFM dossier (`ley-line-open/docs/decades/T8/capnp-rtfm-findings.md`):

1. **Append-only ordinals.** Add fields at the next `@N`. Never rename, never repurpose, never reuse. Removing a field is a breaking change.
2. **fileIds are stable** for the life of the file. `identity.capnp` is `@0xb8e3f1a2c4d5e6f7`. If the file moves or is renamed, the explicit ID stays.
3. **Deprecate, don't delete.** Use `# DEPRECATED:` docstring prefix (workerd convention). Live example: `BridgeCertResult.privateKey @1` is deprecated-but-kept; new code reads `BridgeCertPair`.
4. **No on-wire `schemaVersion`.** Capnp's fileId + ordinals + canonical form are the version surface. The RTFM specifically rejects on-the-wire version counters; workerd and Sandstorm both decline to embed one.
5. **Pure-struct schemas, no `interface`.** No live RPC in this layer; we emit data. Future RPC surfaces live in a separate file with a separate fileId.

## codegen

| command | output | toolchain |
|---|---|---|
| `task schema:ts` | `../gen/ts/identity.ts` | `codegen/capnp-to-ts.ts` (in-tree, hand-rolled) |
| `task schema:go` | `../gen/go/identity.capnp.go` | `capnpc-go` (upstream) |
| `task schema:all` | both | both |
| `task schema:check` | diff — fails if `gen/` is stale relative to schema | both |

`gen/` IS committed — consumers don't re-run the generators on every build (matches the workerd / mache convention).

### what `capnp-to-ts.ts` actually supports

It is a regex parser, ~280 LOC. Handles the subset we use, silently skips the rest:

- ✅ `struct` (with nested `union { ... }`)
- ✅ `enum`
- ✅ Scalar types: `Text`, `Data`, `Bool`, `UInt32`, `UInt64`, `Int64`
- ✅ `List(T)` for any `T` it knows about (scalars, enums, structs)
- ✅ Topological sort of struct emission so referenced types come first
- ✅ Trailing `# comment` on a field becomes a TS comment on the field
- ❌ No canonical-encoding emitter — produces TS types + Zod, not wire bytes
- ❌ No segment table, no pointer layout, no message framing
- ❌ No `using`, `import`, `$Go.package`, or any annotation — the `@0xb8e3f1a2c4d5e6f7` fileId and the `$Go.package` annotations at the top of `identity.capnp` are simply not parsed
- ❌ No groups, no generics, no `interface`, no `Float32`/`Float64`/`Int8`/`Int16`/`Int32`/`UInt8`/`UInt16`, no `AnyPointer`, no `Map`-style entries
- ❌ Unknown types fall through to `unknown` / `z.unknown()` — silent rather than fatal

This is fine for what `identity.capnp` currently uses (the schema sticks to the supported subset on purpose). It is **not** fine for the cross-language-byte-equality claim — see the open issue at the top.

## toolchain pin status

Currently **not pinned**. The RTFM recommends pinning the capnp compiler, every generator (`capnpc-go`, `capnp-to-ts.ts`), and every consumer-side runtime by exact version, plus a cross-runtime fixture suite that asserts byte-for-byte equality on a known input. notme has neither.

Tracked as a Tier 2 fix in `notme-803923`.

## related

- **`../gen/`** — generated TS + Go output, both committed.
- **`../worker/src/revocation.ts`** — consumes `gen/ts/identity.ts`. `bundleCanonical()` at line 159 is the JSON-canonicalization site that diverges from real capnp.
- **`../worker/src/cert-exchange.ts`** — consumes `BridgeCertPair` / `CertPairRequest` / `CertPairPoP` for the 008 PoP exchange.
- **`../docs/design/008-bridge-cert-csr-wimse.md`** — what `BridgeCertPair` represents.
- **`../docs/design/006-dpop-tokens.md`** — DPoP wire format (TS-only, separate file at `packages/dpop`).
- **`signet/pkg/revocation/types.go`** — Go-side mirror that signs `CABundle` for the Worker to verify.
- **`ley-line-open/docs/decades/T8/capnp-rtfm-findings.md`** — canonical-encoding rules, fileId discipline, version-counter analysis. Read before changing anything in this directory.
