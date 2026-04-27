# 008: Bridge Certificate Issuance via Proof-of-Possession Exchange

> Workload identity for AI agents. Composed from WIMSE, X.509, in-toto. No bearer tokens issued.

## Glossary

| Term | Definition |
|---|---|
| **notme** | An identity authority for AI agents, deployed as a Cloudflare Worker or locally via workerd |
| **workerd** | Cloudflare's open-source Workers runtime — runs the same code locally as on the CF edge |
| **Bridge cert** | Short-lived X.509 certificate binding a workload's public key to an identity + scoped capabilities |
| **WIMSE** | IETF Workload Identity in Multi-System Environments (`draft-ietf-wimse-s2s-protocol-05`) |
| **WIT** | Workload Identity Token — WIMSE's proof-of-possession JWT (media type `wimse-id+jwt`) |
| **WPT** | Workload Proof Token — per-request JWT proving the caller holds the key confirmed in the WIT |
| **Principal** | A server-generated UUID representing an authenticated entity (human, orchestrator, or agent) |
| **Scope** | A capability grant constraining what operations a credential authorizes |
| **Epoch** | A monotonic counter for the CA key — incrementing it mass-revokes all outstanding certs |
| **Sidecar proxy** | A local process that holds credentials in memory and makes mTLS connections on behalf of workloads (see 009) |
| **APAS** | Agent Provenance Attestation Standard — cryptographically signed execution provenance for agent pipelines |

## Problem

Current agent identity systems face three challenges:

1. **Bearer tokens are the default.** Most agent tooling authenticates with API keys, PATs, or OAuth tokens. Possession equals identity — a stolen token grants full access with no way to distinguish the thief from the owner.

2. **No standard workload identity for agents.** SPIFFE/SPIRE addresses microservice identity. Kubernetes projected SA tokens address pod identity. Neither addresses AI agents that span trust domains (GHA → CF edge → external API), need scoped delegation (human → orchestrator → agent), and require signed provenance trails.

3. **Private keys end up on disk.** Certificate-based systems solve the bearer problem but create a new one: the private key must be stored somewhere. GHA writes it to `$GITHUB_OUTPUT`. Docker mounts it as a volume. Any file-based key is one `cat` away from compromise.

## Solution overview

Issue **proof-of-possession bridge certificates** via a nonce-based exchange. The caller proves it holds the private keys before the authority signs anything. The resulting certs are short-lived (5 minutes), scoped, and carry a WIMSE-standard identity URI. No bearer tokens are issued.

### What's novel vs composed

**Composed from existing standards (battle-tested):**
- WIMSE identity URIs for workload naming (`draft-ietf-wimse-arch-02`)
- Short-lived X.509 certs from OIDC exchange (same model as Sigstore Fulcio)
- in-toto attestation envelope + DSSE signing (CNCF graduated)
- DPoP/proof-of-possession binding (RFC 9449)
- SLSA provenance structure (`buildDefinition` / `runDetails`)

**Novel contributions:**
- **Dual-cert model**: P-256 (transport/mTLS) + Ed25519 (signing/attestation) from a single issuance exchange, cryptographically bound to each other
- **Hierarchical scope attenuation**: each delegation level can only narrow capabilities, never widen — enforced by the cert signature chain (application of object-capability theory to agent delegation)
- **Workload identity for AI agent pipelines**: connecting WIMSE-style identity to agent provenance attestation (APAS/in-toto)

## Identity model

### WIMSE identity URIs

Adopt WIMSE identity URIs as the canonical format. The same URI appears in X.509 SAN, WIT `sub` claims, git signatures, and APAS attestations:

```
wimse://notme.bot/gha/agentic-research/notme        (GHA workflow)
wimse://notme.bot/user/james                         (passkey-authenticated human)
wimse://notme.bot/agent/dev-agent/dispatch/abc123    (dispatched agent)
```

Format: `wimse://{trust-domain}/{context}/{identity}`

The trust domain is a FQDN. The path is scoped within the trust domain. This follows `draft-ietf-wimse-arch-02` Section 3.1 and is compatible with SPIFFE ID conventions.

### Where the identity lives

| Context | Carrier |
|---|---|
| X.509 bridge cert | SubjectAltName URI extension |
| WIMSE WIT | `sub` claim |
| Git commit signature | Cert SAN (visible in `git log --show-signature`) |
| APAS attestation | `signingCert.subject` in DSSE envelope |
| mTLS connection | Client cert SAN extracted by server |

## Certificate issuance exchange

### Proof-of-possession (not CSR)

The exchange is NOT a PKCS#10 Certificate Signing Request. It is a **proof-of-possession certificate issuance exchange**: the caller generates keypairs, signs a binding payload to prove it holds the private keys, and the authority issues certs only after verifying the proofs.

This is analogous to ACME challenge-response (RFC 8555) and FIDO2/WebAuthn registration — prove you hold the key, get a credential.

### Dual-cert model

Each exchange produces **two certificates** from one request. The caller generates two keypairs in-process (`extractable: false`, never serialized) and proves possession of both:

| Cert | Subject key algorithm | Purpose |
|---|---|---|
| mTLS cert | ECDSA P-256 | Transport authentication (CF edge, mTLS-aware services) |
| Signing cert | Ed25519 | Git commits, APAS attestations, DSSE envelopes |

P-256 is required for the mTLS cert because Cloudflare's policy layer (Access, WAF, API Shield) only supports RSA and ECDSA — not EdDSA. Ed25519 is used for signing because it is the algorithm specified by the signet protocol and APAS.

### Cryptographic binding between certs

The two certs are bound by a shared value derived from both public keys:

```
binding = SHA-256(P-256_SPKI_DER || Ed25519_SPKI_DER)
```

This binding is embedded as a custom X.509 extension in both certs. It proves the authority knew both keys at issuance time and prevents an attacker from mixing certs from different exchanges.

### Wire protocol

**Single round-trip. Caller proves possession in the request body.**

```http
POST /cert/gha HTTP/1.1
Authorization: Bearer <GHA OIDC JWT>
Content-Type: application/json

{
  "public_keys": {
    "mtls": "<P-256 SPKI PEM>",
    "signing": "<Ed25519 SPKI PEM>"
  },
  "proofs": {
    "mtls": "<ES256 signature over binding_payload>",
    "signing": "<EdDSA signature over binding_payload>"
  }
}
```

Where `binding_payload = SHA-256(mtls_spki_der || signing_spki_der || SHA-256(oidc_jwt))`.

Each proof is a signature over the same binding payload, proving:
- The caller holds the P-256 private key
- The caller holds the Ed25519 private key
- Both keys are bound to this specific OIDC identity
- The exchange cannot be replayed (OIDC JWT is one-time via JTI)

Response:
```json
{
  "certificates": {
    "mtls": "<P-256 bridge cert PEM>",
    "signing": "<Ed25519 bridge cert PEM>"
  },
  "identity": "wimse://notme.bot/gha/agentic-research/notme",
  "scopes": ["bridgeCert"],
  "expires_at": 1714060800,
  "authority": { "epoch": 1, "key_id": "6d7681e7" }
}
```

No private key in request or response.

## Certificate hierarchy (scope attenuation)

### Three levels

```
CA (Ed25519, born in authority, extractable:false)
  │
  │ Issuance exchange: caller proves possession of both keys
  │ CA signs two certs, returns them
  ▼
Orchestrator bridge cert pair (scoped to dispatch, 5-min TTL)
  │
  │ Same exchange: agent proves possession to orchestrator
  │ Orchestrator signs with its Ed25519 signing cert
  ▼
Agent session cert pair (scoped to step, ≤5-min TTL)
  │
  │ mTLS (P-256) or signed artifact (Ed25519)
  ▼
Service validates cert chain up to CA trust bundle
```

### Scope attenuation (monotonic restriction)

Each level of the hierarchy can only **restrict** capabilities, never widen them. This is the capability attenuation property from object-capability security (Miller's E language, KeyKOS, Capsicum).

```
CA grants:     scope = {bridgeCert, certMint, sign:git, sign:attestation}
Orchestrator:  scope = {bridgeCert, sign:git}           (narrowed — no certMint)
Agent:         scope = {bridgeCert}                      (narrowed further — no signing)
```

**Enforcement model.** The cert signature chain enforces *authenticity* — each cert was signed by its parent. The scope subset check (`cert[n].scopes ⊆ cert[n-1].scopes`) is a *semantic verification step* that relying parties MUST perform. This is cooperative enforcement, not intrinsic — analogous to how application code must check OAuth scopes even though the token signature is valid.

Verifiers MUST implement this algorithm:
```
for each cert in chain (leaf to root):
  verify cert.signature against parent.publicKey
  verify cert.notAfter > now
  verify cert.scopes ⊆ parent.scopes   // MUST check — not optional
  verify cert.identity matches expected WIMSE URI pattern
```

If any step fails, reject the entire chain.

### BasicConstraints and path length

| Level | BasicConstraints | pathlen | KeyUsage |
|---|---|---|---|
| CA | CA=true | 1 (allows one intermediate) | keyCertSign, cRLSign |
| Orchestrator bridge | CA=true | 0 (can sign leaf certs only) | keyCertSign |
| Agent session | CA=false | N/A (leaf) | digitalSignature |

Note: the CA's pathlen MUST be ≥ 1 for the three-level hierarchy. pathlen=0 (current implementation) only permits two levels.

## X.509 extension encoding

### OID namespace

The current OID arc `1.3.6.1.4.1.99999` is a **placeholder**. Production deployments MUST use a registered Private Enterprise Number from IANA. OID assignment:

| OID suffix | Name | Encoding | Description |
|---|---|---|---|
| .1.1 | subjectIdentity | UTF8String | Principal UUID |
| .1.2 | issuanceTime | UTF8String | RFC 3339 timestamp |
| .1.3 | scopes | SEQUENCE OF UTF8String | Granted capabilities |
| .1.4 | epoch | INTEGER | CA epoch at issuance |
| .1.5 | authMethod | UTF8String | How the caller authenticated |
| .1.6 | peerCertBinding | OCTET STRING | SHA-256(P-256 SPKI ‖ Ed25519 SPKI) |

Scopes are encoded as ASN.1 `SEQUENCE OF UTF8String`, not comma-delimited strings, for unambiguous parsing by third-party verifiers.

### nameConstraints (defense-in-depth)

Orchestrator bridge certs SHOULD include nameConstraints restricting the URI SAN namespace of subordinate certs:

```
permittedSubtrees: URI:wimse://notme.bot/agent/*
```

This provides automatic namespace scoping enforced by any conformant X.509 path validator (RFC 5280 Section 4.2.1.10), independent of the custom scope extension.

## Authentication paths

| Context | Mechanism | Proof of possession |
|---|---|---|
| Agent → local sidecar | Plain HTTP over localhost | Trust = same machine (see 009 for cgroup enforcement) |
| Sidecar → remote service | mTLS with P-256 bridge cert | TLS CertificateVerify on every connection |
| GHA action → authority | OIDC (consumed) + PoP exchange (produced) | Nonce signatures prove key possession |
| CLI → authority | mTLS with existing bridge cert | TLS CertificateVerify |
| Browser → authority | WIMSE WIT+WPT (application layer) | WPT signed per-request |
| Git commit | Ed25519 signing cert | Signature on commit object |
| APAS attestation | Ed25519 signing cert + DSSE | Signature on in-toto envelope |

### Relationship to the sidecar proxy (009)

The bridge cert issuance exchange (this spec) produces the credentials. The sidecar proxy (009) holds and uses them. The sidecar:
- Holds both private keys in memory (`extractable: false`)
- Makes mTLS connections on behalf of local agents
- Signs artifacts (git commits, attestations) on behalf of agents
- Enforces scope before proxying any request
- Runs in a network namespace where agents can only reach `localhost`

This is the Istio/Envoy sidecar model applied to AI agents. The agent talks plaintext to localhost; the sidecar handles identity.

### Relationship to nono

[nono](https://nono.sh) provides kernel-level sandboxing (Landlock/Seatbelt) and credential injection (phantom token pattern). notme provides cryptographic workload identity. They are complementary:
- nono ensures the agent cannot escape the sandbox
- notme ensures the agent's requests carry verifiable identity
- nono's phantom tokens handle services that only accept API keys
- notme's bridge certs handle services that support mTLS

A combined deployment: nono sandboxes the agent process, notme's sidecar provides identity-aware mTLS proxying within the sandbox.

## Bearer token policy

notme's **issued credentials** are proof-of-possession bound:
- Bridge certs require the private key (mTLS handshake or signature)
- WIMSE WITs require a matching WPT (per-request proof)

The system **consumes** bearer credentials at trust boundaries:
- GHA OIDC tokens (issued by GitHub, consumed by notme during cert exchange)
- Session cookies (HTTP-only, SameSite, for browser passkey flows)
- Bootstrap codes (single-use, 15-minute TTL, for first-time setup)

These consumed credentials gate the *authorization to obtain* a proof-of-possession credential. They are not propagated.

## Revocation

Bridge certs are ephemeral (5-minute TTL). Revocation is implicit: certs expire before revocation would be needed. No CRL, no OCSP.

For emergency revocation (CA compromise, credential theft within the 5-minute window): increment the CA epoch. All certs signed with the previous epoch are immediately invalid. Verifiers check `cert.epoch == bundle.epoch` (or within a configurable grace window for in-flight requests).

Epoch verification policy: if `cert.epoch < bundle.epoch`, the cert is REJECTED. The grace window (if any) is a deployment-time configuration, not a protocol-level default.

## Interoperability

| System | How |
|---|---|
| Cloudflare mTLS | P-256 cert, CA uploaded to CF trust store |
| Git commit signing | Ed25519 cert, `gpg.format=x509`, `gpgsm` 2.3+ |
| APAS / in-toto | Ed25519 cert in DSSE envelope (`signingCert` field) |
| WIMSE-aware services | SAN URI is a valid WIMSE identity |
| SPIFFE/SPIRE | SAN URI follows SPIFFE URI convention |
| Kubernetes | Projected SA token → cert exchange (same as GHA OIDC) |
| Sigstore/Fulcio | Parallel model (OIDC → short-lived cert) |

### Known interop requirements

- **CF mTLS trust store**: Ed25519 CA signing P-256 subject certs (cross-algorithm) — requires empirical verification with CF's validation stack
- **Git gpgsm**: Ed25519 cert support requires GnuPG 2.3+ / GnuTLS 3.6+
- **Browser WebCrypto**: Ed25519 in Chrome 113+, Firefox 130+, Safari 17+
- **OpenSSL**: Ed25519 requires OpenSSL 1.1.1+

## Migration from current state

| What | Current (007+DPoP) | Target (008) |
|---|---|---|
| `/cert/gha` response | `{ token, token_type: "DPoP" }` | `{ certificates: { mtls, signing }, identity }` |
| Action outputs | `notme_token`, `notme_jkt` | `notme_cert`, `notme_signing_cert`, `notme_identity` |
| Identity format | UUID | `wimse://notme.bot/{context}/{identity}` |
| Primary auth | DPoP proof (per-request) | mTLS (transport layer) |
| Git signing | Not supported | Ed25519 signing cert |
| Cert pair binding | None | SHA-256(SPKI ‖ SPKI) in extension |
| CA pathlen | 0 (blocks 3-level) | 1 (permits orchestrator delegation) |
| Scope encoding | Not enforced | ASN.1 SEQUENCE OF UTF8String, subset check mandatory |

## Success criteria

1. `/cert/gha` returns two PEM certs after verifying PoP nonce signatures. No private key in response.
2. Both certs carry `wimse://notme.bot/...` in SAN URI and a shared peer binding extension.
3. P-256 cert validates against CF mTLS trust store (empirical verification required).
4. Ed25519 cert can sign a git commit (`git -c gpg.format=x509 commit -S`).
5. Scope attenuation enforced: agent cert cannot grant wider scopes than issuer. Verification pseudocode implemented.
6. CA cert has `pathlen >= 1` to support three-level hierarchy.
7. All existing adversarial tests pass + new cert-chain scope-narrowing tests.
8. `grep -r "token_type.*Bearer" worker/src/ action/src/` returns zero results for notme-issued credentials.
