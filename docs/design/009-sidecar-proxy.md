# 009: Identity Sidecar Proxy

> Every agent gets an mTLS-capable sidecar. Keys live in the sidecar's memory. Agents talk to localhost. The kernel enforces the boundary.

## Glossary

Inherits all terms from [008](008-bridge-cert-csr-wimse.md). Additional:

| Term | Definition |
|---|---|
| **Sidecar** | A co-located process that handles identity and network security on behalf of an application workload |
| **Network namespace** | Linux kernel primitive that isolates a process's network stack — the process can only see interfaces assigned to its namespace |
| **cgroup** | Linux kernel primitive for resource isolation and accounting — constrains CPU, memory, network, and device access |
| **UDS** | Unix domain socket — inter-process communication on the same host, with kernel-enforced peer credential verification |
| **Envoy** | CNCF's L7 proxy, used as the data plane in Istio service mesh |
| **Landlock** | Linux security module (5.13+) for unprivileged sandboxing — restricts filesystem and network access |

## Problem

008 defines how bridge certs are issued. This spec defines how they are **held and used**.

The gap: an agent receives identity credentials (cert pair from 008), but:
1. The agent's code shouldn't touch cryptographic keys directly — it's complex, error-prone, and the key must be `extractable: false`
2. Every outbound connection needs mTLS — the agent shouldn't have to configure TLS for every HTTP client it uses
3. Every signable artifact (git commits, attestations) needs the Ed25519 key — the agent shouldn't import crypto libraries
4. Without enforcement, a compromised agent can bypass the proxy and make unauthenticated requests directly

## Solution overview

A **notme sidecar** — a workerd process running the same Worker code as the authority — co-locates with the agent. The sidecar:
- Holds the bridge cert pair + private keys in memory (`extractable: false`)
- Exposes a local HTTP API on `localhost:8788`
- Makes mTLS connections to remote services on behalf of the agent
- Signs artifacts (git commits, DSSE envelopes) on behalf of the agent
- Enforces scope constraints before proxying any request
- Runs in a shared network namespace where the agent can ONLY reach localhost

The agent talks plain HTTP to `localhost:8788`. It never touches a key, a cert, or a TLS configuration.

## Architecture

```
┌──────────────────────────────────────────────────┐
│  network namespace (shared by agent + sidecar)    │
│                                                    │
│  ┌────────────┐        ┌───────────────────────┐  │
│  │  Agent     │ HTTP   │  notme sidecar        │  │
│  │  process   │───────→│  (workerd :8788)       │  │
│  │            │        │                        │  │
│  │  - no keys │        │  - P-256 key (memory)  │──┼──→ mTLS to service A
│  │  - no TLS  │        │  - Ed25519 key (memory)│──┼──→ mTLS to service B
│  │  - no certs│        │  - bridge cert pair    │  │
│  └────────────┘        │  - scope enforcement   │  │
│                        │  - signing API         │  │
│  ┌────────────┐        │  - audit log           │  │
│  │  Another   │ HTTP   │                        │  │
│  │  agent     │───────→│                        │  │
│  └────────────┘        └───────────────────────┘  │
│                                                    │
│  outbound: sidecar only (iptables/nftables rule)  │
│  agents: localhost:8788 is the only reachable addr │
└──────────────────────────────────────────────────┘
```

### Comparison to existing systems

| System | Role | notme sidecar equivalent |
|---|---|---|
| Istio Envoy sidecar | mTLS proxy for microservices | mTLS proxy for AI agents |
| SPIRE Agent | SVID delivery over UDS | Cert holding + signing over HTTP |
| nono | Kernel sandbox + credential injection | Complements: nono sandboxes, sidecar provides identity |
| ssh-agent | Key holding + signing over UDS | Same pattern, but for X.509 + mTLS, not SSH |
| Docker credential helper | Injects registry auth | Similar, but for any service, not just registries |

## Sidecar API

The sidecar exposes these endpoints on `localhost:8788`:

### Proxy: `POST /proxy`

The agent requests the sidecar to make an mTLS-authenticated request on its behalf.

```http
POST /proxy HTTP/1.1
Content-Type: application/json

{
  "url": "https://api.example.com/data",
  "method": "GET",
  "headers": { "Accept": "application/json" }
}
```

The sidecar:
1. Checks that the destination URL is in the allowed destinations list
2. Checks that the request is within the cert's scope
3. Establishes an mTLS connection to the destination using the P-256 bridge cert
4. Forwards the request
5. Returns the response to the agent

Response:
```json
{
  "status": 200,
  "headers": { "content-type": "application/json" },
  "body": "<response from upstream>"
}
```

If scope check fails: `403 { "error": "scope insufficient", "required": "...", "granted": "..." }`
If destination not allowed: `403 { "error": "destination not in allowlist" }`

### Sign: `POST /sign`

The agent requests the sidecar to sign data with the Ed25519 signing key.

```http
POST /sign HTTP/1.1
Content-Type: application/json

{
  "payload": "<base64 of data to sign>",
  "format": "raw" | "dsse" | "git-commit"
}
```

The sidecar:
1. Checks the signing operation is within scope (`sign:git`, `sign:attestation`, etc.)
2. Signs with the Ed25519 private key (never exported)
3. Returns the signature

For `format: "dsse"`, the sidecar wraps the payload in a DSSE envelope and signs it.
For `format: "git-commit"`, the sidecar produces an X.509 commit signature compatible with `gpg.format=x509`.

### Identity: `GET /identity`

Returns the sidecar's current identity and capabilities.

```json
{
  "identity": "wimse://notme.bot/gha/agentic-research/notme",
  "scopes": ["bridgeCert", "sign:git"],
  "certificates": {
    "mtls": "<P-256 cert PEM (public)>",
    "signing": "<Ed25519 cert PEM (public)>"
  },
  "expires_at": 1714060800,
  "authority": { "epoch": 1, "key_id": "6d7681e7" }
}
```

Note: the certs (PEM) are public data. The private keys are never exposed by any endpoint.

### Authority endpoints (passthrough)

The sidecar also serves the identity authority API (same Worker code):
- `/.well-known/jwks.json` — CA public key
- `/.well-known/signet-authority.json` — discovery
- `/cert/gha`, `/cert` — cert issuance (the sidecar can issue its own certs for sub-delegation)

## Enforcement boundary

### Network namespace isolation

On Linux, the agent and sidecar share a network namespace. iptables/nftables rules ensure:

```bash
# Agent process (identified by UID or cgroup) can only reach localhost
iptables -A OUTPUT -m owner --uid-owner agent-uid -d 127.0.0.0/8 -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner agent-uid -j REJECT

# Sidecar process can reach anything (it does the mTLS)
iptables -A OUTPUT -m owner --uid-owner sidecar-uid -j ACCEPT
```

Alternatively, using cgroup net_cls:

```bash
# Tag agent traffic with classid
echo 0x100001 > /sys/fs/cgroup/net_cls/agent/net_cls.classid

# iptables drops tagged traffic to non-localhost
iptables -A OUTPUT -m cgroup --cgroup 0x100001 ! -d 127.0.0.0/8 -j REJECT
```

### macOS enforcement

macOS does not have network namespaces or cgroups. Options:
- **Seatbelt sandbox** (same as nono): `sandbox-exec` with network deny profile
- **PF firewall rules**: per-user outbound filtering
- **Application firewall**: restrict outbound per-binary

macOS enforcement is weaker than Linux — Seatbelt is the best option but is undocumented and Apple-internal. For development, the trust model is "you trust your own machine." For CI (GHA Linux runners), full cgroup enforcement applies.

### Container deployment (Docker/K8s)

In containerized environments, the sidecar runs as a container alongside the agent container:

```yaml
# docker-compose.yml
services:
  notme:
    image: ghcr.io/agentic-research/notme:latest
    ports: ["8788:8788"]
    network_mode: "service:agent"  # share network namespace

  agent:
    image: my-agent:latest
    environment:
      NOTME_URL: http://localhost:8788
    depends_on: [notme]
    # agent can only reach localhost (shared network ns)
```

In Kubernetes:
```yaml
# Sidecar container in the same pod
containers:
  - name: notme-sidecar
    image: ghcr.io/agentic-research/notme:latest
    ports: [{ containerPort: 8788 }]
  - name: agent
    image: my-agent:latest
    env:
      - name: NOTME_URL
        value: http://localhost:8788
```

### GHA CI deployment

```yaml
services:
  notme:
    image: ghcr.io/agentic-research/notme:latest
    ports:
      - 8788:8788

steps:
  - name: Authenticate
    uses: agentic-research/notme/action@main
    with:
      authority_url: http://notme:8788
  # Subsequent steps talk to localhost:8788
```

## Credential lifecycle in the sidecar

```
1. Sidecar starts (workerd serve config.capnp)
   → CA key generated in SigningAuthority DO (extractable:false)
   → Ephemeral mode: key in memory only, not in SQLite

2. Agent authenticates (OIDC, passkey, or bootstrap)
   → Sidecar performs 008 PoP exchange on behalf of agent
   → Receives bridge cert pair from authority
   → OR: sidecar IS the authority (local mode) and self-issues

3. Certs held in memory
   → P-256 private key: used for mTLS (TLS CertificateVerify)
   → Ed25519 private key: used for signing (git, DSSE)
   → Both extractable:false — cannot be serialized

4. Agent makes requests via /proxy
   → Sidecar establishes mTLS with bridge cert
   → Scope checked before every proxy request
   → Every proxied request logged (audit trail)

5. Agent requests signatures via /sign
   → Sidecar signs with Ed25519 key
   → Scope checked before every signature
   → Every signature logged

6. Cert approaches expiry (TTL - 60s)
   → Sidecar re-authenticates and obtains fresh cert pair
   → Old certs dropped, new certs loaded
   → Seamless — no agent-visible interruption

7. Process exits
   → Keys die with the process
   → No cleanup needed — extractable:false means no key material to wipe
```

## Destination allowlist

The sidecar maintains an allowlist of destinations it will proxy to. This prevents SSRF via the proxy:

```json
{
  "allowed_destinations": [
    "*.notme.bot",
    "api.github.com",
    "registry.npmjs.org"
  ],
  "denied_destinations": [
    "169.254.169.254",
    "metadata.google.internal",
    "100.100.100.200"
  ]
}
```

Cloud metadata endpoints are **hard-denied** (same approach as nono). The allowlist is configured at sidecar startup via environment variable or config file.

## Audit trail

Every proxied request and signing operation is logged:

```json
{
  "timestamp": "2026-04-26T12:00:00Z",
  "type": "proxy",
  "identity": "wimse://notme.bot/agent/dev-agent/dispatch/abc123",
  "destination": "https://api.github.com/repos/owner/repo/pulls",
  "method": "POST",
  "scope_checked": "bridgeCert",
  "allowed": true,
  "response_status": 201,
  "duration_ms": 145
}
```

For signing operations:
```json
{
  "timestamp": "2026-04-26T12:00:01Z",
  "type": "sign",
  "identity": "wimse://notme.bot/agent/dev-agent/dispatch/abc123",
  "format": "git-commit",
  "payload_hash": "sha256:abc123...",
  "scope_checked": "sign:git",
  "allowed": true
}
```

These logs feed into APAS attestations — the sidecar IS the execution evidence for the agent's session.

## Relationship to 007 and 008

| Spec | What it defines | Status |
|---|---|---|
| 007 | Private keys never leave process memory (Platform abstraction, ephemeral key storage) | Implemented, merged |
| 008 | Bridge cert issuance via PoP exchange (cert pair, WIMSE identity, scope attenuation) | Designed, not implemented |
| **009** | **Sidecar proxy that holds certs and acts on behalf of agents** | **This spec** |

007 proved the keys can be secretless. 008 defines how to issue the right credentials. 009 defines how to use them.

## Implementation phases

### Phase 1: Proxy + Sign API
- Add `/proxy` and `/sign` endpoints to the existing Worker code
- Destination allowlist (config-driven)
- Audit logging to stdout (structured JSON)
- No network namespace enforcement yet — trust is localhost

### Phase 2: Container image + GHA service
- Update the melange/apko container image
- GHA workflow uses notme as a service container
- Docker Compose example with shared network namespace

### Phase 3: Network namespace enforcement
- Linux: iptables/cgroup rules for agent process isolation
- Integration with nono (if available) for Landlock/Seatbelt sandboxing
- eBPF observability hooks (future — monitor sidecar bypass attempts)

### Phase 4: Cert auto-renewal
- Sidecar re-authenticates before cert expiry
- Transparent to agents — no interruption
- Handles authority unavailability gracefully (cache valid cert, retry)

## Success criteria

1. Agent can make authenticated requests via `curl http://localhost:8788/proxy -d '{"url":"https://api.github.com/..."}'` — no TLS config, no certs, no keys
2. Agent can sign a git commit via `POST /sign` with `format: "git-commit"` — signature verifiable with the bridge cert
3. `/proxy` rejects requests to destinations not in the allowlist
4. `/proxy` rejects requests that exceed the cert's scope
5. Cloud metadata endpoints hard-denied
6. Private keys never appear in any sidecar response or log entry
7. On Linux: agent process in cgroup cannot reach any address except localhost:8788
8. Container image works as GHA service container and Docker Compose sidecar
