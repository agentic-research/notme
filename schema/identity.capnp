@0xb8e3f1a2c4d5e6f7;
using Go = import "/go.capnp";
$Go.package("identity");
$Go.import("github.com/agentic-research/notme/gen/go/identity");

# identity.capnp — Cross-language type definitions for the signet identity stack.
#
# Every type here is code-generated for TypeScript (types + Zod), Go, and Rust.
# This is the SINGLE source of truth. Do not manually define these types
# in any language — import the generated code instead.
#
# CRITICAL: CABundle canonical encoding must produce identical bytes across
# all languages. Cap'n Proto's deterministic binary format guarantees this.

# ── Revocation ──

struct CABundle {
  epoch     @0 :UInt64;    # Incremented on CA key rotation — mass-revokes old certs
  seqno     @1 :UInt64;    # Monotonic — rollback detection (must always increase)
  keys      @2 :List(KeyEntry);  # Active CA public keys
  keyId     @3 :Text;      # Current signing key identifier
  prevKeyId @4 :Text;      # Previous key (graceful rotation window)
  issuedAt  @5 :Int64;     # Unix timestamp (seconds) — staleness check
  signature @6 :Data;      # Ed25519 signature over canonical bundle (excludes this field)
}

struct KeyEntry {
  kid       @0 :Text;
  publicKey @1 :Data;      # Raw Ed25519 public key (32 bytes)
}

struct TokenClaims {
  keyId @0 :Text;
  epoch @1 :UInt64;
}

enum RevocationReason {
  epochMismatch  @0;
  unknownKey     @1;
  rollbackAttack @2;
  bundleInvalid  @3;
  bundleStale    @4;
}

struct RevocationResult {
  revoked @0 :Bool;
  reason  @1 :RevocationReason;
}

# ── Certificates ──

struct BridgeCertResult {
  certificate @0 :Text;    # PEM-encoded X.509 bridge cert
  privateKey  @1 :Text;    # PEM-encoded ephemeral private key (returned once, never stored)
  expiresAt   @2 :Int64;   # Unix timestamp (seconds)
  subject     @3 :Text;    # CN from cert (OIDC sub claim for GHA)
  scope       @4 :CertScope;
}

enum CertScope {
  bridgeCert       @0;     # sign commits, auth to MCP, standard agent operations
  authorityManage  @1;     # rotate epoch, register credentials, manage authority
  certMint         @2;     # mint certs for others (delegated authority)
}

struct AuthorityState {
  epoch @0 :UInt64;
  keyId @1 :Text;
}

# ── Authentication ──

struct CertRequest {
  scopes @0 :List(CertScope);
  proof  @1 :Proof;
}

struct Proof {
  union {
    ghaOidc       @0 :GHAClaims;
    passkey        @1 :Data;    # credential ID
    bootstrapCode  @2 :Text;
  }
}

struct GHAClaims {
  iss              @0  :Text;
  sub              @1  :Text;   # "repo:{owner}/{repo}:ref:refs/heads/{branch}"
  aud              @2  :Text;   # Requested audience (e.g. "notme.bot")
  exp              @3  :Int64;
  iat              @4  :Int64;
  jti              @5  :Text;   # JWT ID — used for replay protection
  repository       @6  :Text;   # "owner/repo"
  repositoryOwner  @7  :Text;
  ref              @8  :Text;   # "refs/heads/main"
  sha              @9  :Text;
  actor            @10 :Text;
  workflow         @11 :Text;
  jobWorkflowRef   @12 :Text;
  runId            @13 :Text;
  eventName        @14 :Text;
  environment      @15 :Text;
}

# ── APAS Attestation ──

struct DispatchPredicate {
  beadRef      @0 :BeadRef;
  agent        @1 :AgentIdentity;
  pipeline     @2 :PipelineContext;
  signingCert  @3 :BridgeCertResult;   # the cert that signed this attestation
}

struct BeadRef {
  repo         @0 :Text;
  beadId       @1 :Text;
  contentHash  @2 :Text;   # sha256:{hex}
}

struct AgentIdentity {
  name         @0 :Text;
  provider     @1 :Text;   # anthropic, openai, etc.
  model        @2 :Text;
  definition   @3 :Text;   # sha256 hash of agent definition file
}

struct PipelineContext {
  phases       @0 :List(Text);
  currentPhase @1 :UInt32;
  pipelineId   @2 :Text;   # UUID
}

struct HandoffPredicate {
  fromPhase         @0 :Text;
  toPhase           @1 :Text;
  summary           @2 :Text;
  filesChanged      @3 :List(Text);
  commitShas        @4 :List(Text);
  previousChainHash @5 :Text;
  chainHash         @6 :Text;
  signingCert       @7 :BridgeCertResult;
}
