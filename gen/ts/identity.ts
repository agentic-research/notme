// AUTO-GENERATED from schema/identity.capnp — do not edit manually.
// Run: npx tsx schema/codegen/capnp-to-ts.ts schema/identity.capnp

import { z } from "zod";

export enum RevocationReason {
  epochMismatch = "epochMismatch",
  unknownKey = "unknownKey",
  rollbackAttack = "rollbackAttack",
  bundleInvalid = "bundleInvalid",
  bundleStale = "bundleStale",
}

export const RevocationReasonSchema = z.nativeEnum(RevocationReason);

export enum CertScope {
  bridgeCert = "bridgeCert",
  authorityManage = "authorityManage",
  certMint = "certMint",
}

export const CertScopeSchema = z.nativeEnum(CertScope);

export interface KeyEntry {
  kid: string;
  publicKey: Uint8Array; // Raw Ed25519 public key (32 bytes)
}

export const KeyEntrySchema: z.ZodType<KeyEntry> = z.object({
  kid: z.string(),
  publicKey: z.instanceof(Uint8Array),
}) as any;

export interface CABundle {
  epoch: number; // Incremented on CA key rotation — mass-revokes old certs
  seqno: number; // Monotonic — rollback detection (must always increase)
  keys: KeyEntry[]; // Active CA public keys
  keyId: string; // Current signing key identifier
  prevKeyId: string; // Previous key (graceful rotation window)
  issuedAt: number; // Unix timestamp (seconds) — staleness check
  signature: Uint8Array; // Ed25519 signature over canonical bundle (excludes this field)
}

export const CABundleSchema: z.ZodType<CABundle> = z.object({
  epoch: z.number().int().nonnegative(),
  seqno: z.number().int().nonnegative(),
  keys: z.array(KeyEntrySchema),
  keyId: z.string(),
  prevKeyId: z.string(),
  issuedAt: z.number().int(),
  signature: z.instanceof(Uint8Array),
}) as any;

export interface TokenClaims {
  keyId: string;
  epoch: number;
}

export const TokenClaimsSchema: z.ZodType<TokenClaims> = z.object({
  keyId: z.string(),
  epoch: z.number().int().nonnegative(),
}) as any;

export interface RevocationResult {
  revoked: boolean;
  reason: RevocationReason;
}

export const RevocationResultSchema: z.ZodType<RevocationResult> = z.object({
  revoked: z.boolean(),
  reason: RevocationReasonSchema,
}) as any;

export interface BridgeCertResult {
  certificate: string; // PEM-encoded X.509 bridge cert
  privateKey: string; // DEPRECATED — always empty in 008+. Kept for wire compat.
  expiresAt: number; // Unix timestamp (seconds)
  subject: string; // CN from cert (principal UUID or OIDC sub)
  scope: CertScope;
}

export const BridgeCertResultSchema: z.ZodType<BridgeCertResult> = z.object({
  certificate: z.string(),
  privateKey: z.string(),
  expiresAt: z.number().int(),
  subject: z.string(),
  scope: CertScopeSchema,
}) as any;

export interface BridgeCertPair {
  mtlsCert: string; // PEM — P-256 cert for mTLS transport auth
  signingCert: string; // PEM — Ed25519 cert for git commits + APAS attestations
  scopes: string[]; // Granted capabilities (string-based, not enum — extensible)
  expiresAt: number; // Unix timestamp (seconds)
  subject: string; // Principal UUID or OIDC sub
  binding: string; // SHA-256(P-256 SPKI || Ed25519 SPKI) hex — proves both certs from same exchange
  epoch: number; // CA epoch at issuance
  authMethod: string; // How the caller authenticated (gha-oidc, passkey, bootstrap)
}

export const BridgeCertPairSchema: z.ZodType<BridgeCertPair> = z.object({
  mtlsCert: z.string(),
  signingCert: z.string(),
  scopes: z.array(z.string()),
  expiresAt: z.number().int(),
  subject: z.string(),
  binding: z.string(),
  epoch: z.number().int().nonnegative(),
  authMethod: z.string(),
}) as any;

export interface AuthorityState {
  epoch: number;
  keyId: string;
}

export const AuthorityStateSchema: z.ZodType<AuthorityState> = z.object({
  epoch: z.number().int().nonnegative(),
  keyId: z.string(),
}) as any;

export interface GHAClaims {
  iss: string;
  aud: string; // Requested audience (e.g. "notme.bot")
  exp: number;
  iat: number;
  jti: string; // JWT ID — used for replay protection
  repository: string; // "owner/repo"
  repositoryOwner: string;
  ref: string; // "refs/heads/main"
  sha: string;
  actor: string;
  workflow: string;
  jobWorkflowRef: string;
  runId: string;
  eventName: string;
  environment: string;
}

export const GHAClaimsSchema: z.ZodType<GHAClaims> = z.object({
  iss: z.string(),
  aud: z.string(),
  exp: z.number().int(),
  iat: z.number().int(),
  jti: z.string(),
  repository: z.string(),
  repositoryOwner: z.string(),
  ref: z.string(),
  sha: z.string(),
  actor: z.string(),
  workflow: z.string(),
  jobWorkflowRef: z.string(),
  runId: z.string(),
  eventName: z.string(),
  environment: z.string(),
}) as any;

export interface Proof {
  // union — exactly one field is set
  ghaOidc?: GHAClaims;
  passkey?: Uint8Array;
  bootstrapCode?: string;
}

export const ProofSchema: z.ZodType<Proof> = z.object({
  ghaOidc: GHAClaimsSchema.optional(),
  passkey: z.instanceof(Uint8Array).optional(),
  bootstrapCode: z.string().optional(),
}) as any;

export interface CertPairPublicKeys {
  mtls: string; // P-256 SPKI PEM
  signing: string; // Ed25519 SPKI PEM
}

export const CertPairPublicKeysSchema: z.ZodType<CertPairPublicKeys> = z.object({
  mtls: z.string(),
  signing: z.string(),
}) as any;

export interface CertPairPoP {
  mtls: Uint8Array; // ES256 signature over binding payload
  signing: Uint8Array; // EdDSA signature over binding payload
}

export const CertPairPoPSchema: z.ZodType<CertPairPoP> = z.object({
  mtls: z.instanceof(Uint8Array),
  signing: z.instanceof(Uint8Array),
}) as any;

export interface CertPairRequest {
  proof: Proof; // How the caller authenticated
  publicKeys: CertPairPublicKeys; // P-256 + Ed25519 SPKI PEMs
  proofs: CertPairPoP; // Signatures over binding payload
}

export const CertPairRequestSchema: z.ZodType<CertPairRequest> = z.object({
  proof: ProofSchema,
  publicKeys: CertPairPublicKeysSchema,
  proofs: CertPairPoPSchema,
}) as any;

export interface CertRequest {
  scopes: CertScope[];
  proof: Proof;
}

export const CertRequestSchema: z.ZodType<CertRequest> = z.object({
  scopes: z.array(CertScopeSchema),
  proof: ProofSchema,
}) as any;

export interface BeadRef {
  repo: string;
  beadId: string;
}

export const BeadRefSchema: z.ZodType<BeadRef> = z.object({
  repo: z.string(),
  beadId: z.string(),
}) as any;

export interface AgentIdentity {
  name: string;
  provider: string; // anthropic, openai, etc.
  model: string;
  definition: string; // sha256 hash of agent definition file
}

export const AgentIdentitySchema: z.ZodType<AgentIdentity> = z.object({
  name: z.string(),
  provider: z.string(),
  model: z.string(),
  definition: z.string(),
}) as any;

export interface PipelineContext {
  phases: string[];
  currentPhase: number;
  pipelineId: string; // UUID
}

export const PipelineContextSchema: z.ZodType<PipelineContext> = z.object({
  phases: z.array(z.string()),
  currentPhase: z.number().int().nonnegative(),
  pipelineId: z.string(),
}) as any;

export interface DispatchPredicate {
  beadRef: BeadRef;
  agent: AgentIdentity;
  pipeline: PipelineContext;
  signingCert: BridgeCertResult; // the cert that signed this attestation (legacy format)
  certPair: BridgeCertPair; // 008: full cert pair with WIMSE identity
}

export const DispatchPredicateSchema: z.ZodType<DispatchPredicate> = z.object({
  beadRef: BeadRefSchema,
  agent: AgentIdentitySchema,
  pipeline: PipelineContextSchema,
  signingCert: BridgeCertResultSchema,
  certPair: BridgeCertPairSchema,
}) as any;

export interface HandoffPredicate {
  fromPhase: string;
  toPhase: string;
  summary: string;
  filesChanged: string[];
  commitShas: string[];
  previousChainHash: string;
  chainHash: string;
  signingCert: BridgeCertResult;
  certPair: BridgeCertPair; // 008: full cert pair
}

export const HandoffPredicateSchema: z.ZodType<HandoffPredicate> = z.object({
  fromPhase: z.string(),
  toPhase: z.string(),
  summary: z.string(),
  filesChanged: z.array(z.string()),
  commitShas: z.array(z.string()),
  previousChainHash: z.string(),
  chainHash: z.string(),
  signingCert: BridgeCertResultSchema,
  certPair: BridgeCertPairSchema,
}) as any;

