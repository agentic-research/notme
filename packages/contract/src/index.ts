// @notme/contract — cross-repo contract for the notme ecosystem.
//
// Single source of truth for invariants shared between this repo (consumer)
// and notme.bot (server). Drift here is how confused-deputy bugs and silent
// breakage between the two halves slip in.
//
// Consumed locally as @notme/contract via the workspace.
// notme.bot keeps a byte-identical mirror at src/contract.ts; its
// src/auth/contract.test.ts byte-diffs against this file in CI when both
// repos are checked out side-by-side.
//
// Bump CONTRACT_VERSION on any breaking shape change; the consumer's pinned
// version gates the upgrade. See ./README.md for the rules of the road.

export const CONTRACT_VERSION = 1;

// ── Scope vocabulary ─────────────────────────────────────────────────────
// Any string token that appears in a session cookie or invite MUST be
// declared here. The TypeScript `as const` widens to a string literal
// union — accidental "bridgecert" / "bridgeCerts" / "BridgeCert" drift
// surfaces at compile time in BOTH repos.

export const SCOPES = {
  BRIDGE_CERT: "bridgeCert",
  AUTHORITY_MANAGE: "authorityManage",
  CERT_MINT: "certMint",
  SIGN_GIT: "sign:git",
  SIGN_ATTESTATION: "sign:attestation",
} as const;

export type ScopeName = (typeof SCOPES)[keyof typeof SCOPES];

export const ALL_SCOPES: readonly ScopeName[] = Object.values(SCOPES);

// ── OIDC verification policy contract ────────────────────────────────────
// The shape the server requires. The consumer MUST construct id_token
// requests whose `aud` is in EXPECTED_AUDIENCES and whose issuer is in
// the deployer-configured allowlist (env.OIDC_ALLOWED_ISSUERS).

export const OIDC_ALLOWED_ALGS = ["RS256", "ES256"] as const;
export type OIDCAllowedAlg = (typeof OIDC_ALLOWED_ALGS)[number];

// ── HTTP error-shape contract ────────────────────────────────────────────
// Status codes the server returns for specific failure classes. Consumer
// retry/branch logic depends on these. Any change here is a breaking
// change — bump CONTRACT_VERSION.

export const ERROR_STATUS = {
  // /join, /auth/oidc/login: bad OIDC proof (signature, aud, issuer, nonce)
  OIDC_PROOF_REJECTED: 403,
  // /invites, scope grants: caller lacks the required scope
  SCOPE_INSUFFICIENT: 403,
  // /auth/passkey/reset on populated system without admin session
  RESET_NOT_PERMITTED: 403,
  // /cert/gha: GHA OIDC token failed validation
  GHA_TOKEN_INVALID: 401,
  // /auth/passkey/login/verify: passkey assertion rejected
  AUTH_FAILED: 401,
  // Generic missing/invalid session cookie
  SESSION_REQUIRED: 401,
} as const;
