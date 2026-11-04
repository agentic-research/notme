// @notme/contract — cross-repo contract for the notme ecosystem.
//
// Single source of truth for invariants shared by the parts of this repo
// that implement the notme protocol on both sides of the wire: the signing
// authority and its /cert/* and login endpoints (worker/), and the
// consumers that hold or present its credentials (action/, proxy/).
//
// Drift between the two sides is how confused-deputy bugs and silent
// breakage slip in.
//
// Consumed via the workspace alias `@notme/contract`. The separate
// notme.bot repo once kept a byte-identical mirror of this file; it is
// archived, so there is no mirror and no cross-repo check.
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

// ── Trusted OIDC issuers (recommended baseline) ──────────────────────────
// The canonical issuer set the protocol is designed around. This is a
// recommendation, NOT a runtime default — the SERVER fails closed: its
// OIDC_ALLOWED_ISSUERS env var defaults to empty, which denies all OIDC
// paths until the deployer explicitly configures the allowlist. The list
// here documents what a sane production deployment should configure.
//
// The CONSUMER side hardcodes its own enforcement Set and SHOULD use this
// list as its source of truth once it migrates off the inlined constant.
//
// Why these specific issuers:
//   - auth.notme.bot       — self-issued, always carries aud=notme.bot.
//   - GitHub Actions       — workflows can mint tokens with arbitrary
//                            audience via core.getIDToken(audience).
// Google ID tokens carry aud=<client-id>.apps.googleusercontent.com, an
// audience that belongs to a DEPLOYMENT, so Google cannot be in a baseline.
// The worker adds it to its per-issuer audience map when the operator sets
// GOOGLE_CLIENT_ID, pinned to that client id (notme-0a1ee8,
// worker/src/auth/verify-proof.ts issuerAudiences).

export const TRUSTED_ISSUERS = [
  "https://auth.notme.bot",
  "https://token.actions.githubusercontent.com",
] as const;

// ── GHA event reject-list for cert exchange ──────────────────────────────
// GitHub-signed `event_name` claim is server-trustable. Tokens minted from
// these events MUST NOT receive a notme bridge cert: pull_request_target
// runs in the UPSTREAM context (upstream secrets, upstream owner) while
// executing fork code, which makes it the classic confused-deputy lane.
// pull_request itself runs in fork context with no secrets, but the owner
// allowlist already covers it; we list it here so the rejection is loud.

export const GHA_REJECTED_EVENTS = [
  "pull_request_target",
  "pull_request",
] as const;
export type GHARejectedEvent = (typeof GHA_REJECTED_EVENTS)[number];

// ── HTTP error-shape contract ────────────────────────────────────────────
// Status codes the server returns for specific failure classes. Consumer
// retry/branch logic depends on these. Any change here is a breaking
// change — bump CONTRACT_VERSION.

export const ERROR_STATUS = {
  // /join: bad OIDC proof (signature, aud, issuer, nonce) offered to redeem
  // an invite. 403, like the garbage-invite refusal beside it, so /join's
  // refusals share one status and the proof check is no oracle for the rest.
  OIDC_PROOF_REJECTED: 403,
  // /auth/oidc/login: bad OIDC proof (signature, aud, issuer, nonce).
  // 401, not 403 (notme-778cbf): this is a login, and a refused credential
  // is an authentication failure (RFC 9110 §15.5.2), the same answer as
  // AUTH_FAILED and GHA_TOKEN_INVALID. OIDC_PROOF_REJECTED used to name this
  // route too, but the route has always answered 401; the entry was wrong,
  // not the route. Additive, so CONTRACT_VERSION is unchanged.
  OIDC_LOGIN_REJECTED: 401,
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
