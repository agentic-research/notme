// @notme/contract — cross-repo contract for the notme ecosystem.
//
// Single source of truth for invariants shared between the two repos that
// implement the notme protocol:
//   - `notme`     (this package's home) — the CONSUMER side: GHA action,
//                  worker that holds the bridge cert + AuthService, proxy.
//   - `notme.bot` (separate repo) — the SERVER side: the signing authority,
//                  passkey/OIDC login, /cert/* mint endpoints.
//
// Drift between the two is how confused-deputy bugs and silent breakage
// slip in.
//
// Consumed by notme components via the workspace alias `@notme/contract`.
// notme.bot keeps a byte-identical mirror at src/contract.ts because it is
// a separate git repo; its src/auth/contract.test.ts byte-diffs against
// this file in CI when both repos are checked out side-by-side.
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
// Google ID tokens carry aud=<client-id>.apps.googleusercontent.com and
// would fail the audience check, so are intentionally omitted — including
// them here would produce confusing "wrong audience" failures instead of
// clear "untrusted issuer" rejections.

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
