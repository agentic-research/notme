/**
 * The deployer's full scope set — what the first administrator of an
 * authority holds (notme-486e8a).
 *
 * One constant because it was spelled out by hand at four grant sites
 * (first passkey user, bootstrap code, attested bootstrap, the registration
 * response) — exactly the multiple-hand-maintained-copies shape that let
 * discovery documents drift.
 *
 * It now includes sign:git and sign:attestation. Those were advertised in
 * scopes_supported, and AuthService.sign() requires one of them for its
 * git-commit and dsse formats, but nothing could ever grant them: canGrant
 * requires the grantor to HOLD a scope (ADR-008's subset rule), and no
 * administrator did. The subset rule is right; the admin set was incomplete.
 *
 * `PRIOR_ADMIN_SCOPES` is the set this replaced, used only to recognise an
 * existing deployer when migrating (SigningAuthority.migrateAdminSigningScopes).
 */
export const ADMIN_SCOPES = [
  "bridgeCert",
  "authorityManage",
  "certMint",
  "sign:git",
  "sign:attestation",
] as const;

export const PRIOR_ADMIN_SCOPES = ["bridgeCert", "authorityManage", "certMint"] as const;

export const SIGNING_SCOPES = ["sign:git", "sign:attestation"] as const;
