// OAuth 2.0 Authorization Server Metadata (RFC 8414).
//
// Pure builder, deliberately separated from the fetch handler so it can be
// asserted directly in vitest without a Cache API, an env, or workerd. The
// handler's only job is caching + headers; the CONTENT is what clients trust,
// so the content is what tests pin.
//
// Served at two paths (see worker.ts):
//   /.well-known/oauth-authorization-server  — accurate per RFC 8414
//   /.well-known/openid-configuration        — same body, ONLY because many
//     client libraries probe exclusively there. notme is NOT an OpenID
//     Provider: it issues no id_token and honours no scope=openid.

import { ALL_SCOPES } from "@notme/contract";

/**
 * Grant types advertised by the discovery documents.
 *
 * Single source of truth on purpose: these were previously hand-listed in
 * each document and had already drifted from reality — "github_pat" and
 * "oidc_token_exchange" were advertised publicly but implemented NOWHERE
 * (the authMethod values the code actually emits are gha-oidc, invite,
 * oidc:github, passkey, test). Two hand-maintained copies of a public
 * capability claim is how a discovery document starts lying.
 *
 * Only verified token-issuance paths belong here:
 *   github_actions_oidc — /cert/gha, validateGHAToken
 *   dpop                — mintDPoPToken
 * Session-establishment methods (passkey/invite/oidc:github) are auth
 * methods, not grants, and are deliberately not conflated with these.
 */
export const AUTHORITY_GRANT_TYPES = ["github_actions_oidc", "dpop"] as const;

/** The DPoP *proof* algorithm (client-generated P-256). RFC 9449. */
export const DPOP_PROOF_ALGS = ["ES256"] as const;

/** The *access token* signing algorithm (this authority's Ed25519 master). */
export const ACCESS_TOKEN_ALGS = ["Ed25519"] as const;

export interface AsMetadata {
  issuer: string;
  token_endpoint: string;
  jwks_uri: string;
  grant_types_supported: readonly string[];
  response_types_supported: readonly string[];
  scopes_supported: readonly string[];
  token_endpoint_auth_methods_supported: readonly string[];
  dpop_signing_alg_values_supported: readonly string[];
  algorithms_supported: readonly string[];
  service_documentation: string;
}

/**
 * Build the RFC 8414 metadata document.
 *
 * `authorityUrl` MUST be byte-identical to the URL clients use for discovery.
 * That is the single field capable of breaking real clients: go-oidc's
 * NewProvider ignores every endpoint field but fails hard on issuer mismatch
 * (`if p.Issuer != issuerURL { return nil, &IssuerMismatchError{...} }`).
 * A trailing slash or scheme/host drift between environments breaks discovery
 * for every OIDC client, so it is asserted in as-metadata.test.ts.
 */
export function buildAsMetadata(
  authorityUrl: string,
  siteUrl: string,
): AsMetadata {
  return {
    issuer: authorityUrl,
    // authorization_endpoint is DELIBERATELY ABSENT. RFC 8414 §2: "This is
    // REQUIRED unless no grant types are supported that use the authorization
    // endpoint." notme supports no such grant type — there is no
    // authorization-code flow. /authorize exists but renders HTML and issues
    // no code, so advertising it would point clients at an RFC 6749 §4.1 flow
    // that isn't implemented. Verified safe: go-oidc does not require it.
    token_endpoint: `${authorityUrl}/token`,
    jwks_uri: `${authorityUrl}/.well-known/jwks.json`,
    grant_types_supported: AUTHORITY_GRANT_TYPES,
    // Empty ON PURPOSE, and RFC 8414 §2 is still satisfied (the field is
    // REQUIRED to be a JSON array, not to be non-empty). notme implements NO
    // standard OAuth response type: no authorization-code issuance, no
    // code->token exchange. Listing ["code"] would be a false claim.
    response_types_supported: [],
    // Sourced from @notme/contract's SCOPES — never hand-listed here. That
    // package exists so scope drift fails at compile time in both repos; a
    // hardcoded copy in a DISCOVERY document is the worst place for it to rot,
    // because clients believe it.
    scopes_supported: ALL_SCOPES,
    // The token endpoint authenticates the USER (session cookie) plus a DPoP
    // proof — there is no client credential, so "none" is accurate rather than
    // client_secret_*. NOTE: the X-Client-Cert path was deliberately REMOVED
    // (the header is attacker-controlled without CF mTLS bindings); do not
    // re-add tls_client_auth here without re-adding that verification.
    token_endpoint_auth_methods_supported: ["none"],
    dpop_signing_alg_values_supported: DPOP_PROOF_ALGS,
    algorithms_supported: ACCESS_TOKEN_ALGS,
    service_documentation: `${siteUrl}/architecture`,
  };
}

/**
 * Fields that MUST NOT appear. Their absence is load-bearing: a strict OIDC
 * client fails fast and legibly instead of discovering an "OP", requesting
 * scope=openid, and silently getting no id_token back. Publishing a capability
 * we lack would be worse than publishing nothing — this is a trust substrate.
 * Enforced by test so nobody "helpfully" re-adds them.
 */
export const FORBIDDEN_METADATA_FIELDS = [
  "id_token_signing_alg_values_supported",
  "subject_types_supported",
  "authorization_endpoint",
  "code_challenge_methods_supported",
] as const;
