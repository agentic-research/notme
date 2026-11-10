/**
 * join-nonce.ts — the /join challenge (ADR-023, notme-e3dede).
 *
 * A GitHub Actions OIDC token has no `nonce` claim; the only value a workflow
 * chooses is the audience. So a server nonce for an automated /join travels
 * IN the audience: `<this deployment's authority URL>/join/<nonce>`. A token
 * minted for that audience names one invite on one deployment, and fails
 * every other route, which pins the shared `notme.bot` audience (D3).
 *
 * The nonce is dpop-nonce.ts's stateless construction (compose, ADR-020)
 * with its own domain, and the MAC also covers SHA-256 of the invite token,
 * so a challenge for one invite does not verify against another (D2). It is
 * not single-use by itself and does not need to be: the token's `jti` and
 * the invite are each single-use; the nonce supplies the binding.
 */
import { encodeBase64url } from "@oslojs/encoding";
import { issueMacNonce, verifyMacNonce } from "./dpop-nonce";
import { GOOGLE_ISSUER } from "./verify-proof";

/** Own domain: a DPoP nonce is not a join nonce, and the reverse (D2). */
const JOIN_NONCE_DOMAIN = "notme-join-nonce-v1";

/** As DPoP: one round trip to fetch a token, short enough not to be an asset. */
export const JOIN_NONCE_TTL_SECONDS = 300;

/** base64url(SHA-256(invite token)): the MAC binds the invite without carrying it. */
async function inviteBinding(inviteToken: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(inviteToken));
  return encodeBase64url(new Uint8Array(digest));
}

export async function issueJoinNonce(
  secret: string,
  inviteToken: string,
  now: number = Math.floor(Date.now() / 1000),
): Promise<string> {
  return issueMacNonce(JOIN_NONCE_DOMAIN, secret, now, await inviteBinding(inviteToken));
}

/** False for every rejection, as verifyDpopNonce: no oracle on the format. */
export async function verifyJoinNonce(
  nonce: unknown,
  secret: string,
  inviteToken: string,
  now: number = Math.floor(Date.now() / 1000),
): Promise<boolean> {
  return verifyMacNonce(
    JOIN_NONCE_DOMAIN,
    nonce,
    secret,
    now,
    JOIN_NONCE_TTL_SECONDS,
    await inviteBinding(inviteToken),
  );
}

/** The origin of the configured authority URL, with no trailing slash or path. */
function authorityOrigin(authorityUrl: string): string {
  return new URL(authorityUrl).origin;
}

/** `<authority origin>/join/<nonce>` (D1): per deployment, never a literal. */
export function joinChallengeAudience(authorityUrl: string, nonce: string): string {
  return `${authorityOrigin(authorityUrl)}/join/${nonce}`;
}

/**
 * The nonce in a challenge audience for THIS deployment, or null. Exact
 * prefix match on the origin, then one non-empty segment of nonce characters
 * (digits, `.`, base64url with its `=` padding): another deployment's challenge, plain
 * `notme.bot`, an extra path segment or a query are all null.
 */
export function parseJoinChallengeAudience(aud: unknown, authorityUrl: string): string | null {
  if (typeof aud !== "string") return null;
  const prefix = `${authorityOrigin(authorityUrl)}/join/`;
  if (!aud.startsWith(prefix)) return null;
  const nonce = aud.slice(prefix.length);
  return /^[0-9]+\.[A-Za-z0-9_-]+=*$/.test(nonce) ? nonce : null;
}

/**
 * Whether a token with the plain shared audience may still join (D5, D6).
 * Allowed while JOIN_REQUIRE_NONCE is off. When it is on, refused for every
 * issuer except Google, whose audience is the deployment's client id and
 * cannot carry a nonce; Google binds natively through `nonce` in a browser
 * flow, which is out of scope, so a Google token stays on single-use jti.
 */
export function plainAudienceAllowed(issuer: string, requireNonce: boolean): boolean {
  if (!requireNonce) return true;
  return issuer === GOOGLE_ISSUER;
}

/** `JOIN_REQUIRE_NONCE`, parsed as DPOP_REQUIRE_NONCE: only `true`/`1` enable it. */
export function joinNonceRequired(env: { JOIN_REQUIRE_NONCE?: string }): boolean {
  const raw = env.JOIN_REQUIRE_NONCE?.trim().toLowerCase();
  return raw === "true" || raw === "1";
}
