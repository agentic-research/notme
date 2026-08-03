/**
 * pkce.ts — SHA-256 base64url, the one primitive the authorization-code flow
 * needs in three places (ADR-013).
 *
 * Used for two different jobs that happen to share a transform:
 *
 *   1. Hashing an authorization code before it is stored. A code is a live
 *      credential until redeemed, so the DO persists only its digest.
 *   2. Computing the PKCE S256 challenge from a verifier (RFC 7636 §4.2:
 *      `code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`).
 *
 * Both must produce base64url WITHOUT padding — RFC 7636 §4.2 requires it for
 * the challenge, and a padded digest would simply never match a compliant
 * client's. Sharing one helper keeps the two from drifting into different
 * encodings, which would fail as an opaque "invalid_grant" with nothing in
 * the error to suggest an encoding mismatch.
 */

import { encodeBase64urlNoPadding } from "@oslojs/encoding";

/** SHA-256 of a string, base64url-encoded without padding. */
export async function sha256Base64url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return encodeBase64urlNoPadding(new Uint8Array(digest));
}

/**
 * Minimum `code_verifier` length (RFC 7636 §4.1: 43–128 characters).
 *
 * Enforced at redemption rather than trusted: PKCE's whole security argument
 * is the entropy of the verifier, and a client that sent a short one would
 * otherwise get a working flow with none of the protection — failing open,
 * silently, in exactly the component whose job is to not do that.
 */
export const MIN_CODE_VERIFIER_LENGTH = 43;
export const MAX_CODE_VERIFIER_LENGTH = 128;

/**
 * RFC 7636 §4.1 unreserved set: ALPHA / DIGIT / "-" / "." / "_" / "~".
 *
 * Checked so a verifier that round-trips through a URL or a JSON encoder
 * unchanged is the only kind accepted — anything else invites an encoding
 * mismatch between the challenge computed here and the one the client
 * computed locally.
 */
const VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]+$/;

export function isValidCodeVerifier(verifier: unknown): verifier is string {
  return (
    typeof verifier === "string" &&
    verifier.length >= MIN_CODE_VERIFIER_LENGTH &&
    verifier.length <= MAX_CODE_VERIFIER_LENGTH &&
    VERIFIER_PATTERN.test(verifier)
  );
}

/**
 * A `code_challenge` is the base64url of a 32-byte digest — always 43 chars,
 * always from the unreserved set. Rejecting anything else at /authorize means
 * a malformed challenge fails when the flow STARTS, with a diagnosable error,
 * rather than at redemption as an opaque invalid_grant one round-trip later.
 */
export function isValidCodeChallenge(challenge: unknown): challenge is string {
  return (
    typeof challenge === "string" &&
    challenge.length === 43 &&
    VERIFIER_PATTERN.test(challenge)
  );
}
