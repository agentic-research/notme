// JWT access token minting and verification for auth.notme.bot.
//
// Tokens are EdDSA-signed JWTs (at+jwt) bound to a DPoP key via cnf.jkt.
// See docs/design/006-dpop-tokens.md for the full design.
//
// Uses Web Crypto (crypto.subtle) for Ed25519 signing/verification.
// No npm JWT libraries — this is intentionally minimal.

import {
  base64urlEncode,
  base64urlDecode,
  validateClaims,
} from "@agentic-research/dpop";
import { ED25519 } from "../platform";

const TOKEN_LIFETIME_SECONDS = 300; // 5 minutes

/** The documented default when no environment is configured. */
const DEFAULT_ISSUER = "https://auth.notme.bot";

/**
 * This deployment's token issuer.
 *
 * Replaces a module constant that was used for BOTH minting and verifying.
 * That made a non-production deployment internally self-consistent while
 * externally lying: staging advertised `issuer: https://auth-staging...` in
 * its discovery document (which is env-derived) and then minted tokens
 * asserting the PRODUCTION issuer, signed with the staging key — an RFC 8414
 * §2 violation requiring no attacker. Because verification used the same
 * constant, staging also accepted production-issued tokens on their claims,
 * failing only on signature, so any staging token-path exercise came back
 * green while proving nothing about issuer identity (notme-28baf2).
 *
 * Mint and verify must move together, which is why `issuer` is now a required
 * parameter of both rather than a default either can silently inherit.
 *
 * Absent vs malformed, as elsewhere in this codebase: absent means "no
 * environment configured" and yields the production default; malformed means
 * the operator configured something and got it wrong, and silently issuing
 * production-issuer tokens from a misconfigured environment is the defect
 * being closed — so it throws.
 */
export function issuerFromEnv(env: { SIGNET_AUTHORITY_URL?: string }): string {
  if (!env.SIGNET_AUTHORITY_URL) return DEFAULT_ISSUER;
  const u = new URL(env.SIGNET_AUTHORITY_URL); // throws on malformed
  if (u.protocol !== "https:" && u.protocol !== "http:") {
    throw new TypeError(
      `SIGNET_AUTHORITY_URL must be http(s) to be a token issuer; got ${u.protocol}`,
    );
  }
  if (!u.host) throw new TypeError("SIGNET_AUTHORITY_URL has no host");
  return u.origin;
}

export interface MintAccessTokenParams {
  sub: string;
  scope: string;
  audience: string;
  /** JWK thumbprint — if provided, token is DPoP-bound (cnf.jkt). If omitted, token is unbound (Bearer/redirect). */
  jkt?: string;
  /**
   * This deployment's issuer — see issuerFromEnv. REQUIRED so no mint site
   * can inherit a hardcoded one.
   */
  issuer: string;
  signingKey: CryptoKey;
  keyId: string;
}

export interface AccessTokenClaims {
  sub: string;
  scope: string;
  aud: string;
  cnf: { jkt: string };
  exp: number;
  jti: string;
}

function encodeJwtPart(obj: Record<string, unknown>): string {
  const json = JSON.stringify(obj);
  return base64urlEncode(new TextEncoder().encode(json));
}

/**
 * Mint an EdDSA-signed JWT access token.
 *
 * Header: { typ: "at+jwt", alg: "EdDSA", kid }
 * Payload: sub, iss, aud, iat, nbf, exp, jti, scope, cnf.jkt
 * Signature: Ed25519 over base64url(header).base64url(payload)
 */
export async function mintAccessToken(
  params: MintAccessTokenParams,
): Promise<string> {
  const { sub, scope, audience, jkt, issuer, signingKey, keyId } = params;

  const header: Record<string, unknown> = {
    typ: "at+jwt",
    alg: "EdDSA",
    kid: keyId,
  };

  const iat = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    sub,
    iss: issuer,
    aud: audience,
    iat,
    nbf: iat,
    exp: iat + TOKEN_LIFETIME_SECONDS,
    jti: crypto.randomUUID(),
    scope,
    ...(jkt ? { cnf: { jkt } } : {}),
  };

  const headerB64 = encodeJwtPart(header);
  const payloadB64 = encodeJwtPart(payload);
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);

  const signature = new Uint8Array(
    await crypto.subtle.sign(ED25519, signingKey, signingInput),
  );
  const signatureB64 = base64urlEncode(signature);

  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

/**
 * Verify an EdDSA-signed JWT access token.
 *
 * Checks:
 * 1. Valid 3-part JWT structure
 * 2. Ed25519 signature against the provided public key
 * 3. Token not expired (exp > now)
 *
 * Returns parsed claims on success, throws on failure.
 */
export async function verifyAccessToken(
  token: string,
  publicKey: CryptoKey,
  /**
   * This deployment's issuer. REQUIRED: a verifier that defaults its issuer
   * accepts another environment's tokens on their claims.
   */
  issuer: string,
): Promise<AccessTokenClaims> {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT: expected 3 parts");
  }

  const [headerB64, payloadB64, signatureB64] = parts;

  // Verify Ed25519 signature
  const signingInput = new TextEncoder().encode(
    `${headerB64}.${payloadB64}`,
  );
  const signature = base64urlDecode(signatureB64);

  const valid = await crypto.subtle.verify(
    ED25519,
    publicKey,
    signature,
    signingInput,
  );

  if (!valid) {
    throw new Error("Invalid signature");
  }

  // Parse payload
  const payloadBytes = base64urlDecode(payloadB64);
  const payload = JSON.parse(new TextDecoder().decode(payloadBytes));

  // Require exp — tokens without expiry must never be accepted
  if (typeof payload.exp !== "number") {
    throw new Error("missing exp claim");
  }
  validateClaims(payload, {
    issuer,
  });

  return {
    sub: payload.sub,
    scope: payload.scope,
    aud: payload.aud,
    cnf: payload.cnf,
    exp: payload.exp,
    jti: payload.jti,
  };
}
