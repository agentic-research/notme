// JWT access token minting and verification for auth.notme.bot.
//
// Tokens are EdDSA-signed JWTs (at+jwt) bound to a DPoP key via cnf.jkt.
// See docs/design/006-dpop-tokens.md for the full design.
//
// Uses Web Crypto (crypto.subtle) for Ed25519 signing/verification.
// No npm JWT libraries — this is intentionally minimal.

import {
  encodeBase64urlNoPadding,
  decodeBase64urlIgnorePadding,
} from "@oslojs/encoding";

const ISSUER = "https://auth.notme.bot";
const TOKEN_LIFETIME_SECONDS = 300; // 5 minutes

export interface MintAccessTokenParams {
  sub: string;
  scope: string;
  audience: string;
  jkt: string;
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
  return encodeBase64urlNoPadding(new TextEncoder().encode(json));
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
  const { sub, scope, audience, jkt, signingKey, keyId } = params;

  const header: Record<string, unknown> = {
    typ: "at+jwt",
    alg: "EdDSA",
    kid: keyId,
  };

  const iat = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    sub,
    iss: ISSUER,
    aud: audience,
    iat,
    nbf: iat,
    exp: iat + TOKEN_LIFETIME_SECONDS,
    jti: crypto.randomUUID(),
    scope,
    cnf: { jkt },
  };

  const headerB64 = encodeJwtPart(header);
  const payloadB64 = encodeJwtPart(payload);
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);

  const signature = new Uint8Array(
    await crypto.subtle.sign("Ed25519" as any, signingKey, signingInput),
  );
  const signatureB64 = encodeBase64urlNoPadding(signature);

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
  const signature = decodeBase64urlIgnorePadding(signatureB64);

  const valid = await crypto.subtle.verify(
    "Ed25519" as any,
    publicKey,
    signature,
    signingInput,
  );

  if (!valid) {
    throw new Error("Invalid signature");
  }

  // Parse payload
  const payloadBytes = decodeBase64urlIgnorePadding(payloadB64);
  const payload = JSON.parse(new TextDecoder().decode(payloadBytes));

  // Check expiry
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp <= now) {
    throw new Error("Token expired");
  }

  return {
    sub: payload.sub,
    scope: payload.scope,
    aud: payload.aud,
    cnf: payload.cnf,
    exp: payload.exp,
    jti: payload.jti,
  };
}
