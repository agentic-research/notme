/**
 * dpop.ts — DPoP proof validation (RFC 9449).
 *
 * Validates a DPoP proof JWT and returns the embedded JWK, jti, and thumbprint.
 * Uses Web Crypto for signature verification — no npm crypto dependencies.
 */

import { computeJwkThumbprint } from "../../../gen/ts/dpop";

/** Maximum allowed age of a DPoP proof (seconds). */
const MAX_IAT_AGE_SECONDS = 60;

export interface DpopValidationOptions {
  /** Expected HTTP method (e.g. "POST"). */
  htm: string;
  /** Expected HTTP request URL (e.g. "https://auth.notme.bot/token"). */
  htu: string;
  /** Server-issued nonce — if provided, proof must contain matching nonce claim. */
  nonce?: string;
  /** Expected access token hash (base64url SHA-256) — for resource server use. */
  accessTokenHash?: string;
}

export interface DpopValidationResult {
  /** The public JWK from the proof header. */
  jwk: JsonWebKey;
  /** The jti claim — caller should use for replay detection. */
  jti: string;
  /** RFC 7638 JWK Thumbprint of the proof key. */
  thumbprint: string;
}

/**
 * Validate a DPoP proof JWT per RFC 9449.
 *
 * Checks:
 * - JWT structure (header.payload.signature, base64url encoded)
 * - Header: typ === "dpop+jwt", alg === "ES256", jwk present (EC P-256)
 * - Signature: verified with the embedded JWK
 * - Claims: jti present/string, htm matches, htu matches, iat within 60s
 * - Optional: nonce matches if provided
 * - Optional: ath matches accessTokenHash if provided
 *
 * @throws Error with descriptive message on any validation failure.
 */
export async function validateDpopProof(
  proof: string,
  options: DpopValidationOptions,
): Promise<DpopValidationResult> {
  // ── 1. Parse JWT structure ──────────────────────────────────────────────
  const parts = proof.split(".");
  if (parts.length !== 3) {
    throw new Error("DPoP proof must have 3 parts (header.payload.signature)");
  }
  const [headerB64, payloadB64, signatureB64] = parts;

  const header = jsonParse(base64urlDecode(headerB64), "header");
  const payload = jsonParse(base64urlDecode(payloadB64), "payload");

  // ── 2. Validate header ─────────────────────────────────────────────────
  if (header.typ !== "dpop+jwt") {
    throw new Error(
      `DPoP proof typ must be "dpop+jwt", got "${header.typ}"`,
    );
  }
  if (header.alg !== "ES256") {
    throw new Error(
      `DPoP proof alg must be "ES256", got "${header.alg}"`,
    );
  }
  if (!header.jwk || typeof header.jwk !== "object") {
    throw new Error("DPoP proof header must contain a jwk");
  }
  if (header.jwk.kty !== "EC" || header.jwk.crv !== "P-256") {
    throw new Error("DPoP proof jwk must be EC P-256");
  }

  // ── 3. Verify signature ────────────────────────────────────────────────
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    header.jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );

  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = base64urlDecodeBytes(signatureB64);

  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    signature,
    signingInput,
  );
  if (!valid) {
    throw new Error("DPoP proof signature verification failed");
  }

  // ── 4. Validate claims ─────────────────────────────────────────────────
  if (!payload.jti || typeof payload.jti !== "string") {
    throw new Error("DPoP proof must contain a jti claim (string)");
  }

  if (payload.htm !== options.htm) {
    throw new Error(
      `DPoP proof htm mismatch: expected "${options.htm}", got "${payload.htm}"`,
    );
  }

  if (payload.htu !== options.htu) {
    throw new Error(
      `DPoP proof htu mismatch: expected "${options.htu}", got "${payload.htu}"`,
    );
  }

  if (typeof payload.iat !== "number") {
    throw new Error("DPoP proof must contain a numeric iat claim");
  }
  const now = Math.floor(Date.now() / 1000);
  const age = now - payload.iat;
  if (age > MAX_IAT_AGE_SECONDS || age < -MAX_IAT_AGE_SECONDS) {
    throw new Error(
      `DPoP proof iat is too old or in the future (age: ${age}s, max: ${MAX_IAT_AGE_SECONDS}s)`,
    );
  }

  // ── 5. Optional: nonce ─────────────────────────────────────────────────
  if (options.nonce !== undefined) {
    if (payload.nonce !== options.nonce) {
      throw new Error(
        `DPoP proof nonce mismatch: expected "${options.nonce}", got "${payload.nonce}"`,
      );
    }
  }

  // ── 6. Optional: access token hash (ath) ───────────────────────────────
  if (options.accessTokenHash !== undefined) {
    if (payload.ath !== options.accessTokenHash) {
      throw new Error(
        `DPoP proof ath mismatch: expected "${options.accessTokenHash}", got "${payload.ath}"`,
      );
    }
  }

  // ── 7. Compute thumbprint ──────────────────────────────────────────────
  const thumbprint = await computeJwkThumbprint(header.jwk);

  return {
    jwk: header.jwk,
    jti: payload.jti,
    thumbprint,
  };
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/** Decode a base64url string to a UTF-8 string. */
function base64urlDecode(s: string): string {
  // Restore standard base64
  const base64 = s.replace(/-/g, "+").replace(/_/g, "/");
  // Pad to multiple of 4
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  // Decode as UTF-8
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}

/** Decode a base64url string to raw bytes. */
function base64urlDecodeBytes(s: string): Uint8Array {
  const base64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** Parse JSON with a descriptive error. */
function jsonParse(s: string, label: string): Record<string, any> {
  try {
    return JSON.parse(s);
  } catch {
    throw new Error(`DPoP proof ${label} is not valid JSON`);
  }
}
