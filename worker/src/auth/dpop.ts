/**
 * dpop.ts — DPoP proof validation (RFC 9449).
 *
 * Validates a DPoP proof JWT and returns the embedded JWK, jti, and thumbprint.
 * Uses Web Crypto for signature verification — no npm crypto dependencies.
 */

import {
  computeJwkThumbprint,
  base64urlDecode,
  jsonParseSafe,
} from "@agentic-research/dpop";

/** Maximum allowed age of a DPoP proof (seconds). */
const MAX_IAT_AGE_SECONDS = 60;

export interface DpopValidationOptions {
  /** Expected HTTP method (e.g. "POST"). */
  htm: string;
  /** Expected HTTP request URL; query and fragment are ignored for `htu`. */
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
 * - Claims: jti present/string, htm matches exactly, normalized htu matches, iat within 60s
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

  const header = jsonParseSafe(
    new TextDecoder().decode(base64urlDecode(headerB64)),
    "DPoP header",
  );
  const payload = jsonParseSafe(
    new TextDecoder().decode(base64urlDecode(payloadB64)),
    "DPoP payload",
  );

  // ── 2. Validate header ─────────────────────────────────────────────────
  if (header.typ !== "dpop+jwt") {
    throw new Error(`DPoP proof typ must be "dpop+jwt", got "${header.typ}"`);
  }
  if (header.alg !== "ES256") {
    throw new Error(`DPoP proof alg must be "ES256", got "${header.alg}"`);
  }
  if (!header.jwk || typeof header.jwk !== "object") {
    throw new Error("DPoP proof header must contain a jwk");
  }
  if (header.jwk.kty !== "EC" || header.jwk.crv !== "P-256") {
    throw new Error("DPoP proof jwk must be EC P-256");
  }
  if (
    ["d", "p", "q", "dp", "dq", "qi", "oth"].some(
      (member) => header.jwk[member] !== undefined,
    )
  ) {
    throw new Error("DPoP proof jwk must not contain private key material");
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
  const signature = base64urlDecode(signatureB64);

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

  if (typeof payload.htm !== "string" || payload.htm !== options.htm) {
    throw new Error(
      `DPoP proof htm mismatch: expected "${options.htm}", got "${payload.htm}"`,
    );
  }

  const proofHtu = normalizeHtu(payload.htu);
  const requestHtu = normalizeHtu(options.htu);
  if (proofHtu === null || requestHtu === null || proofHtu !== requestHtu) {
    throw new Error(
      `DPoP proof htu mismatch: expected "${requestHtu ?? options.htu}", got "${proofHtu ?? payload.htu}"`,
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

function normalizeHtu(value: unknown): string | null {
  if (typeof value !== "string") return null;
  try {
    const parsed = new URL(value);
    parsed.search = "";
    parsed.hash = "";
    return normalizePercentEncoding(parsed.href);
  } catch {
    return null;
  }
}

function normalizePercentEncoding(value: string): string {
  return value.replace(/%[0-9a-fA-F]{2}/g, (triplet) => {
    const codePoint = Number.parseInt(triplet.slice(1), 16);
    const character = String.fromCharCode(codePoint);
    return /[A-Za-z0-9\-._~]/.test(character)
      ? character
      : triplet.toUpperCase();
  });
}
