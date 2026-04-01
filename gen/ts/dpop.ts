/**
 * dpop.ts — Shared DPoP utilities (RFC 7638 JWK Thumbprint).
 *
 * Used by both notme (issuer) and rig (verifier).
 * Pure Web Crypto — no npm dependencies.
 */

/**
 * Compute a JWK Thumbprint per RFC 7638.
 *
 * 1. Extract only the required members for the key type (lexicographically sorted).
 *    - EC (kty "EC"): crv, kty, x, y
 *    - (RSA/OKP could be added later if needed)
 * 2. JSON.stringify with no whitespace.
 * 3. SHA-256 hash via crypto.subtle.digest.
 * 4. Base64url encode (no padding).
 */
export async function computeJwkThumbprint(jwk: JsonWebKey): Promise<string> {
  const canonical = buildCanonicalJson(jwk);
  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonical),
  );
  return base64urlEncode(new Uint8Array(hash));
}

/**
 * Build the canonical JSON representation of a JWK per RFC 7638 Section 3.2.
 * Only includes required members for the key type, sorted lexicographically.
 */
function buildCanonicalJson(jwk: JsonWebKey): string {
  switch (jwk.kty) {
    case "EC": {
      // Required members for EC: crv, kty, x, y (alphabetical order)
      const obj = {
        crv: jwk.crv,
        kty: jwk.kty,
        x: jwk.x,
        y: jwk.y,
      };
      return JSON.stringify(obj);
    }
    case "RSA": {
      // Required members for RSA: e, kty, n (alphabetical order)
      const obj = {
        e: jwk.e,
        kty: jwk.kty,
        n: jwk.n,
      };
      return JSON.stringify(obj);
    }
    case "OKP": {
      // Required members for OKP: crv, kty, x (alphabetical order)
      const obj = {
        crv: jwk.crv,
        kty: jwk.kty,
        x: jwk.x,
      };
      return JSON.stringify(obj);
    }
    default:
      throw new Error(`Unsupported key type: ${jwk.kty}`);
  }
}

/** Base64url encode bytes (no padding). */
function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
