/**
 * dpop.ts — Shared DPoP utilities and verifier SDK.
 *
 * Provides:
 *   - computeJwkThumbprint() — RFC 7638 JWK Thumbprint
 *   - verifyDPoPToken()      — Full DPoP-bound access token verification
 *   - verifyAccessToken()    — Token-only verification (redirect flows, no DPoP proof)
 *
 * Used by notme (issuer), rig (verifier), and any Cloudflare Worker
 * that needs to verify tokens from auth.notme.bot.
 *
 * Pure Web Crypto — no npm dependencies.
 */

// ── Public types ────────────────────────────────────────────────────────────

/** Minimal KV interface — compatible with CF KV but not coupled to it. */
export interface KVLike {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>;
}

/** Options for verifyAccessToken() — token-only verification without DPoP proof. */
export interface VerifyAccessTokenOptions {
  /** The access_token JWT (EdDSA-signed by auth.notme.bot). */
  token: string;
  /** JWKS endpoint URL (e.g. "https://auth.notme.bot/.well-known/jwks.json"). */
  jwksUrl: string;
  /** Optional KV store for caching the JWKS (1-hour TTL). Falls back to fetch-only. */
  kv?: KVLike;
  /** Provide the Ed25519 public key directly — skips JWKS fetch entirely. */
  publicKey?: CryptoKey;
}

/** Options for verifyDPoPToken(). */
export interface VerifyDPoPTokenOptions {
  /** The access_token JWT (EdDSA-signed by auth.notme.bot). */
  token: string;
  /** The DPoP proof JWT (ES256-signed by the client). */
  proof: string;
  /** Expected HTTP method (e.g. "GET", "POST"). */
  method: string;
  /** Expected request URL — exact match per RFC 9449 Section 4.3. */
  url: string;
  /** JWKS endpoint URL (e.g. "https://auth.notme.bot/.well-known/jwks.json"). */
  jwksUrl: string;
  /** Optional KV store for caching the JWKS (1-hour TTL). Falls back to fetch-only. */
  kv?: KVLike;
  /**
   * Provide the Ed25519 public key directly — skips JWKS fetch entirely.
   * Useful for tests or environments where the key is already known.
   */
  publicKey?: CryptoKey;
}

/** Claims returned on successful verification. */
export interface VerifiedTokenClaims {
  /** Subject (user/principal identifier). */
  sub: string;
  /** Space-separated scope string. */
  scope: string;
  /** Audience. */
  aud: string;
  /** Expiry (Unix seconds). */
  exp: number;
  /** JWT ID. */
  jti: string;
}

// ── JWK Thumbprint (RFC 7638) ───────────────────────────────────────────────

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

// ── DPoP Token Verifier ─────────────────────────────────────────────────────

const JWKS_CACHE_KEY = "__notme_jwks";
const JWKS_TTL = 3600; // 1 hour

/**
 * Verify a DPoP-bound access token from auth.notme.bot.
 *
 * Performs all four verification steps:
 *   1. Fetch the Ed25519 signing key from JWKS (with optional KV caching)
 *   2. Verify the access token's EdDSA signature and validate claims
 *   3. Verify the DPoP proof's ES256 signature and validate htm/htu (exact match)
 *   4. Verify cnf.jkt binding — proof key thumbprint must match token claim
 *
 * @returns Verified token claims on success.
 * @throws Error with a descriptive message on any validation failure.
 */
export async function verifyDPoPToken(
  opts: VerifyDPoPTokenOptions,
): Promise<VerifiedTokenClaims> {
  const { token, proof, method, url, jwksUrl, kv, publicKey } = opts;

  // ── 1. Verify access token ──────────────────────────────────────────────

  const tokenParts = token.split(".");
  if (tokenParts.length !== 3) {
    throw new Error("Malformed access token: expected 3 parts");
  }
  const [tHeaderB64, tPayloadB64, tSigB64] = tokenParts;

  // Get the signing key
  const signingKey = publicKey ?? (await fetchSigningKey(jwksUrl, kv));

  // Verify Ed25519 signature
  const tSigInput = new TextEncoder().encode(`${tHeaderB64}.${tPayloadB64}`);
  const tSig = base64urlDecodeBytes(tSigB64);
  const tokenValid = await crypto.subtle.verify(
    { name: "Ed25519" } as any,
    signingKey,
    tSig,
    tSigInput,
  );
  if (!tokenValid) {
    throw new Error("Invalid access token signature");
  }

  // Parse and validate token claims
  const tPayload = jsonParse(base64urlDecodeStr(tPayloadB64), "access token payload");
  const now = Math.floor(Date.now() / 1000);

  if (typeof tPayload.exp !== "number" || tPayload.exp <= now) {
    throw new Error("Access token expired");
  }
  if (typeof tPayload.iat === "number" && tPayload.iat > now + 60) {
    throw new Error("Access token iat is in the future");
  }
  if (!tPayload.sub || typeof tPayload.sub !== "string") {
    throw new Error("Access token missing sub claim");
  }

  // ── 2. Verify DPoP proof ───────────────────────────────────────────────

  const proofParts = proof.split(".");
  if (proofParts.length !== 3) {
    throw new Error("Malformed DPoP proof: expected 3 parts");
  }
  const [pHeaderB64, pPayloadB64, pSigB64] = proofParts;

  const pHeader = jsonParse(base64urlDecodeStr(pHeaderB64), "DPoP proof header");

  if (pHeader.typ !== "dpop+jwt") {
    throw new Error(`DPoP proof typ must be "dpop+jwt", got "${pHeader.typ}"`);
  }
  if (!pHeader.jwk || typeof pHeader.jwk !== "object") {
    throw new Error("DPoP proof header must contain a jwk");
  }

  // Import proof key and verify signature (support ES256 and EdDSA)
  const proofJwk = pHeader.jwk;
  let proofKey: CryptoKey;
  let verifyAlg: { name: string; hash?: string };

  if (proofJwk.kty === "EC") {
    proofKey = await crypto.subtle.importKey(
      "jwk",
      proofJwk,
      { name: "ECDSA", namedCurve: proofJwk.crv || "P-256" },
      true,
      ["verify"],
    );
    verifyAlg = { name: "ECDSA", hash: "SHA-256" };
  } else if (proofJwk.kty === "OKP" && proofJwk.crv === "Ed25519") {
    proofKey = await crypto.subtle.importKey(
      "jwk",
      proofJwk,
      { name: "Ed25519" } as any,
      true,
      ["verify"],
    );
    verifyAlg = { name: "Ed25519" } as any;
  } else {
    throw new Error(`Unsupported DPoP proof key type: ${proofJwk.kty}`);
  }

  const pSigInput = new TextEncoder().encode(`${pHeaderB64}.${pPayloadB64}`);
  const pSig = base64urlDecodeBytes(pSigB64);
  const proofValid = await crypto.subtle.verify(
    verifyAlg,
    proofKey,
    pSig,
    pSigInput,
  );
  if (!proofValid) {
    throw new Error("Invalid DPoP proof signature");
  }

  // Validate proof claims (strict per RFC 9449 Section 4.3)
  const pPayload = jsonParse(base64urlDecodeStr(pPayloadB64), "DPoP proof payload");

  if (pPayload.htm !== method) {
    throw new Error(
      `DPoP proof htm mismatch: expected "${method}", got "${pPayload.htm}"`,
    );
  }
  if (pPayload.htu !== url) {
    throw new Error(
      `DPoP proof htu mismatch: expected "${url}", got "${pPayload.htu}"`,
    );
  }

  // ── 3. Verify cnf.jkt binding ──────────────────────────────────────────

  if (!tPayload.cnf || !tPayload.cnf.jkt) {
    throw new Error("Access token missing cnf.jkt claim");
  }

  const thumbprint = await computeJwkThumbprint(proofJwk);
  if (thumbprint !== tPayload.cnf.jkt) {
    throw new Error("DPoP key binding mismatch: proof key thumbprint does not match cnf.jkt");
  }

  // ── 4. Return verified claims ──────────────────────────────────────────

  return {
    sub: tPayload.sub,
    scope: tPayload.scope ?? "",
    aud: tPayload.aud ?? "",
    exp: tPayload.exp,
    jti: tPayload.jti ?? "",
  };
}

// ── Access Token Verifier (no DPoP proof) ──────────────────────────────────

/**
 * Verify an access token from auth.notme.bot without requiring a DPoP proof.
 *
 * Use this for redirect flows where the DPoP keypair is ephemeral and lost
 * after the browser redirect. The token's EdDSA signature and claims are
 * verified against the JWKS, but DPoP binding (cnf.jkt) is not checked.
 *
 * The token is still trustworthy: notme verified the DPoP binding at mint time,
 * the token is EdDSA-signed, short-lived (5 min), and JTI-unique.
 */
export async function verifyAccessToken(
  opts: VerifyAccessTokenOptions,
): Promise<VerifiedTokenClaims> {
  const { token, jwksUrl, kv, publicKey } = opts;

  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Malformed access token: expected 3 parts");
  }
  const [headerB64, payloadB64, sigB64] = parts;

  // Get the signing key
  const signingKey = publicKey ?? (await fetchSigningKey(jwksUrl, kv));

  // Verify Ed25519 signature
  const sigInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const sig = base64urlDecodeBytes(sigB64);
  const valid = await crypto.subtle.verify(
    { name: "Ed25519" } as any,
    signingKey,
    sig,
    sigInput,
  );
  if (!valid) {
    throw new Error("Invalid access token signature");
  }

  // Parse and validate claims
  const payload = jsonParse(base64urlDecodeStr(payloadB64), "access token payload");
  const now = Math.floor(Date.now() / 1000);

  if (typeof payload.exp !== "number" || payload.exp <= now) {
    throw new Error("Access token expired");
  }
  if (typeof payload.iat === "number" && payload.iat > now + 60) {
    throw new Error("Access token iat is in the future");
  }
  if (!payload.sub || typeof payload.sub !== "string") {
    throw new Error("Access token missing sub claim");
  }

  return {
    sub: payload.sub,
    scope: payload.scope ?? "",
    aud: payload.aud ?? "",
    exp: payload.exp,
    jti: payload.jti ?? "",
  };
}

// ── JWKS fetching ───────────────────────────────────────────────────────────

/**
 * Fetch the Ed25519 signing key from a JWKS endpoint.
 * If a KV store is provided, the JWKS JSON is cached for 1 hour.
 */
async function fetchSigningKey(
  jwksUrl: string,
  kv?: KVLike,
): Promise<CryptoKey> {
  let jwksJson: string | null = null;

  // Try KV cache first
  if (kv) {
    jwksJson = await kv.get(JWKS_CACHE_KEY);
  }

  // Fetch if not cached
  if (!jwksJson) {
    const res = await fetch(jwksUrl);
    if (!res.ok) {
      throw new Error(`JWKS fetch failed: ${res.status}`);
    }
    jwksJson = await res.text();

    // Cache in KV if available
    if (kv) {
      await kv.put(JWKS_CACHE_KEY, jwksJson, { expirationTtl: JWKS_TTL });
    }
  }

  const jwks = JSON.parse(jwksJson) as {
    keys: Array<{ kty: string; crv: string; x: string; alg?: string; kid?: string }>;
  };
  const jwk = jwks.keys.find(
    (k) => k.kty === "OKP" && k.crv === "Ed25519",
  );
  if (!jwk) {
    throw new Error("No Ed25519 key found in JWKS");
  }

  return crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, crv: jwk.crv, x: jwk.x },
    { name: "Ed25519" } as any,
    false,
    ["verify"],
  );
}

// ── Internal helpers ────────────────────────────────────────────────────────

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

/** Decode a base64url string to a UTF-8 string. */
function base64urlDecodeStr(s: string): string {
  return new TextDecoder().decode(base64urlDecodeBytes(s));
}

/** Parse JSON with a descriptive error. */
function jsonParse(s: string, label: string): Record<string, any> {
  try {
    return JSON.parse(s);
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
}
