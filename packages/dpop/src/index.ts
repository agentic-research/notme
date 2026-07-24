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

// ── Stable error codes ──────────────────────────────────────────────────────

/**
 * Stable, machine-readable error codes for every failure this SDK's
 * verifiers can throw. `message` is for humans and may be reworded over
 * time; `code` is the part API consumers should match on — added because
 * cloister and canonical-hours had each independently started matching on
 * message *substrings*, which silently breaks if a message is ever
 * reworded (notme-3bc238).
 */
export type VerifyErrorCode =
  | "CONFIG_AUDIENCE_REQUIRED"
  | "MALFORMED_TOKEN"
  | "TOKEN_SIGNATURE_INVALID"
  | "TOKEN_TYP_INVALID"
  | "TOKEN_EXP_MISSING"
  | "MALFORMED_PROOF"
  | "PROOF_TYP_INVALID"
  | "PROOF_ALG_UNSUPPORTED"
  | "PROOF_JWK_MISSING"
  | "PROOF_JWK_PRIVATE"
  | "PROOF_JWK_INVALID"
  | "PROOF_KEY_TYPE_UNSUPPORTED"
  | "PROOF_SIGNATURE_INVALID"
  | "PROOF_JTI_MISSING"
  | "PROOF_REPLAY"
  | "PROOF_IAT_MISSING"
  | "PROOF_IAT_STALE"
  | "PROOF_HTM_MISMATCH"
  | "PROOF_HTU_MISMATCH"
  | "PROOF_ATH_MISSING"
  | "PROOF_ATH_MISMATCH"
  | "CNF_JKT_MISSING"
  | "CNF_JKT_MISMATCH"
  | "BEARER_TOKEN_DPOP_BOUND"
  | "JWKS_FETCH_FAILED"
  | "JWKS_NO_KEY_FOUND"
  | "JWK_KEY_TYPE_UNSUPPORTED"
  | "JWK_INVALID"
  | "BASE64URL_DECODE_FAILED"
  | "JSON_PARSE_FAILED"
  | "JSON_NOT_OBJECT"
  | "CLAIM_EXP_INVALID_TYPE"
  | "CLAIM_EXP_EXPIRED"
  | "CLAIM_NBF_INVALID_TYPE"
  | "CLAIM_NBF_NOT_YET_VALID"
  | "CLAIM_IAT_INVALID_TYPE"
  | "CLAIM_IAT_FUTURE"
  | "CLAIM_ISS_MISSING"
  | "CLAIM_ISS_MISMATCH"
  | "CLAIM_AUD_MISSING"
  | "CLAIM_AUD_INVALID_TYPE"
  | "CLAIM_AUD_MISMATCH"
  | "CLAIM_SUB_MISSING"
  | "CLAIM_SUB_INVALID_TYPE";

/**
 * Thrown by every verifier/parser in this module. `code` is the stable
 * contract; `message` is human-readable and NOT guaranteed to stay
 * word-for-word identical across versions (though changing it is a
 * courtesy break, not a contract break — `code` is what's guaranteed).
 */
export class DPoPVerificationError extends Error {
  readonly code: VerifyErrorCode;
  constructor(code: VerifyErrorCode, message: string) {
    super(message);
    this.name = "DPoPVerificationError";
    this.code = code;
    // Restore the prototype chain — down-level TS compile targets can lose
    // it across `extends Error`, breaking `instanceof` checks otherwise.
    Object.setPrototypeOf(this, DPoPVerificationError.prototype);
  }
}

// ── Public types ────────────────────────────────────────────────────────────

/** Minimal KV interface — compatible with CF KV but not coupled to it. */
export interface KVLike {
  get(key: string): Promise<string | null>;
  put(
    key: string,
    value: string,
    opts?: { expirationTtl?: number },
  ): Promise<void>;
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
  /**
   * Expected audience — string or array. REQUIRED. Resource servers MUST
   * set this to their own URL to prevent confused-deputy: a token minted
   * for a different resource server (same notme issuer, same public key)
   * would otherwise pass this verifier.
   *
   * Enforced at runtime as well as at the type level; empty strings and
   * empty arrays are rejected.
   */
  audience: string | string[];
  /**
   * Expected issuer — when set, rejects tokens whose `iss` claim doesn't
   * match. Defaults to no check so the SDK works with self-hosted notme
   * deployments under different domains; notme-internal callers should
   * pass `"https://auth.notme.bot"`.
   */
  issuer?: string;
}

/** Options for verifyDPoPToken(). */
export interface VerifyDPoPTokenOptions {
  /** The access_token JWT (EdDSA-signed by auth.notme.bot). */
  token: string;
  /** The DPoP proof JWT (ES256 or EdDSA-signed by the client). */
  proof: string;
  /** Expected HTTP method (e.g. "GET", "POST"). */
  method: string;
  /**
   * Request URL. Query and fragment are removed before comparison with `htu`;
   * absolute-URL normalization follows the platform URL implementation.
   */
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
  /**
   * Expected audience — string or array. REQUIRED. Resource servers MUST
   * set this to their own URL to prevent confused-deputy: a token minted
   * for a different resource server (same notme issuer, same public key)
   * would otherwise pass this verifier. Mirrors `VerifyAccessTokenOptions.audience`
   * — was previously unchecked here (a real gap, found auditing an
   * external consumer's usage; see notme-9c2b41).
   */
  audience: string | string[];
  /**
   * Expected issuer — when set, rejects tokens whose `iss` claim doesn't
   * match. Defaults to no check so the SDK works with self-hosted notme
   * deployments under different domains. Mirrors `VerifyAccessTokenOptions.issuer`.
   */
  issuer?: string;
  /**
   * Atomic check-and-record hook for the DPoP proof's `jti` (single-use,
   * not the access token's jti). Return `true` if the jti was already
   * present; otherwise record it and return `false`. The verifier invokes
   * this only after all stateless validation succeeds. The SDK is
   * issuer-agnostic about the durable ledger implementation, so without
   * this hook only the 60s proof `iat` window bounds replay.
   */
  checkAndRecordJti?: (jti: string) => boolean | Promise<boolean>;
  /**
   * Clock-skew tolerance in SECONDS for the access token's time-based claims
   * (`exp` / `nbf` / `iat`), forwarded to `validateClaims`. Defaults to 60.
   *
   * This matches the existing cloister and canonical-hours deployments.
   * Set it explicitly to 0 to tighten access-token validation. The proof's
   * fixed ±60-second freshness window remains separate and is not widened.
   */
  clockTolerance?: number;
}

/** Claims returned on successful verification. */
export interface VerifiedTokenClaims {
  /** Subject (user/principal identifier). */
  sub: string;
  /** Space-separated scope string. */
  scope: string;
  /** Audience. */
  aud: string | string[];
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
 * Performs all five verification steps:
 *   1. Fetch the Ed25519 signing key from JWKS (with optional KV caching)
 *   2. Verify the access token's EdDSA signature, typ, and claims (exp/nbf/
 *      iat/iss/aud/sub, via the same `validateClaims` the non-DPoP
 *      `verifyAccessToken` path uses — notme-dffc5c)
 *   3. Verify the DPoP proof's signature and required jti/iat/htm/htu/ath
 *   4. Verify cnf.jkt binding — proof key thumbprint must match token claim
 *   5. Atomically check-and-record the proof jti when `checkAndRecordJti` is provided
 *
 * @returns Verified token claims on success.
 * @throws Error with a descriptive message on any validation failure.
 */
export async function verifyDPoPToken(
  opts: VerifyDPoPTokenOptions,
): Promise<VerifiedTokenClaims> {
  const {
    token,
    proof,
    method,
    url,
    jwksUrl,
    kv,
    publicKey,
    audience,
    issuer,
    checkAndRecordJti,
    clockTolerance,
  } = opts;

  requireAudienceConfig(audience);

  // ── 1. Verify access token ──────────────────────────────────────────────

  const tokenParts = token.split(".");
  if (tokenParts.length !== 3) {
    throw new DPoPVerificationError(
      "MALFORMED_TOKEN",
      "Malformed access token: expected 3 parts",
    );
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
    tSig as BufferSource,
    tSigInput,
  );
  if (!tokenValid) {
    throw new DPoPVerificationError(
      "TOKEN_SIGNATURE_INVALID",
      "Invalid access token signature",
    );
  }

  // typ pin — an EdDSA JWT notme signed with the same key for a different
  // purpose (e.g. an id_token, notme-dffc5c/012) must not be replayed here
  // as an access token.
  const tHeader = jsonParse(
    base64urlDecodeStr(tHeaderB64),
    "access token header",
  );
  if (tHeader.typ !== "at+jwt") {
    throw new DPoPVerificationError(
      "TOKEN_TYP_INVALID",
      `Access token typ must be "at+jwt", got "${tHeader.typ}"`,
    );
  }

  // Parse and validate token claims via the shared validator — covers exp,
  // nbf, iat, iss, aud, sub uniformly, the same claim-check logic
  // verifyAccessToken uses (rosary-81353c). exp is a hard requirement here
  // (validateClaims only checks it when present; a DPoP token without exp
  // would break the short-lived contract), pre-checked before delegating.
  const tPayload = jsonParse(
    base64urlDecodeStr(tPayloadB64),
    "access token payload",
  );
  const now = Math.floor(Date.now() / 1000);
  if (typeof tPayload.exp !== "number") {
    throw new DPoPVerificationError(
      "TOKEN_EXP_MISSING",
      "Access token missing exp claim",
    );
  }
  validateClaims(tPayload, {
    issuer,
    audience,
    requireSub: true,
    clockTolerance: clockTolerance ?? 60,
  });

  // ── 2. Verify DPoP proof ───────────────────────────────────────────────

  const proofParts = proof.split(".");
  if (proofParts.length !== 3) {
    throw new DPoPVerificationError(
      "MALFORMED_PROOF",
      "Malformed DPoP proof: expected 3 parts",
    );
  }
  const [pHeaderB64, pPayloadB64, pSigB64] = proofParts;

  const pHeader = jsonParse(
    base64urlDecodeStr(pHeaderB64),
    "DPoP proof header",
  );

  if (pHeader.typ !== "dpop+jwt") {
    throw new DPoPVerificationError(
      "PROOF_TYP_INVALID",
      `DPoP proof typ must be "dpop+jwt", got "${pHeader.typ}"`,
    );
  }
  if (!pHeader.jwk || typeof pHeader.jwk !== "object") {
    throw new DPoPVerificationError(
      "PROOF_JWK_MISSING",
      "DPoP proof header must contain a jwk",
    );
  }
  if (pHeader.alg !== "ES256" && pHeader.alg !== "EdDSA") {
    throw new DPoPVerificationError(
      "PROOF_ALG_UNSUPPORTED",
      `Unsupported DPoP proof algorithm: ${pHeader.alg}`,
    );
  }

  // Import proof key and verify signature (support ES256 and EdDSA)
  const proofJwk = pHeader.jwk;
  if (hasPrivateJwkMaterial(proofJwk)) {
    throw new DPoPVerificationError(
      "PROOF_JWK_PRIVATE",
      "DPoP proof JWK must not contain private key material",
    );
  }
  let proofKey: CryptoKey;
  let verifyAlg: { name: string; hash?: string };

  try {
    if (
      pHeader.alg === "ES256" &&
      proofJwk.kty === "EC" &&
      proofJwk.crv === "P-256"
    ) {
      requireJwkStringMembers(proofJwk, ["crv", "kty", "x", "y"]);
      proofKey = await crypto.subtle.importKey(
        "jwk",
        proofJwk,
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["verify"],
      );
      verifyAlg = { name: "ECDSA", hash: "SHA-256" };
    } else if (
      pHeader.alg === "EdDSA" &&
      proofJwk.kty === "OKP" &&
      proofJwk.crv === "Ed25519"
    ) {
      requireJwkStringMembers(proofJwk, ["crv", "kty", "x"]);
      proofKey = await crypto.subtle.importKey(
        "jwk",
        proofJwk,
        { name: "Ed25519" } as any,
        true,
        ["verify"],
      );
      verifyAlg = { name: "Ed25519" } as any;
    } else {
      throw new DPoPVerificationError(
        "PROOF_KEY_TYPE_UNSUPPORTED",
        `Unsupported DPoP proof key type: ${proofJwk.kty}`,
      );
    }
  } catch (error) {
    if (
      error instanceof DPoPVerificationError &&
      error.code === "PROOF_KEY_TYPE_UNSUPPORTED"
    ) {
      throw error;
    }
    throw new DPoPVerificationError(
      "PROOF_JWK_INVALID",
      "DPoP proof JWK could not be imported",
    );
  }

  const pSigInput = new TextEncoder().encode(`${pHeaderB64}.${pPayloadB64}`);
  const pSig = base64urlDecodeBytes(pSigB64);
  let proofValid = false;
  try {
    proofValid = await crypto.subtle.verify(
      verifyAlg,
      proofKey,
      pSig as BufferSource,
      pSigInput,
    );
  } catch {
    throw new DPoPVerificationError(
      "PROOF_SIGNATURE_INVALID",
      "Invalid DPoP proof signature",
    );
  }
  if (!proofValid) {
    throw new DPoPVerificationError(
      "PROOF_SIGNATURE_INVALID",
      "Invalid DPoP proof signature",
    );
  }

  // Validate proof claims (strict per RFC 9449 Section 4.3)
  const pPayload = jsonParse(
    base64urlDecodeStr(pPayloadB64),
    "DPoP proof payload",
  );

  // jti required — without it, replay detection is impossible
  if (!pPayload.jti || typeof pPayload.jti !== "string") {
    throw new DPoPVerificationError(
      "PROOF_JTI_MISSING",
      "DPoP proof missing jti claim",
    );
  }

  // iat required and must be within 60s — prevents replay of intercepted proofs
  if (typeof pPayload.iat !== "number") {
    throw new DPoPVerificationError(
      "PROOF_IAT_MISSING",
      "DPoP proof missing iat claim",
    );
  }
  const proofAge = now - pPayload.iat;
  if (proofAge > 60 || proofAge < -60) {
    throw new DPoPVerificationError(
      "PROOF_IAT_STALE",
      `DPoP proof iat is too old or in the future (age: ${proofAge}s, max: 60s)`,
    );
  }

  if (typeof pPayload.htm !== "string" || pPayload.htm !== method) {
    throw new DPoPVerificationError(
      "PROOF_HTM_MISMATCH",
      `DPoP proof htm mismatch: expected "${method}", got "${pPayload.htm}"`,
    );
  }
  const proofHtu = normalizeHtu(pPayload.htu);
  const requestHtu = normalizeHtu(url);
  if (proofHtu === null || requestHtu === null || proofHtu !== requestHtu) {
    throw new DPoPVerificationError(
      "PROOF_HTU_MISMATCH",
      `DPoP proof htu mismatch: expected "${requestHtu ?? url}", got "${proofHtu ?? pPayload.htu}"`,
    );
  }

  if (typeof pPayload.ath !== "string") {
    throw new DPoPVerificationError(
      "PROOF_ATH_MISSING",
      "DPoP proof missing ath claim",
    );
  }
  const expectedAth = base64urlEncode(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token)),
    ),
  );
  if (pPayload.ath !== expectedAth) {
    throw new DPoPVerificationError(
      "PROOF_ATH_MISMATCH",
      "DPoP proof ath does not match the presented access token",
    );
  }

  // ── 3. Verify cnf.jkt binding ──────────────────────────────────────────

  if (!tPayload.cnf || !tPayload.cnf.jkt) {
    throw new DPoPVerificationError(
      "CNF_JKT_MISSING",
      "Access token missing cnf.jkt claim",
    );
  }

  const thumbprint = await computeJwkThumbprint(proofJwk);
  if (thumbprint !== tPayload.cnf.jkt) {
    throw new DPoPVerificationError(
      "CNF_JKT_MISMATCH",
      "DPoP key binding mismatch: proof key thumbprint does not match cnf.jkt",
    );
  }

  // The callback is the resource server's atomic check-and-record boundary.
  // Invoke it only after every stateless token/proof check succeeds so an
  // invalid request cannot burn a legitimate proof's jti.
  if (checkAndRecordJti && (await checkAndRecordJti(pPayload.jti))) {
    throw new DPoPVerificationError(
      "PROOF_REPLAY",
      "DPoP proof replay: jti already seen",
    );
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
  const { token, jwksUrl, kv, publicKey, audience, issuer } = opts;
  requireAudienceConfig(audience);

  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new DPoPVerificationError(
      "MALFORMED_TOKEN",
      "Malformed access token: expected 3 parts",
    );
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
    sig as BufferSource,
    sigInput,
  );
  if (!valid) {
    throw new DPoPVerificationError(
      "TOKEN_SIGNATURE_INVALID",
      "Invalid access token signature",
    );
  }

  // Parse and validate claims via the shared validator — covers exp, nbf,
  // iat, iss, aud, sub uniformly so the resource-server path uses the same
  // claim-check logic as the issuer path. Earlier this function inlined a
  // partial check that omitted nbf, iss, and aud (rosary-81353c).
  const payload = jsonParse(
    base64urlDecodeStr(payloadB64),
    "access token payload",
  );
  // exp is a hard requirement here — `validateClaims` only checks it when
  // present, but accepting a token without exp would break the short-lived
  // contract (5-min TTL). Pre-check before delegating.
  if (typeof payload.exp !== "number") {
    throw new DPoPVerificationError(
      "TOKEN_EXP_MISSING",
      "Access token missing exp claim",
    );
  }
  validateClaims(payload, {
    issuer,
    audience,
    requireSub: true,
  });

  // RFC 9449 Section 3: a DPoP-bound token (has cnf.jkt) MUST NOT be
  // accepted as a plain Bearer token. Rejecting here prevents downgrade
  // attacks where an attacker strips the DPoP header from a stolen token.
  if (payload.cnf) {
    throw new DPoPVerificationError(
      "BEARER_TOKEN_DPOP_BOUND",
      "DPoP-bound token cannot be verified as Bearer — use verifyDPoPToken with a proof",
    );
  }

  return {
    sub: payload.sub as string,
    scope: (payload.scope as string | undefined) ?? "",
    aud: (payload.aud as string | undefined) ?? "",
    exp: payload.exp as number,
    jti: (payload.jti as string | undefined) ?? "",
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
      throw new DPoPVerificationError(
        "JWKS_FETCH_FAILED",
        `JWKS fetch failed: ${res.status}`,
      );
    }
    jwksJson = await res.text();

    // Cache in KV if available
    if (kv) {
      await kv.put(JWKS_CACHE_KEY, jwksJson, { expirationTtl: JWKS_TTL });
    }
  }

  const jwks = JSON.parse(jwksJson) as {
    keys: Array<{
      kty: string;
      crv: string;
      x: string;
      alg?: string;
      kid?: string;
    }>;
  };
  const jwk = jwks.keys.find((k) => k.kty === "OKP" && k.crv === "Ed25519");
  if (!jwk) {
    throw new DPoPVerificationError(
      "JWKS_NO_KEY_FOUND",
      "No Ed25519 key found in JWKS",
    );
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
      requireJwkStringMembers(jwk, ["crv", "kty", "x", "y"]);
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
      requireJwkStringMembers(jwk, ["e", "kty", "n"]);
      // Required members for RSA: e, kty, n (alphabetical order)
      const obj = {
        e: jwk.e,
        kty: jwk.kty,
        n: jwk.n,
      };
      return JSON.stringify(obj);
    }
    case "OKP": {
      requireJwkStringMembers(jwk, ["crv", "kty", "x"]);
      // Required members for OKP: crv, kty, x (alphabetical order)
      const obj = {
        crv: jwk.crv,
        kty: jwk.kty,
        x: jwk.x,
      };
      return JSON.stringify(obj);
    }
    default:
      throw new DPoPVerificationError(
        "JWK_KEY_TYPE_UNSUPPORTED",
        `Unsupported key type: ${jwk.kty}`,
      );
  }
}

function requireJwkStringMembers(
  jwk: JsonWebKey,
  members: Array<keyof JsonWebKey>,
): void {
  for (const member of members) {
    if (typeof jwk[member] !== "string" || jwk[member] === "") {
      throw new DPoPVerificationError(
        "JWK_INVALID",
        `JWK "${String(member)}" member must be a non-empty string`,
      );
    }
  }
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

function requireAudienceConfig(
  audience: unknown,
): asserts audience is string | string[] {
  const valid =
    (typeof audience === "string" && audience.length > 0) ||
    (Array.isArray(audience) &&
      audience.length > 0 &&
      audience.every((entry) => typeof entry === "string" && entry.length > 0));
  if (!valid) {
    throw new DPoPVerificationError(
      "CONFIG_AUDIENCE_REQUIRED",
      "Verifier audience must be a non-empty string or string array",
    );
  }
}

function hasPrivateJwkMaterial(jwk: Record<string, unknown>): boolean {
  return ["d", "p", "q", "dp", "dq", "qi", "oth"].some(
    (member) => jwk[member] !== undefined,
  );
}

// ── Exported primitives ─────────────────────────────────────────────────────
// Single implementation for all JWT code. Patterns from jose (MIT, Filip Skokan).

/**
 * Base64url encode bytes (no padding, URL-safe).
 * Chunked at 32KB to prevent stack overflow on large payloads.
 */
export function base64urlEncode(bytes: Uint8Array): string {
  const CHUNK = 0x8000; // 32KB
  const parts: string[] = [];
  for (let i = 0; i < bytes.length; i += CHUNK) {
    parts.push(String.fromCharCode(...bytes.subarray(i, i + CHUNK)));
  }
  return btoa(parts.join(""))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/**
 * Base64url decode to bytes. Handles both URL-safe and standard base64.
 * Throws on malformed input (try/catch around atob).
 */
export function base64urlDecode(s: string): Uint8Array {
  if (s.length === 0) return new Uint8Array(0);
  const base64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new DPoPVerificationError(
      "BASE64URL_DECODE_FAILED",
      "Failed to base64url decode: malformed input",
    );
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Internal aliases used by existing code — delegates to exported functions.
function base64urlDecodeBytes(s: string): Uint8Array {
  return base64urlDecode(s);
}
function base64urlDecodeStr(s: string): string {
  return new TextDecoder().decode(base64urlDecode(s));
}

/**
 * Parse JSON with labeled error. Rejects non-object results (arrays, primitives, null).
 * jose pattern: JWT Claims Set must be a top-level JSON object.
 */
export function jsonParseSafe(s: string, label: string): Record<string, any> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(s);
  } catch {
    throw new DPoPVerificationError(
      "JSON_PARSE_FAILED",
      `${label} is not valid JSON`,
    );
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new DPoPVerificationError(
      "JSON_NOT_OBJECT",
      `${label} must be a JSON object`,
    );
  }
  return parsed as Record<string, any>;
}

// Internal alias for existing code.
function jsonParse(s: string, label: string): Record<string, any> {
  return jsonParseSafe(s, label);
}

/**
 * Validate JWT claims per RFC 7519 + jose patterns.
 *
 * Checks: exp (required unless opts say otherwise), nbf, iat, iss, aud, sub.
 * Type-checks all numeric claims before comparison.
 * Clock tolerance applied to `now`, not claim values.
 */
export interface ValidateClaimsOptions {
  /** Expected issuer — rejects if payload.iss doesn't match. */
  issuer?: string;
  /** Expected audience — string or array. Rejects if no match. */
  audience?: string | string[];
  /** Clock tolerance in seconds (default 0). */
  clockTolerance?: number;
  /** Require sub claim to be present and a string. */
  requireSub?: boolean;
}

export function validateClaims(
  payload: Record<string, unknown>,
  opts: ValidateClaimsOptions,
): void {
  const tolerance = opts.clockTolerance ?? 0;
  const now = Math.floor(Date.now() / 1000);

  // ── exp: type-check, then compare with tolerance ──
  if (payload.exp !== undefined) {
    if (typeof payload.exp !== "number") {
      throw new DPoPVerificationError(
        "CLAIM_EXP_INVALID_TYPE",
        '"exp" claim must be a number',
      );
    }
    if (payload.exp <= now - tolerance) {
      throw new DPoPVerificationError(
        "CLAIM_EXP_EXPIRED",
        '"exp" claim timestamp check failed (token expired)',
      );
    }
  }

  // ── nbf: validate only if present ──
  if (payload.nbf !== undefined) {
    if (typeof payload.nbf !== "number") {
      throw new DPoPVerificationError(
        "CLAIM_NBF_INVALID_TYPE",
        '"nbf" claim must be a number',
      );
    }
    if (payload.nbf > now + tolerance) {
      throw new DPoPVerificationError(
        "CLAIM_NBF_NOT_YET_VALID",
        '"nbf" claim timestamp check failed (token not yet valid)',
      );
    }
  }

  // ── iat: validate only if present ──
  if (payload.iat !== undefined) {
    if (typeof payload.iat !== "number") {
      throw new DPoPVerificationError(
        "CLAIM_IAT_INVALID_TYPE",
        '"iat" claim must be a number',
      );
    }
    if (payload.iat > now + 60 + tolerance) {
      throw new DPoPVerificationError(
        "CLAIM_IAT_FUTURE",
        '"iat" claim is too far in the future',
      );
    }
  }

  // ── iss: required when issuer option is set ──
  if (opts.issuer !== undefined) {
    if (payload.iss === undefined) {
      throw new DPoPVerificationError(
        "CLAIM_ISS_MISSING",
        '"iss" claim missing (required by issuer option)',
      );
    }
    if (payload.iss !== opts.issuer) {
      throw new DPoPVerificationError(
        "CLAIM_ISS_MISMATCH",
        `"iss" claim mismatch: expected "${opts.issuer}", got "${payload.iss}"`,
      );
    }
  }

  // ── aud: required when audience option is set (handles string + array) ──
  if (opts.audience !== undefined) {
    if (payload.aud === undefined) {
      throw new DPoPVerificationError(
        "CLAIM_AUD_MISSING",
        '"aud" claim missing (required by audience option)',
      );
    }
    const expected = Array.isArray(opts.audience)
      ? opts.audience
      : [opts.audience];
    const actual = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!actual.every((a: unknown) => typeof a === "string")) {
      throw new DPoPVerificationError(
        "CLAIM_AUD_INVALID_TYPE",
        '"aud" claim must be a string or an array of strings',
      );
    }
    const match = actual.some(
      (a: unknown) => typeof a === "string" && expected.includes(a),
    );
    if (!match) {
      throw new DPoPVerificationError(
        "CLAIM_AUD_MISMATCH",
        `"aud" claim mismatch: expected ${expected.join(",")}, got ${actual.join(",")}`,
      );
    }
  }

  // ── sub: required when requireSub option is set ──
  if (opts.requireSub) {
    if (payload.sub === undefined) {
      throw new DPoPVerificationError(
        "CLAIM_SUB_MISSING",
        '"sub" claim missing (required)',
      );
    }
    if (typeof payload.sub !== "string") {
      throw new DPoPVerificationError(
        "CLAIM_SUB_INVALID_TYPE",
        '"sub" claim must be a string',
      );
    }
  }
}
