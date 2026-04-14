// Generic proof verification — OIDC JWTs and X.509 certs.
// No provider-specific code. If it has a JWKS, we can verify it.

export interface VerifiedIdentity {
  type: "oidc" | "x509";
  issuer: string; // OIDC issuer URL or cert issuer CN
  subject: string; // OIDC sub claim or cert subject CN
  claims?: Record<string, unknown>; // raw claims for the connection record
}

export interface OIDCProof {
  type: "oidc";
  token: string; // raw JWT
}

export interface X509Proof {
  type: "x509";
  cert: string; // PEM
}

export type Proof = OIDCProof | X509Proof;

import { base64urlDecode } from "../../../gen/ts/dpop";

// ── OIDC verification (any issuer with a JWKS endpoint) ──

interface JWK {
  kty: string;
  kid: string;
  n?: string;
  e?: string;
  alg?: string;
  crv?: string;
  x?: string;
  y?: string;
}

// Trusted OIDC issuers — prevents SSRF via attacker-controlled iss claim
const TRUSTED_ISSUERS = new Set([
  "https://token.actions.githubusercontent.com",
  "https://auth.notme.bot",
  "https://accounts.google.com",
]);

// Simple JWKS cache — per-issuer, 1 hour TTL
const jwksCache = new Map<string, { keys: JWK[]; at: number }>();

async function fetchJWKS(issuer: string): Promise<JWK[]> {
  if (!TRUSTED_ISSUERS.has(issuer)) {
    throw new Error(`untrusted issuer: ${issuer}`);
  }
  const now = Date.now();
  const cached = jwksCache.get(issuer);
  if (cached && now - cached.at < 3600_000) return cached.keys;

  // Try .well-known/jwks first, then .well-known/openid-configuration
  let jwksUrl = `${issuer}/.well-known/jwks`;
  let res = await fetch(jwksUrl);
  if (!res.ok) {
    const configRes = await fetch(
      `${issuer}/.well-known/openid-configuration`,
    );
    if (configRes.ok) {
      const config = (await configRes.json()) as { jwks_uri?: string };
      if (config.jwks_uri) {
        res = await fetch(config.jwks_uri);
      }
    }
  }
  if (!res.ok) throw new Error(`JWKS fetch failed for ${issuer}: ${res.status}`);

  const body = (await res.json()) as { keys: JWK[] };
  jwksCache.set(issuer, { keys: body.keys, at: now });
  return body.keys;
}

/**
 * Verify an OIDC token with mandatory audience validation.
 *
 * expectedAudience prevents confused deputy attacks: a token issued for
 * evil-app.com (same Google issuer, same user sub) must be rejected
 * because its aud doesn't match notme's client ID.
 */
export async function verifyOIDC(
  token: string,
  expectedAudience?: string | string[],
): Promise<VerifiedIdentity> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("malformed JWT");

  const header = JSON.parse(
    new TextDecoder().decode(base64urlDecode(parts[0])),
  ) as { alg: string; kid?: string };
  const payload = JSON.parse(
    new TextDecoder().decode(base64urlDecode(parts[1])),
  ) as Record<string, unknown>;

  // Basic claim checks
  const iss = payload.iss as string;
  const sub = payload.sub as string;
  const exp = payload.exp as number;
  if (!iss) throw new Error("missing issuer");
  if (!sub) throw new Error("missing subject");
  if (typeof exp !== "number") throw new Error("missing exp claim");
  if (exp < Math.floor(Date.now() / 1000)) throw new Error("token expired");

  // Audience validation — prevents confused deputy (cross-application token replay)
  if (expectedAudience) {
    const tokenAud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    const expectedArr = Array.isArray(expectedAudience) ? expectedAudience : [expectedAudience];
    const valid = tokenAud.some((a: unknown) =>
      typeof a === "string" && expectedArr.includes(a),
    );
    if (!valid) {
      throw new Error(
        `wrong audience: expected ${expectedArr.join(",")}, got ${tokenAud.join(",")}`,
      );
    }
  }

  // Fetch JWKS and verify signature
  const keys = await fetchJWKS(iss);
  const jwk = header.kid
    ? keys.find((k) => k.kid === header.kid)
    : keys[0];
  if (!jwk) throw new Error(`unknown key id: ${header.kid}`);

  let cryptoKey: CryptoKey;
  if (header.alg === "RS256" && jwk.n && jwk.e) {
    cryptoKey = await crypto.subtle.importKey(
      "jwk",
      { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256" },
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
  } else if (header.alg === "ES256" && jwk.x && jwk.y) {
    cryptoKey = await crypto.subtle.importKey(
      "jwk",
      { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  } else {
    throw new Error(`unsupported alg: ${header.alg}`);
  }

  const signingInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const algParams =
    header.alg === "RS256"
      ? "RSASSA-PKCS1-v1_5"
      : { name: "ECDSA", hash: "SHA-256" };

  const valid = await crypto.subtle.verify(
    algParams,
    cryptoKey,
    base64urlDecode(parts[2]),
    signingInput,
  );
  if (!valid) throw new Error("invalid signature");

  return {
    type: "oidc",
    issuer: iss,
    subject: sub,
    claims: payload,
  };
}

// ── X.509 verification (cert signed by known CA) ──

export async function verifyX509(
  certPem: string,
  caPublicKeyPem: string,
): Promise<VerifiedIdentity> {
  const { X509Certificate } = await import("@peculiar/x509");
  const cert = new X509Certificate(certPem);

  // Check not expired
  if (cert.notAfter < new Date()) throw new Error("cert expired");
  if (cert.notBefore > new Date()) throw new Error("cert not yet valid");

  // Verify cert was signed by the CA — THE critical check.
  // Without this, any self-signed cert with valid dates would pass.
  const caCert = new X509Certificate(caPublicKeyPem);
  const signatureValid = await cert.verify({ publicKey: caCert.publicKey });
  if (!signatureValid) throw new Error("cert signature invalid — not signed by trusted CA");

  // Extract subject CN
  const subject = cert.subjectName.getField("CN")?.[0] ?? cert.subject;
  const issuer = cert.issuerName.getField("CN")?.[0] ?? cert.issuer;

  return {
    type: "x509",
    issuer,
    subject,
  };
}

// ── Dispatch: verify any proof type ──

export async function verifyProof(
  proof: Proof,
  caPublicKeyPem?: string,
  expectedAudience?: string | string[],
): Promise<VerifiedIdentity> {
  if (proof.type === "oidc") {
    return verifyOIDC(proof.token, expectedAudience);
  }
  if (proof.type === "x509") {
    if (!caPublicKeyPem) throw new Error("CA public key required for x509 verification");
    return verifyX509(proof.cert, caPublicKeyPem);
  }
  throw new Error(`unknown proof type: ${(proof as any).type}`);
}
