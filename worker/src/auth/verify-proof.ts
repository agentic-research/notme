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

// Trusted OIDC issuers — prevents SSRF via attacker-controlled iss claim.
//
// The audience pin on /connections /auth/oidc/login /join is "notme.bot",
// which works for:
//   - https://auth.notme.bot — self-issued, always carries aud=notme.bot
//   - https://token.actions.githubusercontent.com — GHA workflows can
//     request any audience via core.getIDToken(audience) so they can mint
//     tokens with aud=notme.bot
//
// Google ID tokens carry aud=<google-client-id>.apps.googleusercontent.com
// so they CANNOT match audience="notme.bot". Including Google here would
// be misleading: the issuer would pass the trust check but every legitimate
// token would fail the audience check. notme-ae65a0 / M1 from session
// review tracks the proper fix (per-issuer audience map keyed by env config
// for the Google client ID); until then, Google is intentionally absent so
// callers who try it get a clear "untrusted issuer" failure rather than a
// confusing "wrong audience" failure on every request.
const TRUSTED_ISSUERS = new Set([
  "https://token.actions.githubusercontent.com",
  "https://auth.notme.bot",
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
 * `expectedAudience` is REQUIRED. It prevents confused deputy attacks: a
 * token issued for evil-app.com (same Google issuer, same user sub) must
 * be rejected because its aud doesn't match notme's client ID. Earlier
 * the parameter was optional and `/connections` forgot to pass it (see
 * notme-567f07); making it required at the type level kills the bug
 * class — TS rejects callers that try to skip the check.
 */
export async function verifyOIDC(
  token: string,
  expectedAudience: string | string[],
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

  // Audience validation — always runs. Confused-deputy defense.
  const tokenAud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  const expectedArr = Array.isArray(expectedAudience) ? expectedAudience : [expectedAudience];
  const audienceOk = tokenAud.some((a: unknown) =>
    typeof a === "string" && expectedArr.includes(a),
  );
  if (!audienceOk) {
    throw new Error(
      `wrong audience: expected ${expectedArr.join(",")}, got ${tokenAud.join(",")}`,
    );
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
  caPublicKeyPem: string | undefined,
  expectedAudience: string | string[],
): Promise<VerifiedIdentity> {
  if (proof.type === "oidc") {
    return verifyOIDC(proof.token, expectedAudience);
  }
  if (proof.type === "x509") {
    if (!caPublicKeyPem) throw new Error("CA public key required for x509 verification");
    // expectedAudience is unused here — certs don't carry an aud claim. We
    // still take it as a required argument so callers can't accidentally
    // route a token-issuing flow through this function without one.
    return verifyX509(proof.cert, caPublicKeyPem);
  }
  // Exhaustiveness: if Proof gains a new variant, the line below fails to
  // typecheck (proof would no longer be `never` here). Runtime read covers
  // a malformed object cast through.
  const _exhaustive: never = proof;
  const seen = (_exhaustive as { type?: unknown }).type;
  throw new Error(`unknown proof type: ${String(seen)}`);
}
