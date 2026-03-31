// GitHub Actions OIDC JWT validation using WebCrypto (RS256) + Zod claim parsing.
//
// GHA tokens are RS256-signed JWTs issued by token.actions.githubusercontent.com.
// Spec: https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect

import { z } from "zod";

const GHA_ISSUER = "https://token.actions.githubusercontent.com";
const JWKS_URL = `${GHA_ISSUER}/.well-known/jwks`;
const JWKS_TTL_MS = 60 * 60 * 1000; // 1 hour

export const GHAClaimsSchema = z.object({
  // Standard JWT
  iss: z.string(),
  aud: z.union([z.string(), z.array(z.string())]),
  sub: z.string(), // "repo:{owner}/{repo}:ref:refs/heads/{branch}"
  exp: z.number(),
  iat: z.number(),
  jti: z.string().optional(),
  // GHA-specific
  repository: z.string(), // "owner/repo"
  repository_owner: z.string(),
  repository_owner_id: z.string().optional(),
  ref: z.string(), // "refs/heads/main"
  sha: z.string(),
  actor: z.string(),
  actor_id: z.string().optional(),
  workflow: z.string(),
  workflow_ref: z.string().optional(),
  workflow_sha: z.string().optional(),
  job_workflow_ref: z.string(),
  run_id: z.string(),
  run_number: z.string().optional(),
  run_attempt: z.string().optional(),
  event_name: z.string(),
  environment: z.string().optional(),
  runner_environment: z.string().optional(),
});

export type GHAClaims = z.infer<typeof GHAClaimsSchema>;

interface JWK {
  kty: string;
  kid: string;
  n: string;
  e: string;
  alg: string;
  use: string;
}

// Module-scope JWKS cache — lives for the lifetime of the Workers isolate.
// GitHub rotates keys infrequently; a stale key causes a validation failure
// on the next request, which will retry with a fresh fetch.
let jwksCache: { keys: JWK[]; cachedAt: number } | null = null;

async function fetchJWKS(): Promise<JWK[]> {
  const now = Date.now();
  if (jwksCache && now - jwksCache.cachedAt < JWKS_TTL_MS)
    return jwksCache.keys;
  const res = await fetch(JWKS_URL, {
    cf: { cacheTtl: 3600, cacheEverything: true },
  } as RequestInit);
  if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
  const body = (await res.json()) as { keys: JWK[] };
  jwksCache = { keys: body.keys, cachedAt: now };
  return body.keys;
}

function b64urlDecode(s: string): Uint8Array<ArrayBuffer> {
  const b64 = s
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(s.length + ((4 - (s.length % 4)) % 4), "=");
  const raw = atob(b64);
  const buf = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
  return buf;
}

// Validate a GHA OIDC JWT and return typed, Zod-parsed claims.
// Throws on any validation failure — callers treat all errors as 401.
export async function validateGHAToken(
  token: string,
  expectedAudience: string,
): Promise<GHAClaims> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("malformed JWT");
  const [headerB64, payloadB64, sigB64] = parts as [string, string, string];

  const header = JSON.parse(
    new TextDecoder().decode(b64urlDecode(headerB64)),
  ) as { alg: string; kid: string };
  if (header.alg !== "RS256") throw new Error(`unsupported alg: ${header.alg}`);

  const rawPayload = JSON.parse(
    new TextDecoder().decode(b64urlDecode(payloadB64)),
  );

  // Fast-fail on time and audience before hitting the network for JWKS
  const now = Math.floor(Date.now() / 1000);
  if (rawPayload.iss !== GHA_ISSUER)
    throw new Error(`wrong issuer: ${rawPayload.iss}`);
  if (rawPayload.exp < now) throw new Error("token expired");
  if (rawPayload.iat > now + 60) throw new Error("token issued in the future");
  const aud = Array.isArray(rawPayload.aud) ? rawPayload.aud : [rawPayload.aud];
  if (!aud.includes(expectedAudience))
    throw new Error(`wrong audience: ${aud.join(",")}`);

  // RS256 signature verification
  const keys = await fetchJWKS();
  const jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error(`unknown key id: ${header.kid}`);

  const cryptoKey = await crypto.subtle.importKey(
    "jwk",
    { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", use: "sig" },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );

  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    cryptoKey,
    b64urlDecode(sigB64),
    signingInput,
  );
  if (!valid) throw new Error("invalid signature");

  // Zod parse — strong type guarantee on returned claims
  const parsed = GHAClaimsSchema.safeParse(rawPayload);
  if (!parsed.success)
    throw new Error(`invalid claims: ${parsed.error.message}`);
  return parsed.data;
}
