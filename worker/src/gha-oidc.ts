// GitHub Actions OIDC JWT validation using WebCrypto (RS256) + Zod claim parsing.
//
// GHA tokens are RS256-signed JWTs issued by token.actions.githubusercontent.com.
// Spec: https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect

import { z } from "zod";
import { GHA_REJECTED_EVENTS } from "@notme/contract";

export const GHA_ISSUER = "https://token.actions.githubusercontent.com";

/**
 * Refuse a token minted for a GHA_REJECTED_EVENTS run (notme-fbb00e).
 *
 * `@notme/contract` says those tokens "MUST NOT receive a notme bridge
 * cert" and nothing read `event_name`. `pull_request_target` runs FORK code
 * in the UPSTREAM context, so its token names the upstream owner and clears
 * GHA_ALLOWED_OWNERS; `pull_request` is listed so its refusal is loud too.
 * Only GitHub-signed claims reach this, so the value is trustworthy. A token
 * with no `event_name` is not refused here: GitHub always sets it, and the
 * contract names events to reject, not ones to require.
 */
export function assertGhaEventAllowed(eventName: unknown): void {
  if (typeof eventName === "string" && (GHA_REJECTED_EVENTS as readonly string[]).includes(eventName)) {
    throw new Error(`event_name ${eventName} is not accepted (GHA_REJECTED_EVENTS)`);
  }
}
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

/**
 * GHA_ALLOWED_OWNERS (CSV, case-insensitive) as a set. Empty or absent means
 * NO owner is allowed. One parser for every GitHub-token path: /cert/gha,
 * the /token exchange, and the AUTH binding's mintBridgeCert gha-oidc proof,
 * which skipped the check until security review F7.
 */
export function getAllowedOwners(env: {
  GHA_ALLOWED_OWNERS?: string;
}): Set<string> {
  const raw: string = env.GHA_ALLOWED_OWNERS ?? "";
  return new Set(
    raw
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  );
}

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

// b64urlDecode imported from SDK — single implementation for all JWT code
import { base64urlDecode as b64urlDecode } from "@agentic-research/dpop";

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

  // Fork-PR events buy nothing, on every path that calls this (notme-fbb00e).
  assertGhaEventAllowed(rawPayload.event_name);

  // Zod parse — strong type guarantee on returned claims
  const parsed = GHAClaimsSchema.safeParse(rawPayload);
  if (!parsed.success)
    throw new Error(`invalid claims: ${parsed.error.message}`);
  return parsed.data;
}
