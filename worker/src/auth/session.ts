// Session tokens for auth.notme.bot — HMAC-SHA256 via oslo.
//
// A session token encodes the principal + scopes + auth method.
// No server-side session store. The token IS the session.
// Like Let's Encrypt ACME: proof → token → done.

import { encodeBase64url, decodeBase64url } from "@oslojs/encoding";

const SESSION_COOKIE_NAME = "notme_session";
const SESSION_TTL_SECONDS = 86400; // 24 hours

// ── AuthMethod: parsed once, here (notme-32003c) ─────────────────────────────
//
// "A cert's authMethod is DERIVED, never asserted" used to be carried by a
// hand-written guard in each mint route, which agreed only by inspection; a
// new mint path inherited none of them. AuthMethod is a branded string: the
// mints take it, and the only ways to make one are parseAuthMethod and the
// constants below. So an unchecked string reaching a mint is a compile
// error at every call site, present and future, and verifySessionCookie
// (the one place a cookie becomes a session) is where the check runs.
//
// The brand constrains PROVENANCE, not the value: any non-empty string
// parses. What becomes unrepresentable is "an authMethod nobody checked".
// Constraining the value too ("passkey" | "invite" | "bootstrap" |
// "gha-oidc" | `oidc:${string}`) is the bead's stated follow-on.

declare const authMethodBrand: unique symbol;
/** An authMethod that has been checked. Obtain one only via parseAuthMethod, AUTH_METHOD or oidcAuthMethod. */
export type AuthMethod = string & { readonly [authMethodBrand]: true };

/** A non-empty string, or null. The sole cast to AuthMethod outside the constants below. */
export function parseAuthMethod(v: unknown): AuthMethod | null {
  return typeof v === "string" && v.length > 0 ? (v as AuthMethod) : null;
}

/** The fixed methods this authority's own routes issue. */
export const AUTH_METHOD = {
  passkey: "passkey" as AuthMethod,
  invite: "invite" as AuthMethod,
  bootstrap: "bootstrap" as AuthMethod,
  ghaOidc: "gha-oidc" as AuthMethod,
} as const;

/** The issuer-qualified method of an OIDC login or proof. */
export function oidcAuthMethod(issuer: string): AuthMethod {
  return `oidc:${issuer}` as AuthMethod;
}

export interface SessionPayload {
  principalId: string;
  scopes: string[];
  authMethod: AuthMethod; // "passkey" | "invite" | "oidc:<issuer>" | "bootstrap"
  exp: number;
  // v1 compat (deprecated — will be removed)
  userId?: string;
  isAdmin?: boolean;
}

async function hmacSign(data: Uint8Array, secret: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
}

async function hmacVerify(
  data: Uint8Array, signature: Uint8Array, secret: string,
): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify("HMAC", key, signature, data);
}

export async function createSessionCookie(
  session: { principalId: string; scopes: string[]; authMethod: string },
  secret: string,
): Promise<string> {
  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;
  return createSessionCookieWithExp(session, secret, exp);
}

export async function createSessionCookieWithExp(
  session: { principalId: string; scopes: string[]; authMethod: string },
  secret: string,
  exp: number,
): Promise<string> {
  // The WIRE shape takes a plain string: the writer is not the boundary.
  // verifySessionCookie parses authMethod on the way back in, so a cookie
  // written with a bad one is refused there rather than trusted.
  const payload: Omit<SessionPayload, "authMethod"> & { authMethod: string } = {
    principalId: session.principalId,
    scopes: session.scopes,
    authMethod: session.authMethod,
    exp,
    userId: session.principalId,
    isAdmin: session.scopes.includes("authorityManage"),
  };

  const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
  const payloadB64 = encodeBase64url(payloadBytes);
  const sig = await hmacSign(payloadBytes, secret);
  const sigB64 = encodeBase64url(sig);

  return [
    `${SESSION_COOKIE_NAME}=${payloadB64}.${sigB64}`,
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    "Path=/",
    `Max-Age=${SESSION_TTL_SECONDS}`,
  ].join("; ");
}

export async function verifySessionCookie(
  cookieValue: string, secret: string,
): Promise<SessionPayload | null> {
  const parts = cookieValue.split(".");
  if (parts.length !== 2) return null;

  let payloadBytes: Uint8Array;
  let sigBytes: Uint8Array;
  try {
    payloadBytes = decodeBase64url(parts[0]);
    sigBytes = decodeBase64url(parts[1]);
  } catch {
    return null;
  }

  if (!(await hmacVerify(payloadBytes, sigBytes, secret))) return null;

  // Unchecked until parsed: the HMAC proves WE signed it, not that whoever
  // built it at the time filled every field.
  let payload: Omit<SessionPayload, "authMethod"> & { authMethod?: unknown };
  try {
    payload = JSON.parse(new TextDecoder().decode(payloadBytes));
  } catch {
    return null;
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) return null;

  // A missing or non-numeric exp compares false against the clock, so it must
  // be refused outright, or the session would never expire.
  if (typeof payload.exp !== "number" || !Number.isFinite(payload.exp)) return null;
  if (payload.exp < Math.floor(Date.now() / 1000)) return null;

  // Migrate v1 sessions
  if (!payload.principalId && payload.userId) {
    payload.principalId = payload.userId;
    payload.scopes = payload.isAdmin
      ? ["bridgeCert", "authorityManage", "certMint"]
      : ["bridgeCert"];
    payload.authMethod = AUTH_METHOD.passkey;
  }

  // A session that cannot state how it was authenticated is not a session
  // (notme-32003c). Refusing here, rather than in each mint route, is what
  // lets every route — including ones not yet written — rely on it.
  const authMethod = parseAuthMethod(payload.authMethod);
  if (authMethod === null) return null;

  return { ...payload, authMethod };
}

export function clearSessionCookie(): string {
  return `${SESSION_COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`;
}

/**
 * Resolve a session's scopes against the grant store, LIVE.
 *
 * The cookie is a cache of the grant, never the source (notme-77a024). A
 * grant revoked after the cookie was issued must take effect on the next
 * request, not at cookie expiry 24h later — so every authority check reads
 * the DO and INTERSECTS: a scope must be in the cookie (the session asked for
 * it) AND in the grant store (the principal still holds it). Intersection,
 * never either alone: cookie-only ignores revocation; store-only would widen
 * a session past what it was issued with.
 */
export async function liveScopes(
  session: Pick<SessionPayload, "principalId" | "scopes">,
  authority: { getPrincipalScopes(principalId: string): Promise<string[]> },
): Promise<string[]> {
  const held = new Set(await authority.getPrincipalScopes(session.principalId));
  return (session.scopes ?? []).filter((s) => held.has(s));
}
