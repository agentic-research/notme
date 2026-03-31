// Session tokens for auth.notme.bot — HMAC-SHA256 via oslo.
//
// A session token encodes the principal + scopes + auth method.
// No server-side session store. The token IS the session.
// Like Let's Encrypt ACME: proof → token → done.

import { encodeBase64url, decodeBase64url } from "@oslojs/encoding";

const SESSION_COOKIE_NAME = "notme_session";
const SESSION_TTL_SECONDS = 86400; // 24 hours

export interface SessionPayload {
  principalId: string;
  scopes: string[];
  authMethod: string; // "passkey" | "oidc:<issuer>" | "bootstrap"
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
  const payload: SessionPayload = {
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

  let payload: SessionPayload;
  try {
    payload = JSON.parse(new TextDecoder().decode(payloadBytes));
  } catch {
    return null;
  }

  if (payload.exp < Math.floor(Date.now() / 1000)) return null;

  // Migrate v1 sessions
  if (!payload.principalId && payload.userId) {
    payload.principalId = payload.userId;
    payload.scopes = payload.isAdmin
      ? ["bridgeCert", "authorityManage", "certMint"]
      : ["bridgeCert"];
    payload.authMethod = "passkey";
  }

  return payload;
}

export function clearSessionCookie(): string {
  return `${SESSION_COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`;
}
