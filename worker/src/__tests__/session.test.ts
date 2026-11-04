/**
 * session.test.ts — HMAC session cookie tests (principal model).
 * Maps to THREAT_MODEL.md: session.hmac.integrity, session.expiry
 */

import { describe, expect, it } from "vitest";

describe("session.hmac.integrity", () => {
  it("creates a cookie with HMAC signature", async () => {
    const { createSessionCookie } = await import("../auth/session");
    const secret = "test-secret-32-chars-minimum-ok!";
    const cookie = await createSessionCookie(
      {
        principalId: "p-1",
        scopes: ["bridgeCert"],
        authMethod: "passkey",
      },
      secret,
    );
    expect(cookie).toContain("notme_session=");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("SameSite=Strict");
  });

  it("verifies a valid cookie with principal model", async () => {
    const { createSessionCookie, verifySessionCookie } = await import(
      "../auth/session"
    );
    const secret = "test-secret-32-chars-minimum-ok!";
    const cookie = await createSessionCookie(
      {
        principalId: "p-1",
        scopes: ["bridgeCert", "authorityManage"],
        authMethod: "passkey",
      },
      secret,
    );
    const value = cookie.split("notme_session=")[1].split(";")[0];
    const session = await verifySessionCookie(value, secret);

    expect(session).not.toBeNull();
    expect(session!.principalId).toBe("p-1");
    expect(session!.scopes).toContain("bridgeCert");
    expect(session!.scopes).toContain("authorityManage");
    expect(session!.authMethod).toBe("passkey");
    // v1 compat
    expect(session!.userId).toBe("p-1");
    expect(session!.isAdmin).toBe(true);
  });

  it("rejects a tampered cookie", async () => {
    const { createSessionCookie, verifySessionCookie } = await import(
      "../auth/session"
    );
    const secret = "test-secret-32-chars-minimum-ok!";
    const cookie = await createSessionCookie(
      {
        principalId: "p-1",
        scopes: ["bridgeCert"],
        authMethod: "passkey",
      },
      secret,
    );
    const value = cookie.split("notme_session=")[1].split(";")[0];
    const tampered = value.slice(0, -4) + "XXXX";
    expect(await verifySessionCookie(tampered, secret)).toBeNull();
  });

  it("rejects cookie signed with wrong secret", async () => {
    const { createSessionCookie, verifySessionCookie } = await import(
      "../auth/session"
    );
    const cookie = await createSessionCookie(
      {
        principalId: "p-1",
        scopes: ["bridgeCert"],
        authMethod: "oidc:github",
      },
      "correct-secret-32-chars-minimum!",
    );
    const value = cookie.split("notme_session=")[1].split(";")[0];
    expect(
      await verifySessionCookie(value, "wrong-secret-32-characters-here!"),
    ).toBeNull();
  });
});

describe("session.expiry", () => {
  it("rejects an expired cookie", async () => {
    const { createSessionCookieWithExp, verifySessionCookie } = await import(
      "../auth/session"
    );
    const secret = "test-secret-32-chars-minimum-ok!";
    const expiredCookie = await createSessionCookieWithExp(
      {
        principalId: "p-1",
        scopes: ["bridgeCert"],
        authMethod: "passkey",
      },
      secret,
      Math.floor(Date.now() / 1000) - 3600,
    );
    const value = expiredCookie.split("notme_session=")[1].split(";")[0];
    expect(await verifySessionCookie(value, secret)).toBeNull();
  });
});

describe("session.scopes", () => {
  it("isAdmin derived from scopes (v1 compat)", async () => {
    const { createSessionCookie, verifySessionCookie } = await import(
      "../auth/session"
    );
    const secret = "test-secret-32-chars-minimum-ok!";

    // With authorityManage → isAdmin true
    const adminCookie = await createSessionCookie(
      {
        principalId: "p-1",
        scopes: ["bridgeCert", "authorityManage"],
        authMethod: "passkey",
      },
      secret,
    );
    const adminValue = adminCookie.split("notme_session=")[1].split(";")[0];
    const adminSession = await verifySessionCookie(adminValue, secret);
    expect(adminSession!.isAdmin).toBe(true);

    // Without authorityManage → isAdmin false
    const userCookie = await createSessionCookie(
      {
        principalId: "p-2",
        scopes: ["bridgeCert"],
        authMethod: "oidc:github",
      },
      secret,
    );
    const userValue = userCookie.split("notme_session=")[1].split(";")[0];
    const userSession = await verifySessionCookie(userValue, secret);
    expect(userSession!.isAdmin).toBe(false);
  });
});

// ── authMethod is parsed at the boundary (notme-32003c) ──────────────────────
//
// verifySessionCookie used to JSON.parse the payload with no shape check, so
// each mint route carried its own guard against a missing authMethod. The
// check now lives here, once: a validly signed payload whose authMethod does
// not parse is not a session.

/** Sign arbitrary payload bytes exactly as createSessionCookie does. */
async function signedRaw(raw: string, secret: string): Promise<string> {
  const { encodeBase64url } = await import("@oslojs/encoding");
  const bytes = new TextEncoder().encode(raw);
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, bytes));
  return `${encodeBase64url(bytes)}.${encodeBase64url(sig)}`;
}
const signedValue = (payload: Record<string, unknown>, secret: string) =>
  signedRaw(JSON.stringify(payload), secret);

describe("session.auth-method.parsed", () => {
  const secret = "test-secret-32-chars-minimum-ok!";
  const exp = Math.floor(Date.now() / 1000) + 3600;

  it("rejects a signed payload with no authMethod", async () => {
    const { verifySessionCookie } = await import("../auth/session");
    const value = await signedValue({ principalId: "p-1", scopes: ["bridgeCert"], exp }, secret);
    expect(await verifySessionCookie(value, secret)).toBeNull();
  });

  it("rejects an empty or non-string authMethod", async () => {
    const { verifySessionCookie } = await import("../auth/session");
    for (const authMethod of ["", 42, null, ["passkey"], { m: "passkey" }]) {
      const value = await signedValue({ principalId: "p-1", scopes: [], authMethod, exp }, secret);
      expect(await verifySessionCookie(value, secret), JSON.stringify(authMethod)).toBeNull();
    }
  });

  it("rejects a signed payload that is not an object", async () => {
    const { verifySessionCookie } = await import("../auth/session");
    for (const raw of ["null", "42", '"passkey"']) {
      expect(await verifySessionCookie(await signedRaw(raw, secret), secret), raw).toBeNull();
    }
  });

  it("still migrates a v1 session, whose method was always passkey", async () => {
    const { verifySessionCookie } = await import("../auth/session");
    const value = await signedValue({ userId: "u-1", isAdmin: false, exp }, secret);
    const session = await verifySessionCookie(value, secret);
    expect(session).not.toBeNull();
    expect(session!.principalId).toBe("u-1");
    expect(session!.authMethod).toBe("passkey");
  });

  it("parseAuthMethod accepts any non-empty string and nothing else", async () => {
    const { parseAuthMethod } = await import("../auth/session");
    expect(parseAuthMethod("passkey")).toBe("passkey");
    expect(parseAuthMethod("oidc:https://accounts.example")).toBe("oidc:https://accounts.example");
    for (const bad of ["", undefined, null, 1, {}, []]) {
      expect(parseAuthMethod(bad), JSON.stringify(bad)).toBeNull();
    }
  });
});
