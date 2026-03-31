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
