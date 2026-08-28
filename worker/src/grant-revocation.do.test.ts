/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * grant-revocation.do.test.ts — the grant is the revocation unit
 * (notme-77a024, Goal Zero criterion C, ADR-019 D3).
 *
 * Before this: authority lived in two places that never met. passkey login
 * read `passkey_users.is_admin` — a boolean with no revoke path — while
 * `capability_grants` had `revoked_at` that passkey users never consulted.
 * Revoking a grant did nothing to the primary user class, and a session
 * baked scopes into a 24h cookie nothing re-read. The available
 * granularities were "one credential, when it expires" and "every credential
 * ever, via rotation". This file pins the unit in between.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../worker";
import { createSessionCookie } from "./auth/session";
import type { SigningAuthority } from "./signing-authority";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };

function authority(name = "default") {
  return env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(name));
}

describe("the grant object (DO layer)", () => {
  it("revoking a grant removes the scope from the principal's live set", async () => {
    const stub = authority("grant-revoke-do");
    const pid = crypto.randomUUID();
    await stub.createPrincipalWithCapabilities(pid, ["bridgeCert", "authorityManage"]);
    expect(await stub.getPrincipalScopes(pid)).toEqual(
      expect.arrayContaining(["bridgeCert", "authorityManage"]),
    );

    const result = await stub.revokeCapability(pid, "authorityManage", "admin-1");
    expect(result.revoked).toBe(true);

    expect(await stub.getPrincipalScopes(pid)).toEqual(["bridgeCert"]);
  });

  it("revocation is idempotent and reports when nothing was live", async () => {
    const stub = authority("grant-revoke-idem");
    const pid = crypto.randomUUID();
    await stub.createPrincipalWithCapabilities(pid, ["bridgeCert"]);
    expect((await stub.revokeCapability(pid, "bridgeCert", "a")).revoked).toBe(true);
    expect((await stub.revokeCapability(pid, "bridgeCert", "a")).revoked).toBe(false);
    expect((await stub.revokeCapability(pid, "certMint", "a")).revoked).toBe(false);
  });

  it("lists grants as objects — id, scope, who, when, and revocation state", async () => {
    const stub = authority("grant-list");
    const pid = crypto.randomUUID();
    await stub.createPrincipalWithCapabilities(pid, ["bridgeCert", "certMint"], "granter-1");
    await stub.revokeCapability(pid, "certMint", "revoker-1");

    const grants = await stub.listGrants(pid);
    const byScope = Object.fromEntries(grants.map((g) => [g.scope, g]));
    expect(byScope.bridgeCert.grantedBy).toBe("granter-1");
    expect(byScope.bridgeCert.revokedAt).toBeNull();
    expect(byScope.certMint.revokedAt).not.toBeNull();
    expect(byScope.certMint.revokedBy).toBe("revoker-1");
    expect(typeof byScope.bridgeCert.id).toBe("string");
  });
});

describe("sessions re-read the grant — revocation takes effect on the NEXT request", () => {
  async function sessionFor(pid: string, scopes: string[]) {
    const secret = await authority().getSessionSecret();
    return createSessionCookie({ principalId: pid, scopes, authMethod: "passkey" }, secret);
  }
  const get = (path: string, cookie: string) =>
    worker.fetch(
      new Request(`${ORIGIN}${path}`, { headers: { cookie } }),
      { ...env, ...LOCAL_ENV },
    );

  it("an authorityManage route refuses a session whose grant was revoked, before the cookie expires", async () => {
    const pid = crypto.randomUUID();
    await authority().createPrincipalWithCapabilities(pid, ["bridgeCert", "authorityManage"]);
    const cookie = await sessionFor(pid, ["bridgeCert", "authorityManage"]);

    // Live grant: admitted.
    expect((await get("/admin/alarm-health", cookie)).status).toBe(200);

    await authority().revokeCapability(pid, "authorityManage", "test");

    // Same cookie, same expiry — the grant is gone, so the door is shut.
    expect((await get("/admin/alarm-health", cookie)).status).toBe(403);
  });

  it("a cookie cannot carry a scope the grant store does not hold", async () => {
    // The cookie is a CACHE of the grant, never the source. A forged or stale
    // claim of authorityManage with no backing grant is refused.
    const pid = crypto.randomUUID();
    await authority().createPrincipalWithCapabilities(pid, ["bridgeCert"]);
    const cookie = await sessionFor(pid, ["bridgeCert", "authorityManage"]);
    expect((await get("/admin/alarm-health", cookie)).status).toBe(403);
  });
});

describe("passkey users are principals — one source of authority", () => {
  it("the first registered passkey user holds admin GRANTS, not just an is_admin bit", async () => {
    const stub = authority("passkey-principal");
    const pid = crypto.randomUUID();
    // Drive the same path /auth/passkey/register/verify takes after a
    // verified ceremony: the DO records the principal and its grants.
    await runInDurableObject(stub, async (auth) => {
      await (auth as SigningAuthority).ensurePasskeyPrincipal(pid, true);
    });
    expect(await stub.getPrincipalScopes(pid)).toEqual(
      expect.arrayContaining(["bridgeCert", "authorityManage", "certMint"]),
    );
    // Revocable like any other grant — the is_admin bit no longer decides.
    await stub.revokeCapability(pid, "authorityManage", "test");
    expect(await stub.getPrincipalScopes(pid)).not.toContain("authorityManage");
  });
});

describe("POST /principals/:id/revoke — the operator's lever", () => {
  const post = (path: string, body: unknown, cookie?: string) =>
    worker.fetch(
      new Request(`${ORIGIN}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", ...(cookie ? { cookie } : {}) },
        body: JSON.stringify(body),
      }),
      { ...env, ...LOCAL_ENV },
    );
  async function adminCookie(pid: string) {
    const secret = await authority().getSessionSecret();
    return createSessionCookie(
      { principalId: pid, scopes: ["bridgeCert", "authorityManage"], authMethod: "passkey" },
      secret,
    );
  }

  it("requires authorityManage — held LIVE", async () => {
    const admin = crypto.randomUUID();
    await authority().createPrincipalWithCapabilities(admin, ["bridgeCert"]); // no authorityManage
    const target = crypto.randomUUID();
    const res = await post(`/principals/${target}/revoke`, { scope: "bridgeCert" }, await adminCookie(admin));
    expect(res.status).toBe(403);
  });

  it("revokes, records who did it, and reports the outcome honestly", async () => {
    const admin = crypto.randomUUID();
    await authority().createPrincipalWithCapabilities(admin, ["bridgeCert", "authorityManage"]);
    const target = crypto.randomUUID();
    await authority().createPrincipalWithCapabilities(target, ["bridgeCert", "certMint"]);

    const res = await post(`/principals/${target}/revoke`, { scope: "certMint" }, await adminCookie(admin));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ revoked: true, principal_id: target, scope: "certMint" });
    expect(await authority().getPrincipalScopes(target)).toEqual(["bridgeCert"]);

    const grants = await authority().listGrants(target);
    expect(grants.find((g) => g.scope === "certMint")?.revokedBy).toBe(admin);

    // Again: nothing live to revoke, and the response says so.
    const again = await post(`/principals/${target}/revoke`, { scope: "certMint" }, await adminCookie(admin));
    expect(await again.json()).toMatchObject({ revoked: false });
  });

  it("refuses self-revocation of authorityManage — the last admin is not a footgun", async () => {
    const admin = crypto.randomUUID();
    await authority().createPrincipalWithCapabilities(admin, ["bridgeCert", "authorityManage"]);
    const res = await post(`/principals/${admin}/revoke`, { scope: "authorityManage" }, await adminCookie(admin));
    expect(res.status).toBe(409);
  });
});
