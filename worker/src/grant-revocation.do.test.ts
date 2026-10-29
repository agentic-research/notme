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

describe("a revoked admin cannot pass authority on from a stale cookie", () => {
  // The gate that matters most. POST /invites feeds the session's scopes into
  // canGrant(); if that read the cookie, an admin whose authorityManage was
  // revoked could still mint invites carrying it — revocation would be
  // defeated by the very mechanism that spreads authority. Pinned at the
  // route because grant-revocation's gate test above covers only
  // /admin/alarm-health.
  const post = (path: string, body: unknown, cookie: string) =>
    worker.fetch(
      new Request(`${ORIGIN}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify(body),
      }),
      { ...env, ...LOCAL_ENV },
    );

  it("POST /invites refuses once the granter's authorityManage is revoked — same cookie", async () => {
    const admin = crypto.randomUUID();
    await authority().createPrincipalWithCapabilities(admin, ["bridgeCert", "authorityManage"]);
    const secret = await authority().getSessionSecret();
    const cookie = await createSessionCookie(
      { principalId: admin, scopes: ["bridgeCert", "authorityManage"], authMethod: "passkey" },
      secret,
    );

    const before = await post("/invites", { scopes: ["bridgeCert", "authorityManage"] }, cookie);
    expect(before.status).toBe(200);

    // Revoked by a DIFFERENT admin (self-revocation of authorityManage is refused).
    await authority().revokeCapability(admin, "authorityManage", "other-admin");

    const after = await post("/invites", { scopes: ["bridgeCert", "authorityManage"] }, cookie);
    expect(after.status).toBe(403);
  });

  it("POST /invites cannot grant a scope the granter no longer HOLDS, even with authorityManage intact", async () => {
    // canGrant needs authorityManage AND the specific scope. Revoke certMint
    // on the admin: they may still administer, but may no longer hand out
    // certMint — and the check must see the LIVE set, not the cookie's.
    const admin = crypto.randomUUID();
    await authority().createPrincipalWithCapabilities(admin, ["bridgeCert", "authorityManage", "certMint"]);
    const secret = await authority().getSessionSecret();
    const cookie = await createSessionCookie(
      { principalId: admin, scopes: ["bridgeCert", "authorityManage", "certMint"], authMethod: "passkey" },
      secret,
    );
    await authority().revokeCapability(admin, "certMint", "other-admin");

    const res = await post("/invites", { scopes: ["bridgeCert", "certMint"] }, cookie);
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toMatch(/certMint/);
  });
});

// ── The grant needs an IDENTITY, and history needs to survive a re-grant ────
//
// `capability_grants` declared `UNIQUE(principal_id, scope)` across ALL rows
// and `grantCapability` wrote `INSERT OR REPLACE`. Together those make a
// re-grant destructive in two ways:
//
//   1. IT ERASES THE REVOCATION. The replaced row carried `revoked_at` and
//      `revoked_by`; the new one does not, so a scope deliberately taken
//      away returns with no record it was ever removed. `listGrants`
//      documents itself as "every grant ever made to a principal, revoked
//      ones included — the audit view", and that was false in exactly the
//      case an audit exists for.
//   2. IT CHANGES THE GRANT ID. `id` is freshly generated per call, so
//      nothing can REFERENCE a grant and still mean the same grant later —
//      which is what blocks ADR-019 D3, a credential naming the grant that
//      authorized it.
//
// LATENT, NOT LIVE, and the distinction is the point rather than an excuse:
// no route reaches it. `grantCapability` has no RPC method and its only
// callers are `createPrincipalWithCapabilities` (which fails on an existing
// principal — the principals PRIMARY KEY, met while writing these tests) and
// `ensurePasskeyPrincipal` (which returns existing grants rather than
// re-granting). So this is fixed at the unit, where the next thing to be
// built stands on it, not at a door an attacker can knock on today.
//
// Driven through `runInDurableObject` against the real DO SQLite rather than
// by adding an RPC method: the unit under test is the exported function, and
// widening a full-CA RPC surface to make a test convenient is the wrong
// trade (rpc-surface.do.test.ts exists to ask that question).
//
// Same shape as the retired_keys defect fixed under notme-77a024: a
// uniqueness constraint quietly collapsing history something else promises
// to retain.
describe("grant identity and history survive a re-grant (ADR-019 D3)", () => {
  type GrantsApi = typeof import("./auth/principals");

  /** Run the real principals module against this DO's real SQLite. */
  async function withGrants<T>(
    name: string,
    fn: (api: GrantsApi, sql: unknown) => T,
  ): Promise<T> {
    const stub = authority(name);
    return runInDurableObject(stub, async (auth) => {
      const api = (await import("./auth/principals")) as GrantsApi;
      // `ctx` is protected on DurableObject, so the cast is how every DO
      // test in this repo reaches real storage (bootstrap-code.do.test.ts
      // does the same). The point is to drive the production module against
      // production SQLite, not to reimplement it against a stub.
      return fn(api, (auth as any).ctx.storage.sql);
    });
  }

  it("keeps the revoked grant as a row of its own when the scope is granted again", async () => {
    const pid = crypto.randomUUID();
    const grants = await withGrants("grant-regrant-history", (api, sql) => {
      api.createPrincipal(sql, pid, "re-grant subject");
      api.grantCapability(sql, pid, "bridgeCert", "granter-1");
      expect(api.revokeCapability(sql, pid, "bridgeCert", "revoker-1").revoked).toBe(true);

      // An operator re-grants the scope they revoked — a legitimate action.
      api.grantCapability(sql, pid, "bridgeCert", "granter-2");
      expect(api.getCapabilities(sql, pid)).toEqual(["bridgeCert"]);
      return api.listGrants(sql, pid);
    });

    const bridge = grants.filter((g) => g.scope === "bridgeCert");
    // TWO rows: the revocation happened and is still on the record.
    expect(bridge).toHaveLength(2);
    const revoked = bridge.filter((g) => g.revokedAt !== null);
    const live = bridge.filter((g) => g.revokedAt === null);
    expect(revoked).toHaveLength(1);
    expect(live).toHaveLength(1);
    expect(revoked[0]!.revokedBy).toBe("revoker-1");
    expect(revoked[0]!.grantedBy).toBe("granter-1");
    expect(live[0]!.grantedBy).toBe("granter-2");
    // Distinct grants, distinct identities — the live one is not the revoked
    // one wearing a new timestamp.
    expect(live[0]!.id).not.toBe(revoked[0]!.id);
  });

  it("gives a live grant a stable id, so a credential could name it", async () => {
    const pid = crypto.randomUUID();
    const { first, after } = await withGrants("grant-stable-id", (api, sql) => {
      api.createPrincipal(sql, pid, "stable id subject");
      api.grantCapability(sql, pid, "bridgeCert", "granter-1");
      const first = api.listGrants(sql, pid).find((g) => g.scope === "bridgeCert")!;

      // Granting a scope the principal already holds live is a no-op, NOT a
      // replacement. If the id moved here, a reference taken a moment
      // earlier would now point at nothing.
      api.grantCapability(sql, pid, "bridgeCert", "granter-2");
      return {
        first,
        after: api.listGrants(sql, pid).filter((g) => g.scope === "bridgeCert"),
      };
    });

    expect(after).toHaveLength(1);
    expect(after[0]!.id).toBe(first.id);
    expect(after[0]!.grantedBy).toBe("granter-1"); // the original grant stands
    expect(after[0]!.grantedAt).toBe(first.grantedAt);
  });

  // THE INDEX IS THE BACKSTOP, AND IT NEEDED ITS OWN TEST. Mutation-removing
  // `capability_grants_one_live` left every other test in this file green,
  // because `grantCapability`'s own live-check fires first — so the index was
  // redundant defence that nothing could distinguish from decoration. The
  // thing it actually guards is a caller that does NOT go through
  // grantCapability, which is what this test is.
  it("refuses a second live grant written straight to the table", async () => {
    const pid = crypto.randomUUID();
    await withGrants("grant-index-backstop", (api, sql) => {
      const db = sql as { exec(q: string, ...a: unknown[]): unknown };
      api.createPrincipal(sql, pid, "index backstop subject");
      api.grantCapability(sql, pid, "bridgeCert", "granter-1");

      expect(() =>
        db.exec(
          "INSERT INTO capability_grants (id, principal_id, scope, granted_by) VALUES (?, ?, 'bridgeCert', 'bypass')",
          crypto.randomUUID(),
          pid,
        ),
      ).toThrow(/UNIQUE|constraint/i);

      // A second REVOKED row is fine — history is append-only, and the
      // index deliberately does not cover it.
      db.exec(
        "INSERT INTO capability_grants (id, principal_id, scope, granted_by, revoked_at) VALUES (?, ?, 'bridgeCert', 'historic', '2026-01-01 00:00:00')",
        crypto.randomUUID(),
        pid,
      );
      expect(api.getCapabilities(sql, pid)).toEqual(["bridgeCert"]);
    });
  });

  // THE MIGRATION IS THE RISKY PART, so it gets its own test. Every test
  // above runs against a DO whose table was created new, in the post-fix
  // shape — so none of them would notice if the rebuild were deleted. This
  // one builds the OLD table by hand, puts live and revoked rows in it, and
  // then lets ensurePrincipalSchema find them.
  it("rebuilds an existing table that carries the old all-rows UNIQUE, losing no rows", async () => {
    const pid = crypto.randomUUID();
    const result = await withGrants("grant-migration", (api, sql) => {
      const db = sql as {
        exec(q: string, ...a: unknown[]): { toArray(): unknown[] };
      };
      db.exec("DROP TABLE IF EXISTS capability_grants");
      db.exec(`
        CREATE TABLE capability_grants (
          id           TEXT PRIMARY KEY,
          principal_id TEXT NOT NULL,
          scope        TEXT NOT NULL,
          granted_by   TEXT,
          granted_at   TEXT NOT NULL DEFAULT (datetime('now')),
          expires_at   TEXT,
          revoked_at   TEXT,
          revoked_by   TEXT,
          UNIQUE(principal_id, scope)
        )
      `);
      db.exec("DROP INDEX IF EXISTS capability_grants_one_live");
      db.exec(
        "INSERT INTO capability_grants (id, principal_id, scope, granted_by, granted_at) VALUES ('old-live', ?, 'bridgeCert', 'granter-0', '2026-01-01 00:00:00')",
        pid,
      );
      db.exec(
        "INSERT INTO capability_grants (id, principal_id, scope, granted_by, granted_at, revoked_at, revoked_by) VALUES ('old-revoked', ?, 'certMint', 'granter-0', '2026-01-02 00:00:00', '2026-01-03 00:00:00', 'revoker-0')",
        pid,
      );

      // The migration runs here, on an authority that predates it.
      api.ensurePrincipalSchema(sql);

      // A re-grant of the revoked scope must now append rather than
      // overwrite — the behaviour the rebuild exists to enable.
      api.grantCapability(sql, pid, "certMint", "granter-1");

      const ddl = (
        db
          .exec(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'capability_grants'",
          )
          .toArray() as Array<{ sql: string | null }>
      )[0]?.sql;
      return { grants: api.listGrants(sql, pid), ddl };
    });

    // Both pre-existing rows survived, ids intact — a migration that loses
    // the revoked row destroys exactly the history this change protects.
    const byId = new Map(result.grants.map((g) => [g.id, g]));
    expect(byId.get("old-live")?.revokedAt).toBeNull();
    expect(byId.get("old-live")?.grantedBy).toBe("granter-0");
    expect(byId.get("old-revoked")?.revokedBy).toBe("revoker-0");
    // And the constraint that caused the defect is gone from the new table.
    expect(result.ddl).not.toContain("UNIQUE(principal_id, scope)");
    // The appended grant proves the rebuild took effect, not just that the
    // DDL text changed.
    const certMint = result.grants.filter((g) => g.scope === "certMint");
    expect(certMint).toHaveLength(2);
    expect(certMint.filter((g) => g.revokedAt === null)).toHaveLength(1);
  });

  it("never holds two live grants for one scope", async () => {
    const pid = crypto.randomUUID();
    const { live, secondRevoke, scopesAfter } = await withGrants(
      "grant-one-live",
      (api, sql) => {
        api.createPrincipal(sql, pid, "one live subject");
        api.grantCapability(sql, pid, "certMint", "g1");
        api.grantCapability(sql, pid, "certMint", "g2");
        api.revokeCapability(sql, pid, "certMint", "r1");
        api.grantCapability(sql, pid, "certMint", "g3");
        return {
          live: api
            .listGrants(sql, pid)
            .filter((g) => g.scope === "certMint" && g.revokedAt === null),
          // One revoke must be enough to take the scope away. A second live
          // row would leave the principal holding a scope they were
          // stripped of — the partial unique index is what forbids it.
          secondRevoke: api.revokeCapability(sql, pid, "certMint", "r2").revoked,
          scopesAfter: api.getCapabilities(sql, pid),
        };
      },
    );

    expect(live).toHaveLength(1);
    expect(secondRevoke).toBe(true);
    expect(scopesAfter).not.toContain("certMint");
  });
});
