/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * sign-scopes.do.test.ts — the advertised signing scopes are reachable
 * (notme-486e8a follow-on: "if it advertises it should work").
 *
 * scopes_supported published sign:git and sign:attestation, and
 * AuthService.sign() requires one of them for its git-commit and dsse
 * formats. But no route could grant them (canGrant requires the grantor to
 * HOLD a scope, and no admin did) and no certificate could carry them
 * (CERT_ELIGIBLE_SCOPES was {bridgeCert}). Two advertised scopes and two
 * signing formats that could never be used.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { ADMIN_SCOPES } from "./auth/admin-scopes";
import { certScopesForSession } from "./auth/passkey-cert-scopes";
import { grantCapability, revokeCapability } from "./auth/principals";
import type { SigningAuthority } from "./signing-authority";

const fresh = (name: string) =>
  env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(`sign-scopes-${name}-${crypto.randomUUID()}`));

describe("the admin set includes the signing scopes", () => {
  it("ADMIN_SCOPES is the deployer's full set", () => {
    expect([...ADMIN_SCOPES]).toEqual(["bridgeCert", "authorityManage", "certMint", "sign:git", "sign:attestation"]);
  });

  it("the first passkey user is granted it", async () => {
    const stub = fresh("first");
    const scopes = await stub.ensurePasskeyPrincipal("deployer", true);
    expect([...scopes].sort()).toEqual([...ADMIN_SCOPES].sort());
  });

  it("a later user is not", async () => {
    const stub = fresh("later");
    expect(await stub.ensurePasskeyPrincipal("someone", false)).toEqual(["bridgeCert"]);
  });
});

describe("existing admins are migrated, once, and a deliberate revocation sticks", () => {
  /** Plant a principal holding exactly `scopes`, as production holds them. */
  async function plant(stub: DurableObjectStub<SigningAuthority>, pid: string, scopes: string[]) {
    await runInDurableObject(stub, (a) => {
      const sql = (a as SigningAuthority)["ctx"].storage.sql;
      for (const s of scopes) grantCapability(sql, pid, s, "test");
    });
  }

  it("an admin holding the old triple gains sign:git and sign:attestation", async () => {
    const stub = fresh("migrate");
    await stub.createPrincipalWithCapabilities("old-admin", ["bridgeCert", "authorityManage", "certMint"]);
    await stub.migrateAdminSigningScopes();
    expect((await stub.getPrincipalScopes("old-admin")).sort()).toEqual([...ADMIN_SCOPES].sort());
  });

  it("does NOT re-grant a signing scope the admin revoked", async () => {
    const stub = fresh("revoked");
    await stub.createPrincipalWithCapabilities("careful-admin", ["bridgeCert", "authorityManage", "certMint", "sign:git"]);
    await runInDurableObject(stub, (a) => {
      revokeCapability((a as SigningAuthority)["ctx"].storage.sql, "careful-admin", "sign:git", "careful-admin");
    });
    await stub.migrateAdminSigningScopes();
    const after = await stub.getPrincipalScopes("careful-admin");
    expect(after).not.toContain("sign:git");
    expect(after).toContain("sign:attestation");
  });

  it("leaves a non-admin alone", async () => {
    const stub = fresh("nonadmin");
    await stub.createPrincipalWithCapabilities("user", ["bridgeCert"]);
    await stub.migrateAdminSigningScopes();
    expect(await stub.getPrincipalScopes("user")).toEqual(["bridgeCert"]);
  });

  it("leaves a partial admin (authorityManage without certMint) alone", async () => {
    // Only a principal holding the WHOLE old deployer set was a deployer.
    const stub = fresh("partial");
    await stub.createPrincipalWithCapabilities("ops", ["bridgeCert", "authorityManage"]);
    await stub.migrateAdminSigningScopes();
    expect((await stub.getPrincipalScopes("ops")).sort()).toEqual(["authorityManage", "bridgeCert"]);
  });

  it("is idempotent", async () => {
    const stub = fresh("idem");
    await stub.createPrincipalWithCapabilities("admin", ["bridgeCert", "authorityManage", "certMint"]);
    await stub.migrateAdminSigningScopes();
    await stub.migrateAdminSigningScopes();
    const grants = await stub.listGrants("admin");
    expect(grants.filter((g: { scope: string }) => g.scope === "sign:git")).toHaveLength(1);
  });
});

describe("a certificate may carry the signing scopes", () => {
  it("signing purposes are cert-eligible; administration and delegation still are not", () => {
    expect(certScopesForSession([...ADMIN_SCOPES])).toEqual(["bridgeCert", "sign:git", "sign:attestation"]);
  });
});
