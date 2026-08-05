/**
 * authority-host.test.ts — the authority surface must be selectable by
 * configuration, not only by the hardcoded auth.notme.bot subdomain.
 *
 * Why: the staging environment (wrangler.toml [env.staging]) serves the
 * authority at auth-staging.notme.bot. getSubdomain() yields "auth-staging"
 * there, which the `sub === "auth"` check rejects — so before
 * authorityHostFromEnv, a staging worker could never serve the authority
 * surface and the staging gate would silently test the wrong code path.
 *
 * Production must be unaffected: with SIGNET_AUTHORITY_URL unset or set to
 * https://auth.notme.bot, the resolved host is auth.notme.bot — exactly what
 * sub === "auth" already matched.
 */

import { describe, expect, it, vi } from "vitest";

// worker.ts's transitive imports reach `cloudflare:workers` (DurableObject,
// WorkerEntrypoint), unavailable in plain vitest. Stub minimal shapes — this
// file tests a pure host-resolution helper, not runtime integration.
vi.mock("cloudflare:workers", () => ({
  DurableObject: class {},
  WorkerEntrypoint: class {
    ctx: unknown;
    env: unknown;
    constructor(ctx: unknown, env: unknown) {
      this.ctx = ctx;
      this.env = env;
    }
  },
}));

const { authorityHostFromEnv, wimseTrustDomain, getAllowedOwners } =
  await import("../../worker");
const { caSubjectForEnv } = await import("../signing-authority");

describe("authorityHostFromEnv", () => {
  it("resolves the production authority URL to its host (parity with sub === 'auth')", () => {
    expect(authorityHostFromEnv("https://auth.notme.bot")).toBe(
      "auth.notme.bot",
    );
  });

  it("resolves a staging authority URL so [env.staging] can serve the surface", () => {
    expect(authorityHostFromEnv("https://auth-staging.notme.bot")).toBe(
      "auth-staging.notme.bot",
    );
  });

  it("preserves an explicit port (local workerd)", () => {
    expect(authorityHostFromEnv("http://localhost:8788")).toBe(
      "localhost:8788",
    );
  });

  it("returns null when unset — hardcoded matching remains the only selector", () => {
    expect(authorityHostFromEnv(undefined)).toBeNull();
    expect(authorityHostFromEnv("")).toBeNull();
  });

  it("returns null on a malformed URL instead of throwing in the fetch path", () => {
    expect(authorityHostFromEnv("not a url")).toBeNull();
  });
});

describe("wimseTrustDomain", () => {
  it("derives the domain from SITE_URL so staging cannot name production", () => {
    expect(wimseTrustDomain({ SITE_URL: "https://staging.notme.bot" })).toBe(
      "staging.notme.bot",
    );
  });

  it("returns the production domain when SITE_URL is absent — the documented default", () => {
    // Absent means "no environment configured", whose default is the value
    // every mint site hardcoded before this function existed.
    expect(wimseTrustDomain({})).toBe("notme.bot");
  });

  it("THROWS on a malformed SITE_URL rather than falling back to production", () => {
    // The dangerous case: an operator configured something and got it wrong.
    // Silently resolving that to notme.bot would mint production identities
    // from a misconfigured environment — the exact defect this removes.
    expect(() => wimseTrustDomain({ SITE_URL: "not a url" })).toThrow();
    expect(() => wimseTrustDomain({ SITE_URL: "file:///etc" })).toThrow();
  });
});

describe("cross-environment config must not inherit production (notme-1532eb)", () => {
  it("allows NO GHA owners when unset — omission must fail closed", () => {
    // Previously defaulted to "agentic-research", so deleting the staging var
    // RE-SUPPLIED the production org rather than refusing. An authority that
    // has not declared which orgs may exchange OIDC tokens should accept none.
    expect(getAllowedOwners({}).size).toBe(0);
    expect(getAllowedOwners({ GHA_ALLOWED_OWNERS: "" }).size).toBe(0);
  });

  it("uses exactly the owners declared, normalized", () => {
    const owners = getAllowedOwners({ GHA_ALLOWED_OWNERS: "Foo, bar " });
    expect([...owners].sort()).toEqual(["bar", "foo"]);
  });

  it("gives a non-production authority a distinguishable CA subject", () => {
    // The CA subject DN was the literal CN=signet-authority,O=notme in BOTH
    // environments, so a verifier inspecting the issuing CA could not tell
    // staging from production.
    expect(caSubjectForEnv({})).toBe("CN=signet-authority,O=notme");
    expect(
      caSubjectForEnv({ SIGNET_AUTHORITY_URL: "https://auth.notme.bot" }),
    ).toBe("CN=signet-authority,O=notme");
    expect(
      caSubjectForEnv({ SIGNET_AUTHORITY_URL: "https://auth-staging.notme.bot" }),
    ).toBe("CN=signet-authority auth-staging.notme.bot,O=notme");
  });
});
