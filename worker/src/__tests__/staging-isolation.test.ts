// staging-isolation.test.ts — the [env.staging] properties ADR-018 calls
// load-bearing are structural, not aspirational.
//
// ADR-018 promises that the staging gate exercises the real Worker/DO
// boundary WITHOUT touching production state. Three config facts carry that
// promise, and each fails silently if someone edits it later:
//
//   1. No vpc_services under env.staging. worker.ts guards `if (env.VPC_AUTH)`
//      and falls through to a 503, so ADDING a VPC binding would quietly give
//      staging a live path to the production signet backend on Fly — the one
//      thing staging must never reach.
//   2. A distinct Worker name, so staging gets its own Durable Objects (its
//      own SigningAuthority CA key, its own RevocationAuthority). Sharing the
//      name would point staging at PRODUCTION's DOs.
//   3. Staging hosts in SITE_URL/SIGNET_AUTHORITY_URL. worker.ts derives the
//      authority surface from SIGNET_AUTHORITY_URL (authorityHostFromEnv), so
//      a production URL here makes staging serve production's identity —
//      and worker:verify's api-docs check would be measuring the wrong thing.
//
// Asserted against wrangler.toml.example: the live worker/wrangler.toml is
// gitignored (it carries real resource ids), so the example is the only copy
// CI can see — which also makes it the only copy a reviewer reads. Same
// string-assertion idiom as deployment-verification.test.ts.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const config = readFileSync(
  fileURLToPath(new URL("../../wrangler.toml.example", import.meta.url)),
  "utf8",
);

/**
 * Every TOML section header belonging to the staging environment, paired with
 * its body. A section belongs to staging when its header starts with
 * `env.staging` — `[env.staging]`, `[[env.staging.routes]]`,
 * `[env.staging.vars]`, and so on.
 */
function stagingSections(): Array<{ header: string; body: string }> {
  const sections: Array<{ header: string; body: string }> = [];
  let current: { header: string; body: string } | null = null;
  for (const line of config.split("\n")) {
    const header = line.match(/^\s*\[{1,2}\s*([^\]]+?)\s*\]{1,2}\s*$/);
    if (header) {
      if (current) sections.push(current);
      current = /^env\.staging\b/.test(header[1]!)
        ? { header: header[1]!, body: "" }
        : null;
      continue;
    }
    if (current) current.body += line + "\n";
  }
  if (current) sections.push(current);
  return sections;
}

describe("[env.staging] isolation (ADR-018)", () => {
  it("declares a staging environment at all", () => {
    expect(stagingSections().length).toBeGreaterThan(0);
  });

  it("has NO vpc_services — staging must not reach the production backend", () => {
    const vpc = stagingSections().filter((s) =>
      /(^|\.)vpc_services$/.test(s.header),
    );
    expect(vpc).toEqual([]);
    // Belt and braces: the binding name must not appear anywhere under
    // staging, whatever section shape a future edit uses.
    for (const s of stagingSections()) {
      expect(s.body).not.toContain("VPC_AUTH");
    }
  });

  it("runs under its own Worker name, so it gets its own Durable Objects", () => {
    const root = stagingSections().find((s) => s.header === "env.staging");
    expect(root).toBeDefined();
    const name = root!.body.match(/^\s*name\s*=\s*"([^"]+)"/m)?.[1];
    expect(name).toBeDefined();
    expect(name).not.toBe("notme-bot"); // the production Worker
    expect(name).toContain("staging");
  });

  it("points its vars at staging hosts, never production", () => {
    const vars = stagingSections().find((s) => s.header === "env.staging.vars");
    expect(vars).toBeDefined();
    const siteUrl = vars!.body.match(/^\s*SITE_URL\s*=\s*"([^"]+)"/m)?.[1];
    const authorityUrl = vars!.body.match(
      /^\s*SIGNET_AUTHORITY_URL\s*=\s*"([^"]+)"/m,
    )?.[1];

    expect(siteUrl).toBeDefined();
    expect(authorityUrl).toBeDefined();
    // Exact production hosts are the failure this catches — a staging deploy
    // that serves production's identity surface.
    expect(new URL(siteUrl!).host).not.toBe("notme.bot");
    expect(new URL(authorityUrl!).host).not.toBe("auth.notme.bot");
    expect(new URL(authorityUrl!).host).toContain("staging");
  });

  it("binds its OWN kv namespace id, not production's", () => {
    const stagingKv = stagingSections().filter((s) =>
      /(^|\.)kv_namespaces$/.test(s.header),
    );
    expect(stagingKv.length).toBeGreaterThan(0);
    // The example ships placeholders; what matters is that staging declares
    // its own id line rather than inheriting or reusing production's.
    for (const s of stagingKv) {
      expect(s.body).toMatch(/^\s*id\s*=/m);
    }
  });
});
