/**
 * staging-smoke-config.test.ts — the post-merge staging deploy cannot reset
 * staging to template placeholders, and its token is fenced (notme-6ae724,
 * security review H1, H2, M1, L4).
 *
 * H1: wrangler makes the config's vars authoritative, so a config rebuilt from
 *     the template with only the KV id filled set staging's
 *     GHA_ALLOWED_OWNERS to "your-staging-org" — an org anyone can register.
 * H2: the token can deploy ANY Worker in the account (Cloudflare API tokens
 *     scope to account/zone, not to a script), so only `main` may run it.
 * M1: only the deploy step may see the token.
 * L4: an unconfigured run must not show green.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  renderStagingConfig,
  stagingPlaceholders,
  stagingRouteProblems,
  stagingVarKeys,
} from "../../../scripts/staging-config";

const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const template = readFileSync(join(ROOT, "worker/wrangler.toml.example"), "utf8");
const workflow = readFileSync(join(ROOT, ".github/workflows/staging-smoke.yml"), "utf8");

const fullEnv = (): Record<string, string> => ({
  STAGING_SITE_URL: "https://staging.notme.bot",
  STAGING_SIGNET_AUTHORITY_URL: "https://auth-staging.notme.bot",
  STAGING_GHA_ALLOWED_OWNERS: "a-real-staging-org",
  STAGING_ALLOWED_AUDIENCES: "https://staging.notme.bot,https://auth-staging.notme.bot",
  STAGING_RENEWAL_BINDING_V3: "off",
  STAGING_KV_NAMESPACE_ID: "0123456789abcdef0123456789abcdef",
});

/** The text of one top-level job (two-space-indented key). */
function job(name: string): string {
  const lines = workflow.split("\n");
  const start = lines.findIndex((l) => l === `  ${name}:`);
  if (start < 0) return "";
  const end = lines.findIndex((l, i) => i > start && /^ {2}[\w-]+:\s*$/.test(l));
  return lines.slice(start, end < 0 ? undefined : end).join("\n");
}

/** Steps of a job, split on `- ` at step indentation. */
const steps = (j: string) => j.split(/\n(?= {6}- )/).slice(1);

describe("staging config rendering (H1)", () => {
  it("the defect: filling only the KV id leaves a registrable placeholder owner", () => {
    const kvOnly = template.replace("<your-staging-kv-namespace-id>", "0123456789abcdef0123456789abcdef");
    expect(stagingPlaceholders(kvOnly).join("\n")).toMatch(/GHA_ALLOWED_OWNERS = "your-staging-org"/);
  });

  it("requires EVERY staging var from the environment — the list is read from the template", () => {
    expect(stagingVarKeys(template)).toEqual([
      "SITE_URL",
      "SIGNET_AUTHORITY_URL",
      "GHA_ALLOWED_OWNERS",
      "ALLOWED_AUDIENCES",
      "RENEWAL_BINDING_V3",
    ]);
    for (const k of Object.keys(fullEnv())) {
      const env = fullEnv();
      delete env[k];
      expect(() => renderStagingConfig(template, env), k).toThrow(new RegExp(k));
    }
  });

  it("fails closed when a supplied value is itself a placeholder", () => {
    expect(() => renderStagingConfig(template, { ...fullEnv(), STAGING_GHA_ALLOWED_OWNERS: "your-staging-org" })).toThrow(
      /placeholders remain/,
    );
    expect(() => renderStagingConfig(template, { ...fullEnv(), STAGING_KV_NAMESPACE_ID: "REPLACE-ME" })).toThrow(
      /placeholders remain/,
    );
  });

  it("fails closed on a placeholder anywhere in a staging table, not only vars", () => {
    const t = template.replace('pattern = "staging.notme.bot"', 'pattern = "your-host.example"');
    expect(() => renderStagingConfig(t, fullEnv())).toThrow(/env\.staging\.routes/);
  });

  it("renders the supplied values and leaves production tables alone", () => {
    const out = renderStagingConfig(template, fullEnv());
    expect(out).toContain('GHA_ALLOWED_OWNERS = "a-real-staging-org"');
    expect(out).toContain('id = "0123456789abcdef0123456789abcdef"');
    expect(stagingPlaceholders(out)).toEqual([]);
    // Production's placeholders are untouched — `--env staging` never reads them.
    expect(out).toContain('GHA_ALLOWED_OWNERS = "your-org"');
  });

  it("writes values as TOML strings, so a hostile value cannot break out", () => {
    const out = renderStagingConfig(template, { ...fullEnv(), STAGING_GHA_ALLOWED_OWNERS: 'x"\n[evil]' });
    expect(out).toContain('GHA_ALLOWED_OWNERS = "x\\"\\n[evil]"');
    expect(out).not.toMatch(/^\[evil\]/m);
  });
});

describe("staging-smoke.yml fences the token (H2, M1, L4)", () => {
  it("builds the config with staging-config.ts, not a one-placeholder sed", () => {
    expect(workflow).toMatch(/scripts\/staging-config\.ts worker\/wrangler\.toml\.example worker\/wrangler\.toml/);
    expect(workflow).not.toMatch(/sed "s\|<your-staging-kv-namespace-id>/);
    for (const k of stagingVarKeys(template)) {
      expect(workflow, k).toContain(`STAGING_${k}: \${{ vars.STAGING_${k} }}`);
    }
  });

  it("every job that touches the staging environment runs only on refs/heads/main", () => {
    for (const name of ["configured", "staging-smoke"]) {
      expect(job(name), name).toMatch(/^ {4}if: .*github\.ref == 'refs\/heads\/main'/m);
    }
  });

  it("the token reaches the deploy step and nothing else", () => {
    const smoke = job("staging-smoke");
    const holders = steps(smoke).filter((s) => s.includes("secrets.CLOUDFLARE_STAGING_API_TOKEN"));
    expect(holders).toHaveLength(1);
    expect(holders[0]).toMatch(/run: task worker:deploy-staging/);
    // Not at job level.
    const header = smoke.split("\n    steps:")[0];
    expect(header).not.toContain("secrets.");
  });

  it("the configured-check sees only a boolean, never the token", () => {
    const gate = job("configured");
    expect(gate).toMatch(/secrets\.CLOUDFLARE_STAGING_API_TOKEN != ''/);
    expect(gate).not.toMatch(/: \$\{\{ secrets\.CLOUDFLARE_STAGING_API_TOKEN \}\}/);
  });

  it("an unconfigured run is SKIPPED, not green", () => {
    expect(job("staging-smoke")).toMatch(/needs: configured/);
    expect(job("staging-smoke")).toMatch(/needs\.configured\.outputs\.ready == 'true'/);
    expect(job("configured")).toMatch(/::warning/);
  });
});

describe("staging config — re-review N4, N7", () => {
  it("N4: a \$& / \$\` / \$' in the KV id is written literally, not expanded", () => {
    for (const v of ["ab$&cd", "ab$\`cd", "ab$'cd"]) {
      const out = renderStagingConfig(template, { ...fullEnv(), STAGING_KV_NAMESPACE_ID: v });
      expect(out, v).toContain(`id = ${JSON.stringify(v)}`);
    }
  });

  it("N7: the template's staging routes are its own, not production's", () => {
    expect(stagingRouteProblems(template)).toEqual([]);
  });

  it("N7: no staging routes → refused (it would inherit production's notme.bot/* and auth.notme.bot/*)", () => {
    const noRoutes = template.replace(/\[\[env\.staging\.routes\]\]\npattern = "[^"]*"\ncustom_domain = true\n/g, "");
    expect(noRoutes).not.toContain("[[env.staging.routes]]");
    expect(() => renderStagingConfig(noRoutes, fullEnv())).toThrow(/declares no routes/);
  });

  it("N7: a staging route naming a production host, or a wildcard, is refused", () => {
    const prod = template.replace('pattern = "auth-staging.notme.bot"', 'pattern = "auth.notme.bot"');
    expect(() => renderStagingConfig(prod, fullEnv())).toThrow(/production host/);
    const wild = template.replace('pattern = "staging.notme.bot"', 'pattern = "*.notme.bot/*"');
    expect(() => renderStagingConfig(wild, fullEnv())).toThrow(/wildcard/);
  });
});
