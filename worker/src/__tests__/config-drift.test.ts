// config-drift.test.ts — the pre-deploy check that the live, gitignored
// worker/wrangler.toml has not fallen behind the template (notme-a3804c,
// overnight review H3).
//
// Run against FIXTURES only. The real live file is never read here: it holds
// real resource ids, and CI does not have it.

import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parse as parseYaml } from "yaml";
import { configDrift, parseToml, run, TomlError } from "../../../scripts/config-drift";
import { renderStagingConfig, stagingVarKeys } from "../../../scripts/staging-config";

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url).href);
const TEMPLATE_PATH = here("../../wrangler.toml.example");
const templateText = readFileSync(TEMPLATE_PATH, "utf8");
const template = parseToml(templateText);
const fixture = (name: string) => here(`./fixtures/config-drift/${name}`);

/** The template as CI renders it for a staging deploy: real-looking values, no placeholders. */
function inLine(): string {
  const env: Record<string, string> = { STAGING_KV_NAMESPACE_ID: "0123456789abcdef" };
  for (const k of stagingVarKeys(templateText)) env[`STAGING_${k}`] = `value-for-${k}`;
  env.STAGING_REKOR_URL = "https://rekor.sigstage.dev";
  return renderStagingConfig(templateText, env);
}

describe("parseToml reads what wrangler configs use", () => {
  it("the template parses, with its tables, arrays of tables and staging env", () => {
    expect(template.compatibility_date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(Array.isArray(template.ratelimits)).toBe(true);
    const staging = (template.env as Record<string, any>).staging;
    expect(staging.vars.REKOR_URL).toBe("https://rekor.sigstage.dev");
    expect(staging.ratelimits.map((r: any) => r.name)).toContain("SESSION_LIMITER");
    // [ratelimits.simple] belongs to the LAST [[ratelimits]] above it.
    expect((template.ratelimits as any[])[0].simple).toEqual({ limit: 20, period: 60 });
  });

  it("multi-line arrays and strings, inline tables, quoted and dotted keys, escapes", () => {
    const t = parseToml(readFileSync(fixture("nodejs-compat.toml"), "utf8")) as Record<string, any>;
    expect(t.compatibility_flags).toEqual(["nodejs_compat", "some_other_flag"]);
    expect(t.workers_dev).toBe(false);
    expect(t.limits).toEqual({ cpu_ms: 50 });
    expect(t.observability).toEqual({ enabled: true });
    expect(t.vars.CT_LOG_SHARDS).toContain('"log_id"');
    expect(t.vars.ESCAPED).toBe('a "quoted" é value');
    expect(t.vars.MULTI).toBe("line one continued");
  });

  it("a parse error names the line, never its content", () => {
    let err: unknown;
    try {
      parseToml(readFileSync(fixture("unparseable.toml"), "utf8"));
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(TomlError);
    expect((err as Error).message).toMatch(/line 3/);
    expect((err as Error).message).not.toContain("fixture-secret");
  });
});

describe("configDrift", () => {
  it("control: the template rendered the way CI renders it has no drift", () => {
    expect(configDrift(template, parseToml(inLine()))).toEqual([]);
  });

  it("the stale fixture: every drift is named, and nothing else", () => {
    const drift = configDrift(template, parseToml(readFileSync(fixture("stale.toml"), "utf8")));
    const tDate = String(template.compatibility_date);
    const stagingVarsMissing = stagingVarKeys(templateText)
      .filter((k) => !["SITE_URL", "SIGNET_AUTHORITY_URL", "GHA_ALLOWED_OWNERS", "ALLOWED_AUDIENCES", "REKOR_URL"].includes(k))
      .map((k) => `env.staging.vars.${k}: missing`);
    expect(drift).toEqual([
      `compatibility_date: older than the template's (${tDate})`,
      "version_metadata: missing (template binds CF_VERSION_METADATA)",
      "env.staging.version_metadata: missing (template binds CF_VERSION_METADATA)",
      "ratelimits: SESSION_LIMITER missing",
      "ratelimits: PRINCIPAL_LIMITER missing",
      "env.staging.ratelimits: TOKEN_LIMITER namespace_id differs from the template's (2001)",
      "env.staging.ratelimits: CERT_LIMITER missing",
      "env.staging.ratelimits: PASSKEY_LIMITER missing",
      "env.staging.ratelimits: SESSION_LIMITER missing",
      "env.staging.ratelimits: PRINCIPAL_LIMITER missing",
      "env.staging.vars.REKOR_URL: missing (want https://rekor.sigstage.dev)",
      ...stagingVarsMissing,
    ]);
  });

  it("refuses nodejs_compat and nodejs_compat_v2 at top level and in staging; a trailing slash on REKOR_URL is the same URL", () => {
    const drift = configDrift(template, parseToml(readFileSync(fixture("nodejs-compat.toml"), "utf8")));
    expect(drift).toContain("compatibility_flags: lists nodejs_compat (a default at this date; workerd refuses it)");
    expect(drift).toContain("env.staging.compatibility_flags: lists nodejs_compat_v2 (a default at this date; workerd refuses it)");
    expect(drift.some((d) => d.startsWith("env.staging.vars.REKOR_URL"))).toBe(false);
    expect(drift.some((d) => d.startsWith("compatibility_date"))).toBe(false); // newer than the template is fine
  });

  it("a staging REKOR_URL pointed at the PUBLIC Rekor is named", () => {
    const live = inLine().replace('REKOR_URL = "https://rekor.sigstage.dev"', 'REKOR_URL = "https://rekor.sigstore.dev"');
    expect(configDrift(template, parseToml(live))).toEqual(["env.staging.vars.REKOR_URL: not https://rekor.sigstage.dev"]);
  });

  it("a version_metadata under another binding name is named", () => {
    const live = inLine().replace(
      '[version_metadata]\nbinding = "CF_VERSION_METADATA"',
      '[version_metadata]\nbinding = "OTHER"',
    );
    expect(configDrift(template, parseToml(live))).toEqual(["version_metadata.binding: not CF_VERSION_METADATA"]);
  });

  it("a production [vars] without SIGNET_AUTHORITY_URL is named (the public-Rekor guard would refuse it)", () => {
    const live = inLine().replace('SIGNET_AUTHORITY_URL = "https://auth.notme.bot"\n', "");
    expect(configDrift(template, parseToml(live))).toEqual(["vars.SIGNET_AUTHORITY_URL: missing"]);
  });

  it("no message carries a value from the live file", () => {
    const text = readFileSync(fixture("stale.toml"), "utf8");
    const drift = configDrift(template, parseToml(text)).join("\n");
    expect(drift).not.toContain("fixture-secret");
    expect(drift).not.toContain("2026-03-01");
  });
});

describe("Taskfile wiring", () => {
  const tasks = (parseYaml(readFileSync(here("../../../Taskfile.yml"), "utf8")) as { tasks: Record<string, any> }).tasks;
  const DEPLOYISH = [
    "worker:deploy-preview",
    "worker:deploy",
    "worker:deploy-staging",
    "worker:canary",
    "worker:promote",
    "ship",
    "ship-staging",
    "ship-prod",
  ];

  it("every task that deploys or moves traffic depends on worker:config-drift", () => {
    for (const name of DEPLOYISH) {
      expect(tasks[name]?.deps ?? [], name).toContain("worker:config-drift");
    }
  });

  it("every task that runs a wrangler deploy/upload, or the promote script, is in that list", () => {
    const moves = /wrangler (deploy|versions (upload|deploy))|worker-promote\.sh/;
    const found = Object.entries(tasks)
      .filter(([, t]) => JSON.stringify(t.cmds ?? []).match(moves))
      .map(([n]) => n);
    expect(found.filter((n) => !DEPLOYISH.includes(n))).toEqual([]);
  });

  it("worker:rollback, the emergency exit, does NOT wait on it", () => {
    expect(tasks["worker:rollback"]?.deps ?? []).not.toContain("worker:config-drift");
  });
});

describe("run (the CLI)", () => {
  const dir = mkdtempSync(join(tmpdir(), "config-drift-"));

  it("live absent: skipped with a message, exit 0 — and exit 1 under STRICT=1", () => {
    const live = join(dir, "absent.toml");
    const lax = run({ template: TEMPLATE_PATH, live, strict: false });
    expect(lax.code).toBe(0);
    expect(lax.lines.join("\n")).toMatch(/skipped/);
    const strict = run({ template: TEMPLATE_PATH, live, strict: true });
    expect(strict.code).toBe(1);
    expect(strict.lines.join("\n")).toMatch(/STRICT=1/);
  });

  it("drift: exit 1 with the list, and no live value in the output", () => {
    const r = run({ template: TEMPLATE_PATH, live: fixture("stale.toml"), strict: false });
    expect(r.code).toBe(1);
    expect(r.lines[0]).toMatch(/lags/);
    expect(r.lines).toContain("  - ratelimits: SESSION_LIMITER missing");
    expect(r.lines.join("\n")).not.toContain("fixture-secret");
  });

  it("an unparseable live file fails closed, naming the line only", () => {
    const r = run({ template: TEMPLATE_PATH, live: fixture("unparseable.toml"), strict: false });
    expect(r.code).toBe(1);
    expect(r.lines.join("\n")).toMatch(/line 3/);
    expect(r.lines.join("\n")).not.toContain("fixture-secret");
  });

  it("in line: exit 0", () => {
    const live = join(dir, "wrangler.toml");
    writeFileSync(live, inLine());
    expect(run({ template: TEMPLATE_PATH, live, strict: true }).code).toBe(0);
  });
});
