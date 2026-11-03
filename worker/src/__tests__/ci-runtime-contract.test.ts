/**
 * ci-runtime-contract.test.ts — CI runs the post-deploy contract against a
 * real, locally booted Worker on every PR (notme-6ae724).
 *
 * THE GAP. ci.yml ran tsc, the plain suite and the vitest-pool-workers suite.
 * `worker:verify` — the contract that has caught every production regression
 * here (served pathlen:0, unmatched paths as 1101, unstamped builds) — ran only
 * by hand, AFTER the build was serving traffic.
 *
 * What is pinned:
 *   - a ci.yml job runs `task worker:contract` on pull requests, with no
 *     secrets and read-only permissions (it must work on a fork PR);
 *   - worker:contract boots the Worker from config DERIVED from the committed
 *     production template, and runs the same scripts/worker-verify.sh;
 *   - the deployed-preview half (staging-smoke.yml) needs a token, so it never
 *     runs on pull_request and is skipped — not green — until the owner adds it.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const read = (rel: string) => readFileSync(join(ROOT, rel), "utf8");

/** The text of one top-level job in a workflow (two-space-indented key). */
function job(workflow: string, name: string): string {
  const lines = workflow.split("\n");
  const start = lines.findIndex((l) => l === `  ${name}:`);
  if (start < 0) return "";
  const end = lines.findIndex((l, i) => i > start && /^ {2}[\w-]+:\s*$/.test(l));
  return lines.slice(start, end < 0 ? undefined : end).join("\n");
}

describe("CI runtime contract (notme-6ae724)", () => {
  const ci = read(".github/workflows/ci.yml");

  it("a CI job runs `task worker:contract`", () => {
    const contract = job(ci, "contract");
    expect(contract).toMatch(/run: task worker:contract/);
  });

  it("…on pull requests, read-only, with no secrets (so it runs on fork PRs too)", () => {
    expect(ci).toMatch(/^on:[\s\S]*?pull_request:/m);
    const contract = job(ci, "contract");
    expect(contract).toMatch(/permissions:\s*\n\s+contents: read/);
    expect(contract).not.toMatch(/secrets\./);
    expect(contract).not.toMatch(/id-token/);
  });

  it("worker:contract boots from the production template and runs the shared verify", () => {
    const script = read("scripts/worker-contract.sh");
    expect(script).toContain("worker/wrangler.toml.example");
    expect(script).toContain("scripts/worker-verify.sh");
    // Only account-bound sections are dropped — nothing else.
    expect(script).toMatch(/name == "vpc_services" \|\| name == "routes" \|\| name ~ \/\^env\\\.\//);
    expect(read("Taskfile.yml")).toMatch(/worker:contract:[\s\S]*?- bash scripts\/worker-contract\.sh/);
  });

  it("the deployed-preview smoke is token-gated and never runs on pull_request", () => {
    const smoke = read(".github/workflows/staging-smoke.yml");
    const on = smoke.slice(smoke.indexOf("\non:"), smoke.indexOf("\npermissions:"));
    expect(on).not.toMatch(/pull_request/);
    expect(smoke).toMatch(/CLOUDFLARE_STAGING_API_TOKEN/);
    // Absent token → the deploy job is SKIPPED with a warning, not a silent green
    // (staging-smoke-config.test.ts pins the details).
    expect(smoke).toMatch(/::warning[^\n]*NOT RUN/);
    expect(smoke).toMatch(/CLOUDFLARE_STAGING_API_TOKEN\(secret\)/);
    expect(smoke).toMatch(/task worker:verify-staging/);
  });
});
