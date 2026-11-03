/**
 * promote-gate.test.ts — `task worker:promote` refuses a version nothing has
 * verified (notme-16b2d5).
 *
 * THE DEFECT. `worker:promote` had one precondition — that `NEW` was a
 * non-empty string — and then ran `wrangler versions deploy NEW@100%`. Any
 * version id in the account's upload history went to 100% of production in one
 * command: one uploaded before a gate existed, by another operator, from a
 * branch that never passed staging. And `ENV` defaulted to production when
 * omitted, so a staging rehearsal with a dropped `ENV=staging` promoted
 * production.
 *
 * THE CONTRACT PINNED HERE, driven through the real Taskfile so the wiring is
 * under test and not just the script:
 *   - ENV is mandatory; neither environment is reachable by omission.
 *   - promote refuses unless a VERSION-KEYED evidence record says a pinned
 *     verify passed for exactly this version in exactly this environment.
 *   - the emergency override needs a typed reason and is logged.
 *   - after the deploy it converges + verifies, and on failure promotes the
 *     prior version back (the defined failure action).
 *
 * `wrangler` is never reached for real: a fake `pnpm` on PATH records what
 * would have run. Nothing here touches a Cloudflare account.
 */
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it } from "vitest";

const ROOT = fileURLToPath(new URL("../../../", import.meta.url));

const NEW = "11111111-2222-4333-8444-555555555555";
const PREV = "99999999-8888-4777-8666-555555555555";
const SHA = "a".repeat(40);

let dir: string;
let log: string;
let evidence: string;

/**
 * A fake `pnpm` that records every invocation and impersonates the two wrangler
 * calls promote makes: `deployments status --json` (who holds traffic now) and
 * `versions deploy` (which it only logs).
 */
function installFakePnpm(bin: string) {
  writeFileSync(
    join(bin, "pnpm"),
    `#!/usr/bin/env bash
echo "$*" >> "$FAKE_LOG"
case "$*" in
  *"deployments status"*)
    printf '{"id":"dep","versions":[{"version_id":"%s","percentage":100}]}\\n' "$FAKE_PREV" ;;
esac
exit 0
`,
  );
  chmodSync(join(bin, "pnpm"), 0o755);
}

/** A stand-in for verify / convergence that exits with a chosen status and records the call. */
function stub(name: string, code: number): string {
  const p = join(dir, `${name}-exit${code}`);
  writeFileSync(p, `#!/usr/bin/env bash\necho "${name} VERSION=\${VERSION:-} EXPECT=\${EXPECT:-} AUTH_BASE=\${AUTH_BASE:-}" >> "$FAKE_LOG"\nexit ${code}\n`);
  chmodSync(p, 0o755);
  return p;
}

function writeEvidence(env: string, version: string, body: Record<string, unknown>) {
  mkdirSync(join(evidence, env), { recursive: true });
  writeFileSync(join(evidence, env, `${version}.json`), JSON.stringify(body));
}

const goodEvidence = (env: string, version = NEW) => ({
  schema: "notme.release-evidence/v1",
  result: "pass",
  pinned: true,
  version,
  env,
  commit: SHA,
  auth_base: env === "staging" ? "https://auth-staging.notme.bot" : "https://auth.notme.bot",
  checked_at: new Date().toISOString(),
});

function promote(vars: Record<string, string>, extraEnv: Record<string, string> = {}) {
  const args = ["-d", ROOT, "worker:promote", ...Object.entries(vars).map(([k, v]) => `${k}=${v}`)];
  const r = spawnSync("task", args, {
    env: {
      ...process.env,
      PATH: `${join(dir, "bin")}:${process.env.PATH}`,
      FAKE_LOG: log,
      FAKE_PREV: PREV,
      NOTME_EVIDENCE_DIR: evidence,
      NOTME_PROMOTE_VERIFY_CMD: stub("verify", 0),
      NOTME_PROMOTE_CONVERGE_CMD: stub("converge", 0),
      ...extraEnv,
    },
    encoding: "utf8",
    timeout: 60_000,
  });
  const calls = existsSync(log) ? readFileSync(log, "utf8") : "";
  return { code: r.status, out: `${r.stdout}\n${r.stderr}`, calls };
}

const deployed = (calls: string, version: string) =>
  calls.split("\n").some((l) => l.includes("versions deploy") && l.includes(`${version}@100%`));

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "promote-gate-"));
  mkdirSync(join(dir, "bin"));
  installFakePnpm(join(dir, "bin"));
  log = join(dir, "calls.log");
  evidence = join(dir, "evidence");
});

describe("worker:promote gate (notme-16b2d5)", () => {
  it("refuses when ENV is omitted — production is not reachable by omission", () => {
    writeEvidence("production", NEW, goodEvidence("production"));
    const r = promote({ NEW });
    expect(r.code).not.toBe(0);
    expect(deployed(r.calls, NEW)).toBe(false);
  });

  it("refuses an unknown ENV", () => {
    const r = promote({ NEW, ENV: "prod" });
    expect(r.code).not.toBe(0);
    expect(deployed(r.calls, NEW)).toBe(false);
  });

  it("refuses a version with no evidence record", () => {
    const r = promote({ NEW, ENV: "production" });
    expect(r.code).not.toBe(0);
    expect(deployed(r.calls, NEW)).toBe(false);
    expect(r.out).toMatch(/no verify evidence/i);
  });

  it("refuses evidence recorded for a DIFFERENT environment", () => {
    // Staging and production version ids never coincide in practice, but the
    // record is keyed by env so a staging pass can never stand in for prod.
    writeEvidence("staging", NEW, goodEvidence("staging"));
    const r = promote({ NEW, ENV: "production" });
    expect(r.code).not.toBe(0);
    expect(deployed(r.calls, NEW)).toBe(false);
  });

  it("refuses a record whose body names another version (file renamed)", () => {
    writeEvidence("production", NEW, goodEvidence("production", PREV));
    const r = promote({ NEW, ENV: "production" });
    expect(r.code).not.toBe(0);
    expect(deployed(r.calls, NEW)).toBe(false);
  });

  it("refuses an unpinned (sampled) or failed verify record", () => {
    writeEvidence("production", NEW, { ...goodEvidence("production"), pinned: false });
    expect(deployed(promote({ NEW, ENV: "production" }).calls, NEW)).toBe(false);
    writeEvidence("production", NEW, { ...goodEvidence("production"), result: "fail" });
    expect(deployed(promote({ NEW, ENV: "production" }).calls, NEW)).toBe(false);
  });

  it("promotes with matching evidence, then converges on and verifies THAT version", () => {
    writeEvidence("production", NEW, goodEvidence("production"));
    const r = promote({ NEW, ENV: "production" });
    expect(r.code, r.out).toBe(0);
    expect(deployed(r.calls, NEW)).toBe(true);
    // Production carries no --env flag; the converge and verify are pinned to NEW's commit.
    expect(r.calls).not.toMatch(/versions deploy.*--env/);
    expect(r.calls).toContain(`converge VERSION=${NEW} EXPECT=${SHA}`);
    expect(r.calls).toContain(`verify VERSION=${NEW} EXPECT=${SHA}`);
    expect(r.out).toContain("production");
  });

  it("targets staging with --env staging and the staging hosts", () => {
    writeEvidence("staging", NEW, goodEvidence("staging"));
    const r = promote({ NEW, ENV: "staging" });
    expect(r.code, r.out).toBe(0);
    expect(r.calls).toMatch(new RegExp(`versions deploy ${NEW}@100% --env staging`));
    expect(r.calls).toContain("AUTH_BASE=https://auth-staging.notme.bot");
  });

  it("rolls back to the prior version when post-promote verify fails", () => {
    writeEvidence("production", NEW, goodEvidence("production"));
    const r = promote({ NEW, ENV: "production" }, { NOTME_PROMOTE_VERIFY_CMD: stub("verify", 1) });
    expect(r.code).not.toBe(0);
    expect(deployed(r.calls, NEW)).toBe(true);
    expect(deployed(r.calls, PREV)).toBe(true);
    expect(r.out).toMatch(/rolled back/i);
  });

  it("rolls back when convergence never arrives", () => {
    writeEvidence("production", NEW, goodEvidence("production"));
    const r = promote({ NEW, ENV: "production" }, { NOTME_PROMOTE_CONVERGE_CMD: stub("converge", 1) });
    expect(r.code).not.toBe(0);
    expect(deployed(r.calls, PREV)).toBe(true);
  });

  it("override needs a typed reason and an explicit EXPECT, and is logged", () => {
    // A bare flag is not an override — it must say why.
    const bare = promote({ NEW, ENV: "production", ALLOW_UNVERIFIED: "yes" });
    expect(deployed(bare.calls, NEW)).toBe(false);

    const noSha = promote({ NEW, ENV: "production", ALLOW_UNVERIFIED: "incident 42: cert minting down" });
    expect(deployed(noSha.calls, NEW)).toBe(false);

    const ok = promote({ NEW, ENV: "production", ALLOW_UNVERIFIED: "incident 42: cert minting down", EXPECT: SHA });
    expect(ok.code, ok.out).toBe(0);
    expect(deployed(ok.calls, NEW)).toBe(true);
    expect(ok.out).toMatch(/UNVERIFIED PROMOTION/);
    const audit = readFileSync(join(evidence, "overrides.log"), "utf8");
    expect(audit).toContain(NEW);
    expect(audit).toContain("incident 42");
  });
});
