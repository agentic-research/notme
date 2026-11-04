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
import { spawn, spawnSync } from "node:child_process";
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
    [ -n "\${FAKE_STATUS_FAIL:-}" ] && { echo "auth error" >&2; exit 1; }
    if [ -n "\${FAKE_DEPLOYMENT:-}" ]; then echo "$FAKE_DEPLOYMENT"
    else printf '{"id":"dep","versions":[{"version_id":"%s","percentage":100}]}\\n' "$FAKE_PREV"; fi ;;
  *"versions deploy $FAKE_PREV@100%"*)
    [ -n "\${FAKE_ROLLBACK_FAIL:-}" ] && { echo "rollback deploy failed" >&2; exit 1; }
    if [ -n "\${FAKE_ROLLBACK_SLEEP:-}" ]; then sleep "$FAKE_ROLLBACK_SLEEP"; fi
    echo "rollback-complete" >> "$FAKE_LOG" ;;
esac
exit 0
`,
  );
  chmodSync(join(bin, "pnpm"), 0o755);
}

/** A stand-in for verify / convergence that exits with a chosen status and records the call. */
function stub(name: string, code: number, sleepS = 0): string {
  const p = join(dir, `${name}-exit${code}-sleep${sleepS}`);
  writeFileSync(p, `#!/usr/bin/env bash\necho "${name} $*" >> "$FAKE_LOG"\n${sleepS ? `sleep ${sleepS}` : ""}\nexit ${code}\n`);
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

/** The inherited environment minus every selector, so only what a test sets is exported. */
function cleanEnv(): NodeJS.ProcessEnv {
  const e = { ...process.env };
  for (const k of ["ENV", "NEW", "EXPECT", "ALLOW_UNVERIFIED", "VERSION", "AUTH_BASE", "SITE_BASE"]) delete e[k];
  return e;
}

function promote(vars: Record<string, string>, extraEnv: Record<string, string> = {}) {
  const args = ["-d", ROOT, "worker:promote", ...Object.entries(vars).map(([k, v]) => `${k}=${v}`)];
  const r = spawnSync("task", args, {
    env: {
      ...cleanEnv(),
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

  it("refuses a pass recorded against a different host (a stub or a local Worker)", () => {
    writeEvidence("production", NEW, { ...goodEvidence("production"), auth_base: "http://127.0.0.1:8787" });
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
    expect(r.calls).toContain(`converge --auth-base https://auth.notme.bot --expect ${SHA}`);
    expect(r.calls).toMatch(new RegExp(`verify .*--version ${NEW} .*--expect ${SHA}`));
    expect(r.out).toContain("production");
  });

  it("targets staging with --env staging and the staging hosts", () => {
    writeEvidence("staging", NEW, goodEvidence("staging"));
    const r = promote({ NEW, ENV: "staging" });
    expect(r.code, r.out).toBe(0);
    expect(r.calls).toMatch(new RegExp(`versions deploy ${NEW}@100% --env staging`));
    expect(r.calls).toContain("--auth-base https://auth-staging.notme.bot");
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

describe("worker:promote — security review fixes (M2, M3, M4, M6, L3)", () => {
  it("M3: rolls back to the highest-percentage version that is NOT NEW (canary at 60%)", () => {
    writeEvidence("production", NEW, goodEvidence("production"));
    const dep = JSON.stringify({ versions: [{ version_id: NEW, percentage: 60 }, { version_id: PREV, percentage: 40 }] });
    const r = promote({ NEW, ENV: "production" }, { FAKE_DEPLOYMENT: dep, NOTME_PROMOTE_VERIFY_CMD: stub("verify", 1) });
    expect(r.code).not.toBe(0);
    expect(deployed(r.calls, PREV)).toBe(true);
    expect(r.out).toMatch(/rolled back/i);
  });

  it("M2: refuses BEFORE deploying when the prior version cannot be determined", () => {
    writeEvidence("production", NEW, goodEvidence("production"));
    const failed = promote({ NEW, ENV: "production" }, { FAKE_STATUS_FAIL: "1" });
    expect(failed.code).not.toBe(0);
    expect(deployed(failed.calls, NEW)).toBe(false);
    expect(failed.out).toMatch(/rollback target/i);

    // A deployment holding only NEW has nothing to roll back to either.
    const onlyNew = JSON.stringify({ versions: [{ version_id: NEW, percentage: 100 }] });
    const r = promote({ NEW, ENV: "production" }, { FAKE_DEPLOYMENT: onlyNew });
    expect(deployed(r.calls, NEW)).toBe(false);
  });

  it("M4: refuses a pass record older than the TTL", () => {
    const stale = new Date(Date.now() - 25 * 3600_000).toISOString();
    writeEvidence("production", NEW, { ...goodEvidence("production"), checked_at: stale });
    const r = promote({ NEW, ENV: "production" });
    expect(r.code).not.toBe(0);
    expect(deployed(r.calls, NEW)).toBe(false);
    expect(r.out).toMatch(/older than 24h/);
  });

  it("M4: a failed post-promote check deletes NEW's pass record, so the next promote is refused", () => {
    writeEvidence("production", NEW, goodEvidence("production"));
    const first = promote({ NEW, ENV: "production" }, { NOTME_PROMOTE_VERIFY_CMD: stub("verify", 1) });
    expect(deployed(first.calls, NEW)).toBe(true);
    expect(existsSync(join(evidence, "production", `${NEW}.json`))).toBe(false);
    const again = promote({ NEW, ENV: "production" });
    expect(again.code).not.toBe(0);
    expect(again.out).toMatch(/no verify evidence/i);
  });

  it("M6: an ENV exported in the shell does not satisfy the requirement", () => {
    writeEvidence("production", NEW, goodEvidence("production"));
    const r = promote({ NEW }, { ENV: "production" });
    expect(r.code).not.toBe(0);
    expect(deployed(r.calls, NEW)).toBe(false);
    expect(r.out).toMatch(/exported in your shell/);
  });

  it("M6: an explicit ENV on the command line wins over a different exported one", () => {
    writeEvidence("staging", NEW, goodEvidence("staging"));
    const r = promote({ NEW, ENV: "staging" }, { ENV: "production" });
    expect(r.code, r.out).toBe(0);
    expect(r.calls).toMatch(new RegExp(`versions deploy ${NEW}@100% --env staging`));
  });

  it("M6: an exported ALLOW_UNVERIFIED is refused, not silently applied", () => {
    const r = promote({ NEW, ENV: "production" }, { ALLOW_UNVERIFIED: "left over from last week", EXPECT: SHA });
    expect(r.code).not.toBe(0);
    expect(deployed(r.calls, NEW)).toBe(false);
  });

  it("L3: an interrupt after the deploy rolls back", async () => {
    writeEvidence("production", NEW, goodEvidence("production"));
    const p = spawn("bash", [join(ROOT, "scripts/worker-promote.sh"), "--env", "production", "--new", NEW], {
      detached: true, // its own process group, like a terminal's foreground job
      env: {
        ...cleanEnv(),
        PATH: `${join(dir, "bin")}:${process.env.PATH}`,
        FAKE_LOG: log,
        FAKE_PREV: PREV,
        NOTME_EVIDENCE_DIR: evidence,
        NOTME_PROMOTE_VERIFY_CMD: stub("verify", 0),
        NOTME_PROMOTE_CONVERGE_CMD: stub("converge", 0, 30),
      },
    });
    let out = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (out += d));
    // Wait until the deploy has happened and convergence is in progress.
    for (let i = 0; i < 100 && !(existsSync(log) && readFileSync(log, "utf8").includes("converge")); i++) {
      await new Promise((r) => setTimeout(r, 100));
    }
    // SIGTERM: a test runner may start children with SIGINT ignored, which bash
    // cannot then trap. The trap is the same for both.
    process.kill(-p.pid!, "SIGTERM");
    const code = await new Promise<number | null>((r) => p.on("close", (c) => r(c)));
    const calls = readFileSync(log, "utf8");
    expect(deployed(calls, NEW), out).toBe(true);
    expect(deployed(calls, PREV), out).toBe(true);
    expect(code).not.toBe(0);
  }, 30_000);
});

describe("worker:promote — re-review N3 (interrupts during rollback)", () => {
  /** Run the script in its own process group, as a terminal's foreground job is. */
  function startDetached(extraEnv: Record<string, string>) {
    const p = spawn("bash", [join(ROOT, "scripts/worker-promote.sh"), "--env", "production", "--new", NEW], {
      detached: true,
      env: {
        ...cleanEnv(),
        PATH: `${join(dir, "bin")}:${process.env.PATH}`,
        FAKE_LOG: log,
        FAKE_PREV: PREV,
        NOTME_EVIDENCE_DIR: evidence,
        NOTME_PROMOTE_VERIFY_CMD: stub("verify", 0),
        NOTME_PROMOTE_CONVERGE_CMD: stub("converge", 0, 30),
        ...extraEnv,
      },
    });
    let out = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (out += d));
    const closed = new Promise<number | null>((r) => p.on("close", (c) => r(c)));
    return { p, closed, out: () => out };
  }
  const logHas = (s: string) => existsSync(log) && readFileSync(log, "utf8").includes(s);
  async function until(cond: () => boolean) {
    for (let i = 0; i < 150 && !cond(); i++) await new Promise((r) => setTimeout(r, 100));
  }

  it("SIGHUP (closed terminal) after the deploy rolls back", async () => {
    writeEvidence("production", NEW, goodEvidence("production"));
    const run = startDetached({});
    await until(() => logHas("converge"));
    process.kill(-run.p.pid!, "SIGHUP");
    const code = await run.closed;
    expect(code).not.toBe(0);
    expect(logHas("rollback-complete"), run.out()).toBe(true);
  }, 30_000);

  it("a SECOND interrupt during the rollback does not abort it", async () => {
    writeEvidence("production", NEW, goodEvidence("production"));
    const run = startDetached({ FAKE_ROLLBACK_SLEEP: "2" });
    await until(() => logHas("converge"));
    process.kill(-run.p.pid!, "SIGTERM");
    await until(() => logHas(`versions deploy ${PREV}@100%`));
    process.kill(-run.p.pid!, "SIGTERM"); // the impatient second Ctrl-C
    process.kill(-run.p.pid!, "SIGHUP");
    await run.closed;
    const log_ = readFileSync(log, "utf8");
    // Completed, and completed the FIRST time — not killed mid-deploy and re-run.
    expect(log_.split("\n").filter((l) => l.includes(`versions deploy ${PREV}@100%`)), run.out()).toHaveLength(1);
    expect(log_.split("\n").filter((l) => l === "rollback-complete")).toHaveLength(1);
  }, 30_000);

  it("NEW's record is deleted BEFORE the rollback deploy, so a failed rollback leaves no pass", () => {
    writeEvidence("production", NEW, goodEvidence("production"));
    const r = promote({ NEW, ENV: "production" }, { NOTME_PROMOTE_VERIFY_CMD: stub("verify", 1), FAKE_ROLLBACK_FAIL: "1" });
    expect(r.code).not.toBe(0);
    expect(r.calls).toContain(`versions deploy ${PREV}@100%`);
    expect(existsSync(join(evidence, "production", `${NEW}.json`))).toBe(false);
  });
});

describe("worker:canary — selectors from the command line only (review M6, re-review N5)", () => {
  function canary(vars: Record<string, string>, exported: Record<string, string> = {}) {
    const args = ["-d", ROOT, "worker:canary", ...Object.entries(vars).map(([k, v]) => `${k}=${v}`)];
    const clean = cleanEnv();
    for (const k of ["OLD", "PCT"]) delete clean[k];
    const r = spawnSync("task", args, {
      env: { ...clean, PATH: `${join(dir, "bin")}:${process.env.PATH}`, FAKE_LOG: log, FAKE_PREV: PREV, ...exported },
      encoding: "utf8",
      timeout: 60_000,
    });
    const calls = existsSync(log) ? readFileSync(log, "utf8") : "";
    return { code: r.status, out: `${r.stdout}\n${r.stderr}`, split: calls.includes("versions deploy") };
  }
  const typed = { NEW, OLD: PREV, ENV: "production" };

  it("all typed: the split is deployed", () => {
    const r = canary(typed);
    expect(r.code, r.out).toBe(0);
    expect(r.split).toBe(true);
  });

  for (const k of ["ENV", "NEW", "OLD", "PCT"] as const) {
    it(`an exported ${k} standing in for a typed one is refused`, () => {
      const vars: Record<string, string> = { ...typed };
      const exported: Record<string, string> = { PCT: "50" };
      if (k !== "PCT") {
        exported[k] = vars[k];
        delete vars[k];
        delete exported.PCT;
      }
      const r = canary(vars, exported);
      expect(r.code).not.toBe(0);
      expect(r.split).toBe(false);
      expect(r.out).toMatch(new RegExp(`${k} is exported in your shell`));
    });
  }
});
