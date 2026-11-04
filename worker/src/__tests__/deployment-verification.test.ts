import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const read = (rel: string) => readFileSync(join(ROOT, rel), "utf8");
// worker:verify's checks moved out of the Taskfile into a script so they can
// run against a stub and a local Worker (notme-325916, notme-6ae724). The
// Taskfile must still delegate to it, or the contract below is about a file
// nothing runs.
const taskfile = read("Taskfile.yml");
const verifyScript = read("scripts/worker-verify.sh");

/** Every file under `dir` (relative to the repo root), recursively. */
function filesUnder(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(join(ROOT, dir))) {
    if (name === "node_modules") continue;
    const rel = join(dir, name);
    if (statSync(join(ROOT, rel)).isDirectory()) out.push(...filesUnder(rel));
    else out.push(rel);
  }
  return out;
}

describe("post-deploy verification contract", () => {
  it("worker:verify runs scripts/worker-verify.sh", () => {
    expect(taskfile).toMatch(/worker:verify:[\s\S]*?cmds:[\s\S]*?- >-\s*\n\s*bash scripts\/worker-verify\.sh/);
  });

  it("retries while a new Worker deployment converges", () => {
    expect(verifyScript).toContain('MAX_ATTEMPTS="${VERIFY_MAX_ATTEMPTS:-5}"');
    expect(verifyScript).toContain('RETRY_DELAY_SECONDS="${VERIFY_RETRY_DELAY_SECONDS:-2}"');
    expect(verifyScript).toContain('while [ "$attempt" -le "$MAX_ATTEMPTS" ]');
  });

  it("checks the DO-backed /.well-known documents", () => {
    expect(verifyScript).toMatch(/ca-bundle\.pem"[\s\S]+BEGIN CERTIFICATE/);
    expect(verifyScript).toMatch(/jwks\.json"[\s\S]+"crv":"Ed25519"/);
  });

  it("no operator tool claims a query bypasses the /.well-known cache", () => {
    // It used to work (notme-382e63). /.well-known/* keys ignore the query
    // now (notme-ed6114), so a nonce there is a bypass that is not one — and
    // refresh-trust-anchor.ts hid its nonce behind a variable
    // (`${BUNDLE}?r=…`), which a literal-path grep missed (review F2). So:
    // every operator surface, the literal form AND the appended form.
    const files = ["Taskfile.yml", ...filesUnder("scripts"), ...filesUnder(".github/workflows")];
    const literal = /\.well-known\/[\w.-]+\?/;
    const appended = /\$\{[^}]*(BUNDLE|JWKS|EPOCHS|WELL_KNOWN)[^}]*\}\?/i;
    const offenders = files.filter((f) => {
      const s = read(f);
      return literal.test(s) || appended.test(s);
    });
    expect(offenders).toEqual([]);
  });

  it("trust-anchor checks compare against the no-store CABundle, not only the edge-cached PEM", () => {
    // After rotate() the edge keeps serving the old root for up to its
    // max-age, and nothing purges it. A check that compares trust/ with that
    // copy can agree with it and sign a stale anchor (review F2). The KV
    // CABundle at /internal/ca-bundle is no-store and names the live key.
    expect(read("scripts/refresh-trust-anchor.ts")).toContain("/internal/ca-bundle");
    expect(read(".github/workflows/release.yml")).toContain("/internal/ca-bundle");
  });

  it("checks the unauthenticated passkey status contract", () => {
    expect(verifyScript).toMatch(
      /passkey-status[\s\S]+auth\/passkey\/status[\s\S]+401[\s\S]+unauthorized/,
    );
  });
});

describe("ship-prod checks PRODUCTION whatever the shell exports (review M6)", () => {
  it("with ENV/AUTH_BASE/SITE_BASE/VERSION/EXPECT exported for staging, converge + verify still target production", () => {
    // --dry renders every command without running it — nothing is deployed.
    const r = spawnSync("task", ["-d", ROOT, "--dry", "ship-prod"], {
      env: {
        ...process.env,
        ENV: "staging",
        AUTH_BASE: "https://auth-staging.notme.bot",
        SITE_BASE: "https://staging.notme.bot",
        VERSION: "01d00000-0000-4000-8000-000000000000",
        EXPECT: "f".repeat(40),
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    const out = `${r.stdout}\n${r.stderr}`;
    const verify = out.split("\n").find((l) => l.includes("[worker:verify]")) ?? "";
    const converge = out.split("\n").find((l) => l.includes("[worker:await-convergence]")) ?? "";
    expect(verify, out).toContain("--env production --auth-base https://auth.notme.bot --site-base https://notme.bot --version '' --expect ''");
    expect(converge, out).toContain("--auth-base https://auth.notme.bot");
    expect(out).not.toContain("staging.notme.bot");
  });
});
