/**
 * worker-verify-pinning.test.ts — a soak verify must measure the NEW version,
 * not whichever version the split happened to route to (notme-325916).
 *
 * THE DEFECT. During a 10/90 canary, `task worker:verify` sent ordinary
 * requests, so each check was answered by whichever version Cloudflare's
 * percentage routing picked. A real production canary served 85/85 samples
 * from the OLD version — a broken NEW version passed the soak because the
 * soak never reached it.
 *
 * THE FIX UNDER TEST. `worker:verify VERSION=<id>` sends Cloudflare's
 * version-override header on every probe:
 *
 *     Cloudflare-Workers-Version-Overrides: <worker-name>="<version-id>"
 *
 * (https://developers.cloudflare.com/workers/configuration/versions-and-deployments/version-overrides/).
 * Cloudflare documents that the override is applied only when the version is
 * in the current deployment and is otherwise IGNORED SILENTLY — the request
 * falls back to percentage routing. That fallback is exactly how ADR-018's
 * first pinned probe measured the old version under the new one's label. So
 * the header alone is a request, not a proof: every check is also bracketed by
 * a pinned `/.well-known/version` probe that must report the expected build.
 *
 * THE STUB models Cloudflare's routing as documented: a deployment of up to
 * two versions with percentages; an override naming this Worker and a version
 * IN the deployment is honoured; anything else falls back to the split. The
 * NEW version is broken (`/token` 500s, the PR #3 shape: fine everywhere
 * except one route). Nothing here touches a Cloudflare account.
 */
import { spawn, execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

// Each case runs the real Taskfile + curl against the stub: seconds, not ms.
vi.setConfig({ testTimeout: 30_000 });

const ROOT = fileURLToPath(new URL("../../../", import.meta.url));

const OLD = { id: "01d00000-0000-4000-8000-000000000000", commit: "1".repeat(40) };
const NEW = { id: "4e700000-0000-4000-8000-000000000000", commit: "2".repeat(40) };

interface Version {
  id: string;
  commit: string;
  brokenToken: boolean;
}

/** Mutable per test: which versions are deployed, at what split, and who is broken. */
let deployment: { version: Version; pct: number }[] = [];
/** How unpinned requests are routed. Default models the measured 85/85: always OLD. */
let sample: () => number = () => 0.99;
let workerName = "notme-bot";
let served: string[] = [];
/** Whether Cloudflare honours a valid override (false models the silent-ignore failure). */
let honour = true;
/** Whether the Worker has the version-metadata binding (serves version_id). */
let versionMeta = true;
/** What \`wrangler deployments status\` reports; defaults to the routing table. */
let listed: { version_id: string; percentage: number }[] | null = null;
let wranglerStub = "";
let deployFile = "";

let server: Server;
let base = "";
let caPem = "";

function route(req: IncomingMessage): Version {
  const header = String(req.headers["cloudflare-workers-version-overrides"] ?? "");
  const m = header.match(/^\s*([a-z0-9-]+)\s*=\s*"([^"]+)"\s*$/);
  if (m && m[1] === workerName) {
    const pinned = deployment.find((d) => d.version.id === m[2]);
    if (pinned && honour) return pinned.version; // honoured: version is in the deployment
  }
  // Ignored (not in deployment / wrong name / malformed) → percentage routing.
  let r = sample() * 100;
  for (const d of deployment) {
    if (r < d.pct) return d.version;
    r -= d.pct;
  }
  return deployment[deployment.length - 1].version;
}

function handle(req: IncomingMessage, res: ServerResponse) {
  const v = route(req);
  served.push(v.id);
  const path = (req.url ?? "/").split("?")[0];
  const send = (status: number, body: string, type = "text/html") => {
    res.writeHead(status, { "content-type": type });
    res.end(body);
  };
  const json = (status: number, body: unknown) => send(status, JSON.stringify(body), "application/json");
  const host = req.headers.host ?? "";
  // One host serves both "auth" and "site" here; the paths do not collide.
  switch (path) {
    case "/":
      return send(200, "notme identity authority");
    case "/login":
      return send(200, "sign in with a passkey");
    case "/.well-known/signet-authority.json":
      return json(200, { issuer: base });
    case "/.well-known/ca-bundle.pem":
      return send(200, caPem, "application/x-pem-file");
    case "/.well-known/jwks.json":
      return json(200, { keys: [{ kty: "OKP", crv: "Ed25519", x: "AA" }] });
    case "/.well-known/version":
      return json(200, { commit: v.commit, stamped: true, version_id: versionMeta ? v.id : "unknown" });
    case "/api/docs":
      return send(200, `docs for http://${host}`);
    case "/auth/passkey/status":
      return json(401, { error: "unauthorized" });
    case "/authorize":
      return json(400, { error: "redirect_uri required" });
    case "/token":
      return v.brokenToken ? send(500, "error code: 1101") : json(400, { error: "dpop_proof_required" });
    case "/apas":
      return send(200, "APAS 0.2.1-draft");
    case "/provenance/dispatch/v1":
      return json(200, { properties: { workItemRef: {} } });
    default:
      return json(404, { error: "not_found" });
  }
}

interface Run {
  code: number | null;
  out: string;
}

/**
 * Run the REAL `task worker:verify` against the stub. Async on purpose: the
 * stub lives in this process, so a synchronous spawn would block the event
 * loop that has to answer the requests.
 */
function verify(vars: Record<string, string>, evidenceDir: string): Promise<Run> {
  const args = [
    "-d",
    ROOT,
    "worker:verify",
    `AUTH_BASE=${base}`,
    `SITE_BASE=${base}`,
    ...Object.entries(vars).map(([k, v]) => `${k}=${v}`),
  ];
  writeFileSync(
    deployFile,
    JSON.stringify({ versions: listed ?? deployment.map((d) => ({ version_id: d.version.id, percentage: d.pct })) }),
  );
  return new Promise((resolve) => {
    const p = spawn("task", args, {
      env: {
        ...process.env,
        VERIFY_MAX_ATTEMPTS: "1",
        VERIFY_RETRY_DELAY_SECONDS: "0",
        NOTME_EVIDENCE_DIR: evidenceDir,
        NOTME_WRANGLER_CMD: wranglerStub,
        STUB_DEPLOYMENT_FILE: deployFile,
      },
    });
    let out = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (out += d));
    p.on("close", (code) => resolve({ code, out }));
  });
}

const old = (): Version => ({ ...OLD, brokenToken: false });
const brokenNew = (): Version => ({ ...NEW, brokenToken: true });
const healthyNew = (): Version => ({ ...NEW, brokenToken: false });

let evidence: string;

beforeAll(async () => {
  const dir = mkdtempSync(join(tmpdir(), "verify-pin-ca-"));
  const key = join(dir, "k.pem");
  const crt = join(dir, "c.pem");
  // A root with pathlen:1, so the root-pathlen check passes on its merits.
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
    "-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=stub root",
    "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1",
  ], { stdio: "ignore" });
  caPem = readFileSync(crt, "utf8");
  // A fake wrangler: \`deployments status --json\` prints the deployment the
  // test declared. Nothing reaches Cloudflare.
  wranglerStub = join(dir, "wrangler");
  deployFile = join(dir, "deployment.json");
  writeFileSync(wranglerStub, '#!/usr/bin/env bash\ncase "$*" in *"deployments status"*) cat "$STUB_DEPLOYMENT_FILE" ;; *) exit 9 ;; esac\n');
  chmodSync(wranglerStub, 0o755);
  server = createServer(handle);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => new Promise<void>((r) => server.close(() => r())));

beforeEach(() => {
  served = [];
  honour = true;
  versionMeta = true;
  listed = null;
  sample = () => 0.99;
  workerName = "notme-bot";
  evidence = mkdtempSync(join(tmpdir(), "verify-pin-evidence-"));
});

describe("canary soak verify targets the new version (notme-325916)", () => {
  it("baseline: a healthy deployment passes, unpinned", async () => {
    deployment = [{ version: old(), pct: 100 }];
    const r = await verify({}, evidence);
    expect(r.code, r.out).toBe(0);
  });

  it("THE DEFECT, kept as a record: an unpinned soak passes a broken canary when routing lands on OLD", async () => {
    // 10/90 split, every sample routed to OLD — the measured production case.
    deployment = [{ version: brokenNew(), pct: 10 }, { version: old(), pct: 90 }];
    const r = await verify({}, evidence);
    expect(r.code, r.out).toBe(0);
    expect(served).not.toContain(NEW.id);
    // ...and it is NOT evidence: nothing is recorded for a sampled run.
    expect(existsSync(join(evidence, "production", `${NEW.id}.json`))).toBe(false);
  });

  it("a pinned soak FAILS a broken canary, deterministically", async () => {
    deployment = [{ version: brokenNew(), pct: 10 }, { version: old(), pct: 90 }];
    const r = await verify({ VERSION: NEW.id, EXPECT: NEW.commit, ENV: "production" }, evidence);
    expect(r.code).not.toBe(0);
    expect(r.out).toMatch(/✗ token/);
    expect(served.every((id) => id === NEW.id)).toBe(true);
    expect(existsSync(join(evidence, "production", `${NEW.id}.json`))).toBe(false);
  });

  it("…under ANY routing of unpinned traffic, not just the all-OLD case", async () => {
    deployment = [{ version: brokenNew(), pct: 10 }, { version: old(), pct: 90 }];
    for (const s of [0, 0.05, 0.5, 0.95, 0.999]) {
      sample = () => s;
      const r = await verify({ VERSION: NEW.id, EXPECT: NEW.commit, ENV: "production" }, evidence);
      expect(r.code, `sample=${s}`).not.toBe(0);
    }
  }, 60_000);

  it("a pinned soak of a healthy canary passes and records version-keyed evidence", async () => {
    deployment = [{ version: healthyNew(), pct: 10 }, { version: old(), pct: 90 }];
    const r = await verify({ VERSION: NEW.id, EXPECT: NEW.commit, ENV: "production" }, evidence);
    expect(r.code, r.out).toBe(0);
    expect(served.every((id) => id === NEW.id)).toBe(true);
    const rec = JSON.parse(readFileSync(join(evidence, "production", `${NEW.id}.json`), "utf8"));
    expect(rec).toMatchObject({
      schema: "notme.release-evidence/v1",
      result: "pass",
      pinned: true,
      version: NEW.id,
      env: "production",
      commit: NEW.commit,
      auth_base: base,
    });
  });

  it("FAILS CLOSED when Cloudflare ignores the override (version not in the deployment)", async () => {
    // The documented silent fallback: NEW uploaded but not deployed. Both the
    // answering version and the checks are healthy, so without the identity
    // bracket this would pass — as evidence about the OLD version.
    deployment = [{ version: old(), pct: 100 }];
    const r = await verify({ VERSION: NEW.id, EXPECT: NEW.commit, ENV: "production" }, evidence);
    expect(r.code).not.toBe(0);
    expect(r.out).toMatch(/not serving/i);
    expect(existsSync(join(evidence, "production", `${NEW.id}.json`))).toBe(false);
  });

  it("…and the identity bracket fails it too, if Cloudflare's listing and its routing disagree", async () => {
    // Listed as deployed (e.g. propagation lag), but the override did not apply.
    honour = false;
    versionMeta = false;
    deployment = [{ version: healthyNew(), pct: 10 }, { version: old(), pct: 90 }];
    const r = await verify({ VERSION: NEW.id, EXPECT: NEW.commit, ENV: "production" }, evidence);
    expect(r.code).not.toBe(0);
    expect(r.out).toMatch(/not honoured.*answered by build/i);
    expect(existsSync(join(evidence, "production", `${NEW.id}.json`))).toBe(false);
  });

  it("names the staging Worker in the header for ENV=staging", async () => {
    workerName = "notme-bot-staging";
    deployment = [{ version: healthyNew(), pct: 10 }, { version: old(), pct: 90 }];
    const r = await verify({ VERSION: NEW.id, EXPECT: NEW.commit, ENV: "staging" }, evidence);
    expect(r.code, r.out).toBe(0);
    expect(existsSync(join(evidence, "staging", `${NEW.id}.json`))).toBe(true);
  });

  it("refuses to pin without an explicit ENV — the evidence key and header name depend on it", async () => {
    deployment = [{ version: healthyNew(), pct: 10 }, { version: old(), pct: 90 }];
    const r = await verify({ VERSION: NEW.id, EXPECT: NEW.commit }, evidence);
    expect(r.code).not.toBe(0);
  });
});

describe("pinned soak — security review fixes (M4, M5)", () => {
  /** Two versions built from the SAME commit: a config-only re-upload. */
  const sameCommitNew = (): Version => ({ id: NEW.id, commit: OLD.commit, brokenToken: false });
  const pinnedArgs = { VERSION: NEW.id, EXPECT: OLD.commit, ENV: "production" };
  const record = () => join(evidence, "production", `${NEW.id}.json`);

  it("M5: a version not in the deployment never earns evidence, even when the commits match", async () => {
    // The override is ignored (NEW is not deployed), OLD answers every probe,
    // and OLD reports the expected commit. No version metadata to tell them apart.
    versionMeta = false;
    deployment = [{ version: old(), pct: 100 }];
    const r = await verify(pinnedArgs, evidence);
    expect(r.code).not.toBe(0);
    expect(r.out).toMatch(/not serving|not in the current deployment/i);
    expect(existsSync(record())).toBe(false);
  });

  it("M5: with version metadata, an ignored pin fails on the version id even when Cloudflare lists NEW", async () => {
    honour = false; // listed in the deployment, but the override did not apply
    deployment = [{ version: sameCommitNew(), pct: 10 }, { version: old(), pct: 90 }];
    const r = await verify(pinnedArgs, evidence);
    expect(r.code).not.toBe(0);
    expect(r.out).toMatch(/answered by version/i);
    expect(existsSync(record())).toBe(false);
  });

  it("M5: a listed, honoured, same-commit version passes and records the version id it saw", async () => {
    deployment = [{ version: sameCommitNew(), pct: 10 }, { version: old(), pct: 90 }];
    const r = await verify(pinnedArgs, evidence);
    expect(r.code, r.out).toBe(0);
    expect(JSON.parse(readFileSync(record(), "utf8"))).toMatchObject({ version: NEW.id, version_id_checked: true });
  });

  it("M4: a failed pinned run removes an earlier pass for that version", async () => {
    mkdirSync(join(evidence, "production"), { recursive: true });
    writeFileSync(record(), JSON.stringify({ schema: "notme.release-evidence/v1", result: "pass", pinned: true }));
    deployment = [{ version: brokenNew(), pct: 10 }, { version: old(), pct: 90 }];
    const r = await verify({ VERSION: NEW.id, EXPECT: NEW.commit, ENV: "production" }, evidence);
    expect(r.code).not.toBe(0);
    expect(existsSync(record())).toBe(false);
  });
});
