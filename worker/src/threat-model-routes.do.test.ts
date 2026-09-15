/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * threat-model-routes.do.test.ts — the routing rows of THREAT_MODEL.md §8,
 * exercised against the REAL fetch handler (notme-8da0a3).
 *
 * REPLACES src/__tests__/routes.test.ts, which asserted nothing. Every one
 * of its eight tests compared literals it had just written — `expect(
 * path.startsWith("/."))`, `expect(blockedPaths).toContain(path)`,
 * `expect("identity authority").not.toBe("agent identity")`, and two bare
 * `expect(true).toBe(true)`. The real fetch was commented out. Its header
 * said "These tests should FAIL until routes are wired into worker.ts" —
 * the routes were wired long ago and the tests never failed, because they
 * never touched them.
 *
 * THREAT_MODEL links rows to test NAMES, so the describe blocks below keep
 * the names `routing.blocked-paths` and `routing.subdomain.isolation` and
 * the mapping stays true — this time of something.
 *
 * These live in the workers pool, not the plain suite, because driving the
 * real handler means importing worker.ts, which imports cloudflare:workers.
 * That import constraint is why the originals were written as literals in
 * the first place; the answer is to move the test, not to fake the subject.
 *
 * EVERY case runs with production-shaped URLs. A localhost SITE_URL sets
 * `isLocal` (worker.ts:1727), and isLocal takes the authority branch for
 * every host — whose catch-all is also a 404. Blocked-path cases run there
 * would pass with the dotfile rule and the blockedPaths Set both deleted,
 * and the subdomain cases could not tell the two hosts apart at all. The
 * only configuration in which these rows mean anything is the hosted one.
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../worker";

const HOSTED = {
  SITE_URL: "https://notme.bot",
  SIGNET_AUTHORITY_URL: "https://auth.notme.bot",
};

/**
 * ASSETS is the static-asset binding; the workers pool has no real one.
 * The stub answers with the path it was ASKED for, which is precisely what
 * lets the subdomain cases below observe which document each host selected
 * rather than merely that two responses exist.
 */
const ASSETS = {
  fetch: (req: Request) =>
    new Response(`asset:${new URL(req.url).pathname}`, {
      status: 200,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    }),
};

function call(host: string, path: string, headers: Record<string, string> = {}) {
  return worker.fetch(
    new Request(`https://${host}${path}`, { headers: { host, ...headers } }),
    { ...env, ...HOSTED, ASSETS } as never,
  );
}
const site = (path: string, headers?: Record<string, string>) =>
  call("notme.bot", path, headers);
const auth = (path: string, headers?: Record<string, string>) =>
  call("auth.notme.bot", path, headers);

describe("routing.blocked-paths", () => {
  it("refuses dotfiles and repository internals", async () => {
    for (const path of ["/.env", "/.git/config", "/.wrangler/state", "/.gitignore"]) {
      const res = await site(path);
      expect(res.status, `${path} must not be served`).toBe(404);
      // A 404 that still carried the file would satisfy a status-only check.
      const body = await res.text();
      expect(body).not.toMatch(/BEGIN [A-Z ]*PRIVATE KEY|SECRET|password/i);
      // ...and it must be the guard answering, not the asset store handing
      // back a 404 page: the stub would have echoed `asset:<path>`.
      expect(body, `${path} reached the asset store`).not.toContain("asset:");
    }
  });

  it("refuses source and config files by exact path", async () => {
    for (const path of ["/worker.ts", "/wrangler.toml", "/Taskfile.yml", "/LICENSE"]) {
      const res = await site(path);
      expect(res.status, `${path} must not be served`).toBe(404);
      expect(await res.text()).not.toContain("asset:");
    }
  });

  it("refuses sourcemaps, which leak source without being listed", async () => {
    for (const path of ["/worker.js.map", "/assets/anything.map"]) {
      const res = await site(path);
      expect(res.status, `${path} must not be served`).toBe(404);
      expect(await res.text()).not.toContain("asset:");
    }
  });

  it("refuses a dotfile nested under a path, not just at the root", async () => {
    // worker.ts checks `includes("/.")` as well as `startsWith("/.")`; a
    // root-only check would miss traversal into a nested hidden directory.
    for (const path of ["/static/.env", "/a/b/.git/config"]) {
      const res = await site(path);
      expect(res.status, `${path} must not be served`).toBe(404);
      expect(await res.text()).not.toContain("asset:");
    }
  });

  it("STILL SERVES /.well-known/, the RFC 8615 exemption", async () => {
    // The dotfile rule must not swallow the one dotted prefix that is
    // supposed to be public. Without this, blocking looks correct and
    // discovery silently breaks. security.txt is served on the marketing
    // host; the authority descriptor on the authority host.
    const sec = await site("/.well-known/security.txt");
    expect(sec.status).toBe(200);
    expect(await sec.text()).toContain("Contact:");

    const desc = await auth("/.well-known/signet-authority.json");
    expect(desc.status).toBe(200);
    expect(await desc.text()).toContain("issuer");
  });
});

describe("routing.subdomain.isolation", () => {
  it("the authority host serves the authority surface", async () => {
    const res = await auth("/", { accept: "application/json" });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.name).toBe("Signet Authority");
    expect(body.authority_url).toBe("https://auth.notme.bot");
  });

  it("the marketing host does not serve the authority surface", async () => {
    // The row's actual claim. `/` on notme.bot must fall through to the
    // asset store, never to the authority landing.
    const res = await site("/", { accept: "application/json" });
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toBe("asset:/");
    expect(body).not.toContain("Signet Authority");
  });

  it("the two hosts do not serve the same document", async () => {
    // The original compared two string LITERALS, which is true of any two
    // different strings. This asks the handler, the only thing that can
    // actually be wrong.
    const authBody = await (await auth("/")).text();
    const siteBody = await (await site("/")).text();
    expect(authBody).toBe("asset:/_auth");
    expect(siteBody).toBe("asset:/");
    expect(authBody).not.toBe(siteBody);
  });

  it("the authority-only endpoints are not reachable on the marketing host", async () => {
    // /token and /cert exist only behind the authority branch. On notme.bot
    // they must not answer; a host check that fell open would serve them.
    for (const path of ["/token", "/cert/gha"]) {
      const res = await site(path, { accept: "application/json" });
      expect(res.status, `${path} must not be an authority endpoint here`).toBe(200);
      expect(await res.text()).toBe(`asset:${path}`);
    }
  });

  it("a stray host is redirected to the canonical site, not served content", async () => {
    // workers.dev and any other host must not answer as either surface —
    // that is the confusion this row names.
    const res = await call("notme-bot.workers.dev", "/");
    expect(res.status).toBe(301);
    expect(res.headers.get("location")).toBe("https://notme.bot/");
  });
});
