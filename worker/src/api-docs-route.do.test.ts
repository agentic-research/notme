/// <reference types="@cloudflare/vitest-plugin/types" />
/**
 * api-docs-route.do.test.ts — /api/docs renders the SERVING environment's
 * authority host, in production as well as staging (notme-131c8e).
 *
 * The asset is a template: it names the authority host only through a
 * placeholder. The route used to serve the asset untouched in production and
 * rewrite the literal "auth.notme.bot" everywhere else, so the page and
 * worker.ts were coupled through a domain string neither one showed. These
 * drive the real route with a stand-in ASSETS binding (this pool has none)
 * that serves a template the way the real asset now does.
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../worker";
import { AUTHORITY_HOST_TOKEN } from "./api-docs";

const TEMPLATE =
  `<title>API — ${AUTHORITY_HOST_TOKEN}</title>` +
  `<code>curl -X POST https://${AUTHORITY_HOST_TOKEN}/cert/gha</code>`;

const assets = {
  fetch: async () =>
    new Response(TEMPLATE, { headers: { "Content-Type": "text/html; charset=utf-8" } }),
};

let n = 0;
async function docsFor(authorityUrl: string, siteUrl: string): Promise<Response> {
  const host = new URL(authorityUrl).host;
  // A fresh query per request: the route cachePuts with max-age=3600, and a
  // cached render from an earlier case would answer for this one.
  return worker.fetch(
    new Request(`${authorityUrl}/api/docs?case=${n++}`, { headers: { host } }),
    { ...env, ASSETS: assets, SITE_URL: siteUrl, SIGNET_AUTHORITY_URL: authorityUrl } as any,
  );
}

describe("/api/docs fills the authority host from the environment", () => {
  it("production: the page names auth.notme.bot, and no placeholder survives", async () => {
    const res = await docsFor("https://auth.notme.bot", "https://notme.bot");
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).not.toContain(AUTHORITY_HOST_TOKEN);
    expect(body).toContain("<title>API — auth.notme.bot</title>");
    expect(body).toContain("https://auth.notme.bot/cert/gha");
  });

  it("staging: the page names the staging authority, never production's", async () => {
    const res = await docsFor("https://auth-staging.notme.bot", "https://staging.notme.bot");
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).not.toContain(AUTHORITY_HOST_TOKEN);
    expect(body).not.toContain("auth.notme.bot");
    expect(body).toContain("https://auth-staging.notme.bot/cert/gha");
    // The body was re-encoded; a stale length would truncate or hang it.
    expect(res.headers.get("Content-Length")).toBeNull();
  });

  it("a self-hosted authority under another domain gets its own host", async () => {
    const res = await docsFor("https://id.example.org", "https://example.org");
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("https://id.example.org/cert/gha");
  });
});

describe("the raw template is not served", () => {
  it("/_api-docs and /_api-docs.html are 404, never the unfilled placeholder", async () => {
    for (const path of ["/_api-docs", "/_api-docs.html"]) {
      for (const origin of ["https://notme.bot", "https://auth.notme.bot"]) {
        const res = await worker.fetch(
          new Request(`${origin}${path}?case=${n++}`, { headers: { host: new URL(origin).host } }),
          { ...env, ASSETS: assets, SITE_URL: "https://notme.bot", SIGNET_AUTHORITY_URL: "https://auth.notme.bot" } as any,
        );
        expect(res.status, `${origin}${path}`).toBe(404);
        expect(await res.text()).not.toContain(AUTHORITY_HOST_TOKEN);
      }
    }
  });
});
