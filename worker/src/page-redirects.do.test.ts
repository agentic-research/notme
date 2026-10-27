/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * page-redirects.do.test.ts — the renamed-page redirects, which had NO test.
 *
 * `/stack`, `/agent-identity` and `/favicon.ico` have 301'd for months with
 * nothing asserting it, so a refactor that dropped one would have shipped
 * silently and only shown up as a 404 in someone's referrer log. They are
 * pinned here alongside the new `/why`.
 *
 * PRODUCTION-SHAPED URLS, for the reason threat-model-routes.do.test.ts
 * documents at length: a localhost SITE_URL sets `isLocal`, which routes
 * every host down the authority branch whose catch-all is also a 404 — so a
 * redirect test run that way can pass with the redirect deleted.
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../worker";

const HOSTED = {
  SITE_URL: "https://notme.bot",
  SIGNET_AUTHORITY_URL: "https://auth.notme.bot",
};
const ASSETS = {
  fetch: (req: Request) =>
    new Response(`asset:${new URL(req.url).pathname}`, {
      status: 200,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    }),
};
const site = (path: string) =>
  worker.fetch(
    new Request(`https://notme.bot${path}`, { headers: { host: "notme.bot" } }),
    { ...env, ...HOSTED, ASSETS } as never,
  );

describe("renamed pages keep redirecting", () => {
  it.each([
    ["/stack", "https://notme.bot/"],
    ["/agent-identity", "https://notme.bot/research"],
    ["/favicon.ico", "https://notme.bot/favicon.svg"],
  ])("%s → %s, permanently", async (from, to) => {
    const res = await site(from);
    expect(res.status).toBe(301);
    expect(res.headers.get("Location")).toBe(to);
  });
});

// ── /why moved to the blog ───────────────────────────────────────────────────
//
// WHY THIS LIVES IN THIS REPO AND NOT IN notme.bot. Both repos declare a
// worker named `notme-bot` on the same two routes, so they are two sources
// for ONE deployment and the last deploy wins. Production's nav.js matches
// THIS repo's, so this repo is what is live — and it has no why.html, which
// is the whole reason /why 404s. A redirect added to the notme.bot repo
// would do nothing until that repo deployed, and deploying it would revert
// this repo's site.
//
// 302, NOT 301, AND DELIBERATELY SO. The post is not on q-q.dev yet (its
// sitemap lists 21 posts and this is not one of them), so the destination is
// the blog ROOT for now and will become the post's own URL. Every other
// redirect in this file is 301 with `max-age=31536000, immutable` — a year —
// which is right for a rename that is settled and wrong for a target still
// moving: a browser that cached an immutable 301 to the root would ignore
// the eventual post URL for a year. It flips to 301 when the post lands.
describe("/why points at the blog", () => {
  it("redirects to q-q.dev", async () => {
    const res = await site("/why");
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("https://q-q.dev/");
  });

  it("is temporary and short-cached, so the target can still move", async () => {
    const res = await site("/why");
    const cc = res.headers.get("Cache-Control") ?? "";
    expect(cc).not.toContain("immutable");
    // Minutes, not a year. The exact number is not the point; being orders
    // of magnitude below the settled redirects above is.
    const maxAge = Number(/max-age=(\d+)/.exec(cc)?.[1] ?? "-1");
    expect(maxAge).toBeGreaterThanOrEqual(0);
    expect(maxAge).toBeLessThanOrEqual(3600);
  });

  it("does not serve the page from assets — the content is not in this repo", async () => {
    // Guards the failure that produced the 404 in the first place: if a
    // why.html were ever added here, this redirect must still win, or the
    // essay would be served from the PUBLIC repo.
    const res = await site("/why");
    expect(res.status).not.toBe(200);
    expect(await res.text()).not.toContain("asset:");
  });
});
