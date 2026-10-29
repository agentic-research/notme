/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * login-redirect.do.test.ts — "sign in first" sends you somewhere that exists
 * (notme-486e8a).
 *
 * Measured in production 2026-10-28: /enrol AND /authorize, with no session,
 * redirected to `https://notme.bot/login?...` — a 404. Every login redirect
 * was built from SITE_URL (the marketing site, notme.bot), but /login, the
 * passkey ceremony and the notme_session cookie all live on the AUTHORITY
 * host (auth.notme.bot). So the first-time user of rig's dashboard sign-in,
 * of rig's admin setup and of machine enrolment hit a dead end.
 *
 * Every other test runs with SITE_URL === the authority origin, which is
 * exactly the configuration that cannot see this. These separate them.
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../worker";

// Production-shaped hosts. localhost is special-cased by the router, which
// would hide exactly the split this file exists for.
const AUTH = "https://auth.example";
// The production shape: the site and the authority are different hosts.
const SPLIT_ENV = { SITE_URL: "https://site.example", SIGNET_AUTHORITY_URL: AUTH };

const get = (path: string) =>
  // The router reads the Host HEADER (as staging-impersonation.do.test.ts
  // does), so it is set explicitly.
  worker.fetch(
    new Request(`${AUTH}${path}`, { redirect: "manual", headers: { host: new URL(AUTH).host } }),
    { ...env, ...SPLIT_ENV },
  );

describe("login redirects stay on the authority, where /login and the session live", () => {
  it("/authorize without a session", async () => {
    const res = await get(
      `/authorize?redirect_uri=${encodeURIComponent("https://rosary.bot/cb")}&state=s&audience=${encodeURIComponent("https://rosary.bot")}`,
    );
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("location")!);
    expect(loc.origin).toBe(AUTH);
    expect(loc.pathname).toBe("/login");
    expect(loc.searchParams.get("return_to")).toMatch(/^\/authorize\?/);
  });

  it("/enroll without a session", async () => {
    const res = await get("/enroll?code=BCDF-GHJK");
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("location")!);
    expect(loc.origin).toBe(AUTH);
    expect(loc.pathname).toBe("/login");
    expect(loc.searchParams.get("return_to")).toBe("/enroll?code=BCDF-GHJK");
  });

  // "/login exists" is checked live (auth.notme.bot/login → 200), not here:
  // this pool has no ASSETS binding, so no static page can be served in it.

  it("/enrol (British spelling) still works, as an alias of /enroll", async () => {
    const res = await get("/enrol?code=BCDF-GHJK");
    expect(res.status).toBe(302);
    expect(new URL(res.headers.get("location")!).origin).toBe(AUTH);
  });
});
