/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * invite-page.do.test.ts — GET /invites must reach an admin and nobody else
 * (notme-4838ae).
 *
 * The page exists because POST /invites was API-only, so granting anyone
 * authority meant pasting a fetch() into devtools — which means in practice
 * nobody did, and an authority with one admin credential is one lost laptop
 * from ungovernable.
 *
 * The GATE is what is tested. An ungated admin page is worse than no page: it
 * would tell an unauthenticated caller that this authority has an invite
 * surface, and the form itself names the scope vocabulary.
 */
import worker from "../worker";
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

const ORIGIN = "http://localhost:8788";
const LOCAL = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };
const call = (path: string, init: RequestInit = {}) =>
  (worker.fetch as (r: Request, e: unknown) => Promise<Response>)(
    new Request(`${ORIGIN}${path}`, init),
    { ...env, ...LOCAL },
  );

describe("GET /invites gating (notme-4838ae)", () => {
  it("refuses an unauthenticated request", async () => {
    const res = await call("/invites");
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: "sign in first" });
  });

  it("refuses a forged session", async () => {
    const res = await call("/invites", {
      headers: { cookie: "notme_session=forged" },
    });
    expect(res.status).toBe(401);
  });

  it("gates the trailing-slash form too", async () => {
    // Route matching that misses /invites/ would serve the page ungated on a
    // URL a browser produces by itself.
    expect((await call("/invites/")).status).toBe(401);
  });

  it("leaks no scope vocabulary in the rejection", async () => {
    // The form names authorityManage and certMint. A 401 that carried them
    // would hand an anonymous caller the thing the gate exists to protect.
    const body = await (await call("/invites")).text();
    for (const s of ["authorityManage", "certMint", "bridgeCert"]) {
      expect(body, `rejection leaked ${s}`).not.toContain(s);
    }
  });

  it("still accepts POST separately — the gate is not a blanket block", async () => {
    // POST has its own auth check; this asserts the new GET branch did not
    // swallow the method it shares a path with.
    const res = await call("/invites", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(res.status).toBe(401); // unauthenticated, but reached POST's check
  });
});
