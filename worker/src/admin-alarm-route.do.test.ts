/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * admin-alarm-route.do.test.ts — /admin/alarm-health must be reachable by an
 * admin and by nobody else (notme-77a024).
 *
 * WHY THE ROUTE EXISTS. `resetAlarmHealth()` is the documented recovery for a
 * circuit-broken bundle-refresh alarm, and it was an RPC method with NO ROUTE
 * — invocable from nowhere. Production ran 130 days with a dead alarm serving
 * a bundle every conformant consumer rejected, and the fix was unreachable.
 *
 * WHY THE GATE IS THE PART UNDER TEST. An admin route that does not actually
 * gate is worse than no route: it hands an unauthenticated caller the ability
 * to re-arm a timer on the Durable Object holding the CA key, and it leaks
 * operational state (uptime, failure counts) that says when the authority is
 * unhealthy — which is exactly when an attacker would want to know.
 *
 * Each rejection is asserted with its OWN status, because they mean different
 * things to an operator debugging at 3am: 401 no session, 401 bad session,
 * 403 authenticated but unprivileged, 405 right path wrong verb.
 */
import worker from "../worker";
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

// Same local-origin idiom as unmatched-path.do.test.ts: the DO pool config is
// hermetic (no wrangler.toml), so the worker is invoked directly rather than
// through SELF, and the authority host is supplied via env.
const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };
const HEALTH = `${ORIGIN}/admin/alarm-health`;
const RESET = `${HEALTH}/reset`;

const call = (url: string, init: RequestInit = {}) =>
  worker.fetch(new Request(url, init), { ...env, ...LOCAL_ENV } as never, {
    waitUntil() {},
    passThroughOnException() {},
  } as never);

describe("/admin/alarm-health gating (notme-77a024)", () => {
  it("refuses an unauthenticated read", async () => {
    const res = await call(HEALTH);
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: "sign in first" });
  });

  it("refuses an unauthenticated RESET — the state-changing one", async () => {
    // The dangerous verb. Re-arming a timer on the DO holding the CA key must
    // never be reachable without a session.
    const res = await call(RESET, { method: "POST" });
    expect(res.status).toBe(401);
  });

  it("refuses a forged session cookie", async () => {
    // The cookie is HMAC-signed; an attacker-chosen value must not pass.
    const res = await call(HEALTH, {
      headers: { cookie: "notme_session=not-a-real-signed-cookie" },
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: "invalid session" });
  });

  it("rejects the wrong verb on each path, distinctly from auth failures", async () => {
    // 405 rather than 401 would leak that the path exists to an
    // unauthenticated caller — so the auth check must come FIRST for a
    // wrong-verb request too. Asserting 401 here pins that ordering.
    expect((await call(HEALTH, { method: "POST" })).status).toBe(401);
    expect((await call(RESET, { method: "GET" })).status).toBe(401);
  });

  it("does not leak alarm state in any rejection body", async () => {
    // A 401 that included failure counts would defeat the gate's purpose:
    // knowing the authority is failing is the operational fact being guarded.
    for (const [url, init] of [
      [HEALTH, {}],
      [RESET, { method: "POST" }],
      [HEALTH, { headers: { cookie: "notme_session=forged" } }],
    ] as const) {
      const body = await (await call(url, init)).text();
      for (const leak of ["failureCount", "totalFires", "lastFireAt", "driftRatio"]) {
        expect(body, `${url} leaked ${leak}`).not.toContain(leak);
      }
    }
  });
});
