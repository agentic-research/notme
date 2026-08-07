/**
 * unmatched-path.do.test.ts — an unmatched path under the authority host must
 * 404, not throw (notme-cb0354).
 *
 * Production binds VPC_AUTH, so an unmatched auth path falls through to
 * `env.VPC_AUTH.fetch(...)`. When that rejects, the rejection is unhandled and
 * Cloudflare surfaces error 1101 — reproduced live 2026-08-05, where EVERY
 * unmatched path under auth.notme.bot returned 500/1101 while known routes
 * were fine.
 *
 * Staging cannot catch this: with no VPC_AUTH binding it takes the explicit
 * 503 fallthrough instead. The two environments diverge exactly at this
 * branch, which is why every staging check passes while production is broken
 * here. These tests inject a failing VPC_AUTH so the production shape is
 * exercised without a production deploy.
 *
 * A constant-shape 404 is also the anti-oracle posture this authority wants:
 * a 500 that only appears for unroutable paths distinguishes them from routed
 * ones just as loudly as a 404 would, while additionally making a genuine
 * upstream failure indistinguishable from a typo.
 */
import worker from "../worker";
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };

/** A VPC binding whose fetch rejects, as production's does for unrouted paths. */
const FAILING_VPC = {
  fetch: () => Promise.reject(new Error("upstream unreachable")),
};

function get(path: string, extra: Record<string, unknown> = {}) {
  return worker.fetch(new Request(`${ORIGIN}${path}`), {
    ...env,
    ...LOCAL_ENV,
    ...extra,
  });
}

describe("unmatched authority paths (notme-cb0354)", () => {
  it("404s when the VPC upstream rejects, rather than throwing 1101", async () => {
    const res = await get("/.well-known/definitely-not-a-route", {
      VPC_AUTH: FAILING_VPC,
    });
    expect(res.status).toBe(404);
  });

  it("404s for an unmatched non-well-known path too", async () => {
    const res = await get("/no/such/endpoint", { VPC_AUTH: FAILING_VPC });
    expect(res.status).toBe(404);
  });

  it("returns a CONSTANT shape, so it is not an existence oracle", async () => {
    const a = await get("/.well-known/aaaaaaaa", { VPC_AUTH: FAILING_VPC });
    const b = await get("/.well-known/bbbbbbbbbbbbbbbbbb", {
      VPC_AUTH: FAILING_VPC,
    });
    expect(a.status).toBe(b.status);
    expect(await a.text()).toBe(await b.text());
  });

  it("still serves known routes when the VPC upstream is failing", async () => {
    // The fix must not swallow real routes — jwks is handled before the
    // fallthrough and must be unaffected by an unhealthy upstream.
    const res = await get("/.well-known/jwks.json", { VPC_AUTH: FAILING_VPC });
    expect(res.status).toBe(200);
  });
});

describe("the fallthrough is identical WITHOUT a VPC binding (notme-cb0354)", () => {
  // Staging binds no VPC_AUTH and took a different fallthrough — a 503
  // "auth.notme.bot not yet configured". Fixing only the VPC branch left the
  // two environments answering unmatched paths differently, which broke the
  // verify gate the moment it started asserting the production shape.
  //
  // They should not differ. From the caller's side an unmatched path simply
  // does not resolve; whether the operator has configured a tunnel is not
  // their business, and saying so tells an unauthenticated stranger about
  // deployment state. Same constant-404 argument as the VPC branch.
  it("404s with no VPC_AUTH bound, exactly as it does with a failing one", async () => {
    const withoutVpc = await get("/.well-known/not-a-route");
    expect(withoutVpc.status).toBe(404);

    const withFailingVpc = await get("/.well-known/not-a-route", {
      VPC_AUTH: FAILING_VPC,
    });
    expect(withFailingVpc.status).toBe(404);
    // Byte-identical across the two deployment shapes, so the response does
    // not disclose which one is serving.
    expect(await withoutVpc.text()).toBe(await withFailingVpc.text());
  });

  it("does not disclose configuration state to unauthenticated callers", async () => {
    const res = await get("/whatever");
    expect(await res.text()).not.toMatch(/configur/i);
  });
});
