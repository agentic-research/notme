/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * admin-revoke-epoch-route.do.test.ts — the mass-revocation lever must be
 * reachable by an admin and by nobody else (notme-77a024).
 *
 * WHY THE ROUTE EXISTS. `revokeEpoch()` advances the revocation generation
 * and republishes the CA bundle synchronously; ADR-019 D7 makes it the ONLY
 * mass-revocation mechanism notme has, and the whole point of D7 was that
 * the previous one "could not be operated" because revoking cost the signing
 * key. It then shipped as a Durable Object RPC method with NO ROUTE and no
 * caller — invocable from nowhere.
 *
 * That is the SAME defect, filed under the SAME bead, that left
 * `resetAlarmHealth()` uninvocable while production served a bundle every
 * conformant consumer rejected for 130 days (see the comment above
 * `/admin/alarm-health` in worker.ts). A lever nothing can pull is not a
 * lever, and a changelog that claims mass revocation while the only entry
 * point is a test file is the kind of false claim this bead exists to stop.
 *
 * WHY THE GATE IS THE PART UNDER TEST. This route invalidates every
 * outstanding credential of the current generation. Reachable without a
 * session it is a denial-of-service primitive against the whole authority,
 * served by the Durable Object holding the CA key.
 *
 * Each rejection is asserted with its OWN status, because they mean
 * different things to an operator: 401 no session, 401 bad session, 403
 * authenticated but unprivileged.
 *
 * AND THE AUTHORIZED PATH IS EXERCISED, which is the point — epoch-lever
 * .do.test.ts already drives `revokeEpoch()` as a DO method, so a passing
 * suite proved the mechanism while saying nothing about whether an operator
 * could reach it. `createSessionCookie` plus a real `authorityManage` grant
 * closes that, the same way grant-revocation.do.test.ts does for
 * /admin/alarm-health.
 */
import worker from "../worker";
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { createSessionCookie } from "./auth/session";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };
const REVOKE = `${ORIGIN}/admin/revoke-epoch`;

const call = (url: string, init: RequestInit = {}) =>
  (worker.fetch as (r: Request, e: unknown) => Promise<Response>)(
    new Request(url, init),
    { ...env, ...LOCAL_ENV },
  );

describe("/admin/revoke-epoch gating (notme-77a024)", () => {
  it("is routed at all — not a 404", async () => {
    // The test that fails before the route exists. 404 here means the lever
    // ADR-019 D7 commits to has no entry point outside the test suite.
    const res = await call(REVOKE, { method: "POST" });
    expect(
      res.status,
      "POST /admin/revoke-epoch returned 404: revokeEpoch() is an RPC method " +
        "with no route, so notme's only mass-revocation lever cannot be pulled.",
    ).not.toBe(404);
  });

  it("refuses an unauthenticated POST", async () => {
    const res = await call(REVOKE, { method: "POST" });
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: "sign in first" });
  });

  it("refuses a forged session cookie", async () => {
    const res = await call(REVOKE, {
      method: "POST",
      headers: { cookie: "notme_session=not-a-real-signed-cookie" },
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: "invalid session" });
  });

  it("answers 401, not 405, for a wrong verb from an anonymous caller", async () => {
    // AUTH BEFORE METHOD. A 405 would confirm to an unauthenticated caller
    // that this authority exposes a mass-revocation endpoint — a free hint
    // about what to attack, on the object holding the CA key.
    const res = await call(REVOKE, { method: "GET" });
    expect(res.status).toBe(401);
  });

  it("leaks no revocation state in any rejection body", async () => {
    // An epoch or seqno in a 401 body would tell an anonymous caller the
    // authority's current generation — which is what a replayed credential
    // needs to look current.
    for (const init of [
      { method: "POST" },
      { method: "GET" },
      { method: "POST", headers: { cookie: "notme_session=forged" } },
    ] as const) {
      const body = await (await call(REVOKE, init)).text();
      for (const leak of ["epoch", "seqno", "keyId", "prevKeyId"]) {
        expect(body, `${init.method} leaked ${leak}`).not.toContain(leak);
      }
    }
  });
});

describe("/admin/revoke-epoch actually pulls the lever (notme-77a024)", () => {
  const authority = (name = "default") =>
    env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(name));

  const sessionFor = async (pid: string, scopes: string[]) =>
    createSessionCookie(
      { principalId: pid, scopes, authMethod: "passkey" },
      await authority().getSessionSecret(),
    );

  it("refuses an authenticated caller WITHOUT authorityManage", async () => {
    // The gate that matters most: an ordinary signed-in user must not be able
    // to invalidate every credential this authority has issued.
    const pid = crypto.randomUUID();
    await authority().createPrincipalWithCapabilities(pid, ["bridgeCert"]);
    const cookie = await sessionFor(pid, ["bridgeCert"]);
    const res = await call(REVOKE, { method: "POST", headers: { cookie } });
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({
      error: "authorityManage scope required",
    });
  });

  it("refuses a cookie CLAIMING authorityManage with no backing grant", async () => {
    // The cookie is a cache of the grant, never the source.
    const pid = crypto.randomUUID();
    await authority().createPrincipalWithCapabilities(pid, ["bridgeCert"]);
    const cookie = await sessionFor(pid, ["bridgeCert", "authorityManage"]);
    expect((await call(REVOKE, { method: "POST", headers: { cookie } })).status).toBe(403);
  });

  it("advances the epoch for a real admin, and reports the propagation bound", async () => {
    const pid = crypto.randomUUID();
    await authority().createPrincipalWithCapabilities(pid, ["authorityManage"]);
    const cookie = await sessionFor(pid, ["authorityManage"]);

    // generateBundle() is the real accessor — there is no getCurrentEpoch().
    // An optional-call fallback here would have made the comparison below
    // vacuous, which is the failure mode this suite exists to avoid.
    const before = (await authority().generateBundle()).epoch;

    const res = await call(REVOKE, { method: "POST", headers: { cookie } });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      epoch: number;
      seqno: number;
      propagation: { boundMs: number };
    };

    // The lever moved something. Asserting a CHANGE rather than a literal,
    // because this DO is shared across this file's tests and the epoch is
    // whatever earlier cases left it at.
    expect(body.epoch).toBeGreaterThan(before);

    // Pulling it twice must move it again — an idempotent "revoke" would mean
    // a second incident could not be answered.
    const second = (await (
      await call(REVOKE, { method: "POST", headers: { cookie } })
    ).json()) as { epoch: number };
    expect(second.epoch).toBeGreaterThan(body.epoch);

    // The operator is told WHEN it takes effect. A lever with no stated
    // propagation bound invites the assumption that it is instant, and for
    // an offline verifier it never is (ADR-019 D7).
    expect(body.propagation.boundMs).toBe(5 * 60 * 1000);
  });

  it("a revoked authorityManage grant shuts the door on the NEXT request", async () => {
    const pid = crypto.randomUUID();
    await authority().createPrincipalWithCapabilities(pid, ["authorityManage"]);
    const cookie = await sessionFor(pid, ["authorityManage"]);

    expect((await call(REVOKE, { method: "POST", headers: { cookie } })).status).toBe(200);

    await authority().revokeCapability(pid, "authorityManage", "test");

    // Same cookie, same expiry.
    expect((await call(REVOKE, { method: "POST", headers: { cookie } })).status).toBe(403);
  });
});
