/// <reference types="@cloudflare/vitest-plugin/types" />
/**
 * session-cookie-amplification.do.test.ts — a junk `notme_session` cookie must
 * not buy a call on the SigningAuthority (notme-a34dad, overnight review C2).
 *
 * Every cookie-authenticated route used to call `authority.getSessionSecret()`
 * before it looked at the cookie, so ANY value in notme_session — "x" will do
 * — was a billed RPC on the one Durable Object that serialises issuance. Past
 * its soft limit (about 1k rps) that object returns overloaded errors, and
 * every mint, /token and .well-known miss fails for everyone.
 *
 * The HMAC check is now local: the secret is cached per isolate with a bounded
 * TTL. These tests count RPCs on the stub (the pre-do-limits.do.test.ts
 * method) rather than inferring them from a status code.
 */
import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import worker from "../worker";
import { encodeBase64url } from "@oslojs/encoding";
import { createSessionCookie } from "./auth/session";
import { __resetSessionSecretCacheForTests, couldBeSessionCookie } from "./auth/session-secret-cache";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };

/** The SIGNING_AUTHORITY namespace with every stub RPC recorded by name. */
function spiedAuthority() {
  const calls: string[] = [];
  const ns = env.SIGNING_AUTHORITY;
  const binding = {
    idFromName: (name: string) => ns.idFromName(name),
    get: (id: DurableObjectId) => {
      const stub = ns.get(id);
      return new Proxy(stub, {
        get(target, prop) {
          const value = Reflect.get(target, prop);
          if (typeof prop !== "string" || prop === "then" || typeof value !== "function") return value;
          return (...args: unknown[]) => {
            calls.push(prop);
            return (target as unknown as Record<string, (...a: unknown[]) => unknown>)[prop]!(...args);
          };
        },
      });
    },
  };
  return { calls, binding };
}

/** A stand-in for a rate-limit binding, which has no test constructor. */
function limiter(allow: (key: string) => boolean) {
  const keys: string[] = [];
  return {
    keys,
    binding: {
      limit: async ({ key }: { key: string }) => {
        keys.push(key);
        return { success: allow(key) };
      },
    },
  };
}

const call = (req: Request, extra: Record<string, unknown>) =>
  worker.fetch(req, { ...env, ...LOCAL_ENV, ...extra } as never);

// The encoding session.ts itself uses, padding included: a forgery the parser
// rejects would prove nothing about the HMAC step.
const b64u = encodeBase64url;

/**
 * A cookie with the right SHAPE — base64url JSON payload with a future exp,
 * a 32-byte signature — signed with a key the authority never had. The
 * strongest junk an attacker can send without the secret: it passes every
 * structural check and fails only the HMAC.
 */
function wellFormedForgery(): string {
  const payload = new TextEncoder().encode(
    JSON.stringify({
      principalId: "forged",
      scopes: ["authorityManage", "certMint", "bridgeCert"],
      authMethod: "passkey",
      exp: Math.floor(Date.now() / 1000) + 3600,
    }),
  );
  return `${b64u(payload)}.${b64u(crypto.getRandomValues(new Uint8Array(32)))}`;
}

const CHALLENGE = "a".repeat(43);
const json = (body: unknown) => JSON.stringify(body);

/**
 * Every route that verifies notme_session, with a request shaped to get PAST
 * its pre-cookie validation, so the cookie check is what it reaches. A route
 * that refused earlier would pass "no RPC" vacuously; the RED run is the
 * evidence each request did reach getSessionSecret.
 */
const ROUTES: Array<{ name: string; req: (cookie: string) => Request }> = [
  { name: "GET /me", req: (c) => new Request(`${ORIGIN}/me`, { headers: { cookie: c, accept: "application/json" } }) },
  { name: "GET /connections", req: (c) => new Request(`${ORIGIN}/connections`, { headers: { cookie: c } }) },
  {
    name: "POST /connections",
    req: (c) => new Request(`${ORIGIN}/connections`, { method: "POST", headers: { cookie: c }, body: "{}" }),
  },
  { name: "GET /admin/alarm-health", req: (c) => new Request(`${ORIGIN}/admin/alarm-health`, { headers: { cookie: c } }) },
  {
    name: "POST /admin/revoke-epoch",
    req: (c) => new Request(`${ORIGIN}/admin/revoke-epoch`, { method: "POST", headers: { cookie: c }, body: "{}" }),
  },
  { name: "GET /invites", req: (c) => new Request(`${ORIGIN}/invites`, { headers: { cookie: c } }) },
  {
    name: "POST /invites",
    req: (c) => new Request(`${ORIGIN}/invites`, { method: "POST", headers: { cookie: c }, body: "{}" }),
  },
  {
    name: "POST /principals/:id/revoke",
    req: (c) => new Request(`${ORIGIN}/principals/p1/revoke`, { method: "POST", headers: { cookie: c }, body: "{}" }),
  },
  { name: "GET /auth/passkey/status", req: (c) => new Request(`${ORIGIN}/auth/passkey/status`, { headers: { cookie: c } }) },
  {
    name: "POST /cert (session proof)",
    req: (c) =>
      new Request(`${ORIGIN}/cert`, {
        method: "POST",
        headers: { cookie: c, "content-type": "application/json" },
        body: json({ proof: { type: "session" } }),
      }),
  },
  { name: "POST /cert/nonce", req: (c) => new Request(`${ORIGIN}/cert/nonce`, { method: "POST", headers: { cookie: c } }) },
  {
    name: "POST /cert/passkey",
    req: (c) =>
      new Request(`${ORIGIN}/cert/passkey`, {
        method: "POST",
        headers: { cookie: c, "content-type": "application/json" },
        body: json({ nonce: "n", public_keys: { mtls: "m", signing: "s" }, proofs: { mtls: "m", signing: "s" } }),
      }),
  },
  { name: "GET /enroll", req: (c) => new Request(`${ORIGIN}/enroll?code=ABCD`, { headers: { cookie: c } }) },
  {
    name: "POST /cert/issuing-ca/device/approve",
    req: (c) =>
      new Request(`${ORIGIN}/cert/issuing-ca/device/approve`, { method: "POST", headers: { cookie: c }, body: "{}" }),
  },
  {
    name: "GET /cert/issuing-ca/enrollments",
    req: (c) => new Request(`${ORIGIN}/cert/issuing-ca/enrollments`, { headers: { cookie: c } }),
  },
  {
    name: "POST /cert/issuing-ca",
    req: (c) => new Request(`${ORIGIN}/cert/issuing-ca`, { method: "POST", headers: { cookie: c }, body: "{}" }),
  },
  {
    name: "GET /authorize",
    req: (c) =>
      new Request(`${ORIGIN}/authorize?redirect_uri=${encodeURIComponent("http://localhost:3000/cb")}&state=s`, {
        headers: { cookie: c },
      }),
  },
  {
    name: "POST /authorize/code",
    req: (c) =>
      new Request(`${ORIGIN}/authorize/code`, {
        method: "POST",
        headers: { cookie: c, "content-type": "application/json" },
        body: json({ audience: "https://rosary.bot", redirect_uri: "http://localhost:3000/cb", code_challenge: CHALLENGE }),
      }),
  },
  {
    name: "POST /authorize/token",
    req: (c) =>
      new Request(`${ORIGIN}/authorize/token`, {
        method: "POST",
        headers: { cookie: c, "content-type": "application/json" },
        body: json({ audience: "https://rosary.bot" }),
      }),
  },
  {
    name: "POST /token",
    req: (c) =>
      new Request(`${ORIGIN}/token`, {
        method: "POST",
        headers: { cookie: c, DPoP: "placeholder", "content-type": "application/json" },
        body: json({ audience: "https://notme.bot" }),
      }),
  },
];

async function validCookie(principalId: string, scopes: string[] = ["bridgeCert"]): Promise<string> {
  const stub = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
  const set = await createSessionCookie({ principalId, scopes, authMethod: "passkey" }, await stub.getSessionSecret());
  return set.split(";")[0]!;
}

/** Warm this isolate's secret cache the way production does: a request with a real cookie. */
async function warm(): Promise<void> {
  const res = await call(
    new Request(`${ORIGIN}/me`, { headers: { cookie: await validCookie("warm-up"), accept: "application/json" } }),
    {},
  );
  expect(res.status).toBe(200);
}

describe("session.cookie.junk-no-do — a junk notme_session cookie makes no SigningAuthority RPC (C2)", () => {
  beforeEach(() => __resetSessionSecretCacheForTests());

  it("the forgery is well-formed: only its HMAC is wrong", () => {
    expect(couldBeSessionCookie(wellFormedForgery())).toBe(true);
    expect(couldBeSessionCookie("x")).toBe(false);
  });

  for (const route of ROUTES) {
    it(`${route.name}: a malformed cookie ("x"), even on a cold isolate`, async () => {
      const spy = spiedAuthority();
      await call(route.req("notme_session=x"), { SIGNING_AUTHORITY: spy.binding });
      expect(spy.calls).toEqual([]);
    });

    it(`${route.name}: a well-formed cookie with a forged HMAC, on a warm isolate`, async () => {
      await warm();
      const spy = spiedAuthority();
      await call(route.req(`notme_session=${wellFormedForgery()}`), { SIGNING_AUTHORITY: spy.binding });
      expect(spy.calls).toEqual([]);
    });
  }

  it("a cold isolate pays at most ONE secret fetch for a burst of well-formed forgeries", async () => {
    const spy = spiedAuthority();
    await Promise.all(
      Array.from({ length: 20 }, () =>
        call(ROUTES[0]!.req(`notme_session=${wellFormedForgery()}`), { SIGNING_AUTHORITY: spy.binding }),
      ),
    );
    expect(spy.calls).toEqual(["getSessionSecret"]);
    // And once it is warm, the next one costs nothing.
    const after = spiedAuthority();
    await call(ROUTES[0]!.req(`notme_session=${wellFormedForgery()}`), { SIGNING_AUTHORITY: after.binding });
    expect(after.calls).toEqual([]);
  });
});

describe("a valid cookie still works, and still answers to the live secret", () => {
  beforeEach(() => __resetSessionSecretCacheForTests());

  it("GET /me accepts a valid cookie", async () => {
    const res = await call(
      new Request(`${ORIGIN}/me`, { headers: { cookie: await validCookie("valid-me"), accept: "application/json" } }),
      {},
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as { authenticated: boolean }).authenticated).toBe(true);
  });

  it("POST /cert/nonce issues a nonce for a valid cookie, warm or cold", async () => {
    const cookie = await validCookie("valid-nonce");
    for (const _ of [0, 1]) {
      const spy = spiedAuthority();
      const res = await call(new Request(`${ORIGIN}/cert/nonce`, { method: "POST", headers: { cookie } }), {
        SIGNING_AUTHORITY: spy.binding,
      });
      expect(res.status).toBe(200);
      // One secret read (the fetch when cold, the liveness confirmation when
      // warm), then the nonce — the same RPC count as before the cache.
      expect(spy.calls).toEqual(["getSessionSecret", "issuePopNonce"]);
    }
  });

  it("a reset that rotates the secret revokes old cookies at once, even in a warm isolate", async () => {
    // The cache must not turn resetPasskeyData's revocation into a TTL-long
    // grace period. A positive local HMAC is confirmed against the live secret.
    const old = await validCookie("pre-reset");
    await warm();
    const stub = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
    await stub.resetPasskeyData();
    const res = await call(new Request(`${ORIGIN}/me`, { headers: { cookie: old, accept: "application/json" } }), {});
    expect(res.status).toBe(302);
    // And a cookie under the NEW secret is accepted right away in the same isolate.
    const fresh = await validCookie("post-reset");
    const ok = await call(new Request(`${ORIGIN}/me`, { headers: { cookie: fresh, accept: "application/json" } }), {});
    expect(ok.status).toBe(200);
  });
});

describe("the per-IP session limiter runs before the DO (defence in depth)", () => {
  beforeEach(() => __resetSessionSecretCacheForTests());

  it("a limited caller with a VALID cookie is refused 429 with no RPC", async () => {
    const cookie = await validCookie("limited");
    await warm();
    const spy = spiedAuthority();
    const rl = limiter(() => false);
    const res = await call(
      new Request(`${ORIGIN}/me`, { headers: { cookie, accept: "application/json", "cf-connecting-ip": "198.51.100.9" } }),
      { SIGNING_AUTHORITY: spy.binding, TOKEN_LIMITER: rl.binding },
    );
    expect(res.status).toBe(429);
    expect(spy.calls).toEqual([]);
    expect(rl.keys).toEqual(["session-ip:198.51.100.9"]);
  });

  it("a cold isolate checks the limiter before fetching the secret", async () => {
    const spy = spiedAuthority();
    const rl = limiter(() => false);
    const res = await call(
      new Request(`${ORIGIN}/cert/nonce`, {
        method: "POST",
        headers: { cookie: `notme_session=${wellFormedForgery()}`, "cf-connecting-ip": "2001:db8:5:6::1" },
      }),
      { SIGNING_AUTHORITY: spy.binding, TOKEN_LIMITER: rl.binding },
    );
    expect(res.status).toBe(429);
    expect(spy.calls).toEqual([]);
    expect(rl.keys).toEqual(["session-ip:2001:db8:5:6::/64"]);
  });

  it("junk that never reaches the DO does not spend the caller's budget", async () => {
    const rl = limiter(() => true);
    await call(ROUTES[0]!.req("notme_session=x"), { TOKEN_LIMITER: rl.binding });
    expect(rl.keys).toEqual([]);
  });
});
