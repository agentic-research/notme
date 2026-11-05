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
import { createSessionCookie, createSessionCookieWithExp } from "./auth/session";
import {
  __resetSessionSecretCacheForTests,
  couldBeSessionCookie,
  PRINCIPAL_LIMIT_PER_MINUTE,
  SESSION_LIMIT_PER_MINUTE,
} from "./auth/session-secret-cache";

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


/**
 * The limiter is keyed by SESSION IDENTITY, not by address (notme-a34dad
 * fix round). After the C2 fix a cookie that fails the cached-secret HMAC
 * never reaches the DO, so the only callers the limiter has to bound hold a
 * correctly signed cookie, and the principal it names is the one thing a
 * per-IP key cannot tell apart behind a NAT. These use the REAL
 * SESSION_LIMITER binding the pool declares (vitest.workers.config.mts), at
 * the production rate, so "not limited" and "limited" are measured against
 * the number that ships, not a stand-in.
 */
describe("session.limiter.per-principal — the session limiter is keyed by session, then principal, after the HMAC", () => {
  beforeEach(() => __resetSessionSecretCacheForTests());

  const me = (cookie: string, ip = "198.51.100.20") =>
    new Request(`${ORIGIN}/me`, { headers: { cookie, accept: "application/json", "cf-connecting-ip": ip } });
  const nonce = (cookie: string, ip = "198.51.100.20") =>
    new Request(`${ORIGIN}/cert/nonce`, { method: "POST", headers: { cookie, "cf-connecting-ip": ip } });

  /**
   * The limiter's windows are aligned to the wall clock (miniflare's, like
   * Cloudflare's fixed windows), so a burst that straddles a minute boundary
   * would see two budgets. Each counting test starts with room left.
   */
  async function roomInWindow(ms = 15_000): Promise<void> {
    const left = 60_000 - (Date.now() % 60_000);
    if (left < ms) await new Promise((r) => setTimeout(r, left + 100));
  }

  it("the shipped rates are 60 per session and 300 per principal, per minute", () => {
    expect(SESSION_LIMIT_PER_MINUTE).toBe(60);
    expect(PRINCIPAL_LIMIT_PER_MINUTE).toBe(300);
  });

  it("a realistic dashboard minute from one valid session is not limited", async () => {
    // The busiest real minute, measured from the routes (SESSION_LIMIT_PER_MINUTE
    // has the count): /me, the invites page (list + create), an /authorize
    // round trip in both shapes, an enrolment approval (/enroll, approve,
    // list), a bridge-pair mint (/cert/nonce + /cert/passkey) twice, alarm
    // health and passkey status.
    const cookie = await validCookie(`dash-${crypto.randomUUID()}`, ["bridgeCert", "authorityManage", "certMint"]);
    const pick = /authorize|enroll|enrollments|device\/approve|alarm-health|passkey\/status|cert\/passkey|GET \/invites|POST \/invites/;
    const burst = [
      me(cookie),
      ...ROUTES.filter((r) => pick.test(r.name)).map((r) => r.req(cookie)),
      nonce(cookie),
      nonce(cookie),
      ROUTES.find((r) => r.name === "POST /cert/passkey")!.req(cookie),
    ];
    expect(burst.length).toBeGreaterThanOrEqual(14);
    for (const req of burst) {
      const res = await call(req, {});
      expect(res.status, new URL(req.url).pathname).not.toBe(429);
    }
  });

  it("one valid session hammering is limited, and its refused requests cost no RPC", async () => {
    await roomInWindow();
    const cookie = await validCookie(`hammer-${crypto.randomUUID()}`);
    const statuses: number[] = [];
    for (let i = 0; i < SESSION_LIMIT_PER_MINUTE + 5; i++) statuses.push((await call(me(cookie), {})).status);
    expect(statuses.slice(0, SESSION_LIMIT_PER_MINUTE).every((s) => s === 200)).toBe(true);
    expect(statuses.slice(SESSION_LIMIT_PER_MINUTE)).toEqual(Array(5).fill(429));
    const spy = spiedAuthority();
    expect((await call(nonce(cookie), { SIGNING_AUTHORITY: spy.binding })).status).toBe(429);
    expect(spy.calls).toEqual([]);
  }, 60_000);

  it("two sessions behind the same IP do not share a budget", async () => {
    await roomInWindow();
    const a = await validCookie(`nat-a-${crypto.randomUUID()}`);
    const b = await validCookie(`nat-b-${crypto.randomUUID()}`);
    for (let i = 0; i < SESSION_LIMIT_PER_MINUTE; i++) await call(me(a, "203.0.113.50"), {});
    expect((await call(me(a, "203.0.113.50"), {})).status).toBe(429);
    expect((await call(me(b, "203.0.113.50"), {})).status).toBe(200);
  }, 60_000);

  it("is keyed by the SESSION the HMAC proved, then its principal, after the HMAC, and never for junk", async () => {
    const rl = limiter(() => false);
    await call(me(`notme_session=${wellFormedForgery()}`), { SESSION_LIMITER: rl.binding });
    await call(me("notme_session=x"), { SESSION_LIMITER: rl.binding });
    expect(rl.keys).toEqual([]);
    // A valid cookie on a warm isolate is refused before the liveness confirmation.
    const cookie = await validCookie("keyed-principal");
    await warm();
    const spy = spiedAuthority();
    const res = await call(me(cookie), { SIGNING_AUTHORITY: spy.binding, SESSION_LIMITER: rl.binding });
    expect(res.status).toBe(429);
    expect(spy.calls).toEqual([]);
    // The session key is the cookie's own MAC: unique per issued cookie,
    // unforgeable, and not the principal's.
    expect(rl.keys).toEqual([`session:${cookie.split(".")[1]}`]);
    // Within its own budget, it is then charged to the principal too.
    const pl = limiter(() => false);
    const res2 = await call(me(cookie), { SESSION_LIMITER: limiter(() => true).binding, PRINCIPAL_LIMITER: pl.binding });
    expect(res2.status).toBe(429);
    expect(pl.keys).toEqual(["principal:keyed-principal"]);
  });

  /** A cookie for `principalId`, distinct from any other one minted for it (its own exp). */
  async function nthCookie(principalId: string, n: number): Promise<string> {
    const stub = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
    const set = await createSessionCookieWithExp(
      { principalId, scopes: ["bridgeCert"], authMethod: "passkey" },
      await stub.getSessionSecret(),
      Math.floor(Date.now() / 1000) + 3600 + n,
    );
    return set.split(";")[0]!;
  }

  it("another session of the SAME principal hammering does not lock this one out (L4)", async () => {
    await roomInWindow();
    // The victim-lockout case: a stolen cookie, or a CI workflow linked to an
    // admin principal, burns its own budget, not the admin's browser session.
    const pid = `shared-${crypto.randomUUID()}`;
    const browser = await nthCookie(pid, 1);
    const attacker = await nthCookie(pid, 2);
    const statuses: number[] = [];
    for (let i = 0; i < SESSION_LIMIT_PER_MINUTE + 5; i++) statuses.push((await call(me(attacker), {})).status);
    expect(statuses.slice(SESSION_LIMIT_PER_MINUTE)).toEqual(Array(5).fill(429));
    expect((await call(me(browser), {})).status).toBe(200);
  }, 60_000);

  it("a principal's sessions TOGETHER are bounded at PRINCIPAL_LIMIT_PER_MINUTE", async () => {
    await roomInWindow();
    // Many sessions of one principal (logins are cheap for whoever holds the
    // credential) do not multiply its budget past the principal key.
    const pid = `many-${crypto.randomUUID()}`;
    const per = SESSION_LIMIT_PER_MINUTE - 1; // never trips a session key
    const sessions = Math.ceil(PRINCIPAL_LIMIT_PER_MINUTE / per) + 1;
    let limited = 0;
    for (let n = 0; n < sessions; n++) {
      const c = await nthCookie(pid, n);
      for (let i = 0; i < per; i++) if ((await call(me(c), {})).status === 429) limited++;
    }
    expect(limited).toBe(sessions * per - PRINCIPAL_LIMIT_PER_MINUTE);
  }, 60_000);

  it("a cookie a reset revoked costs at most one confirmation per isolate, then nothing", async () => {
    // Why charging BEFORE the live check cannot be turned into a lockout by a
    // revoked cookie: the first confirmation refreshes the cached secret, so
    // every later use fails the local HMAC and is never charged.
    const old = await validCookie(`revoked-${crypto.randomUUID()}`);
    await warm();
    const stub = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
    await stub.resetPasskeyData(); // in "another isolate": this one still caches the old secret
    const spy = spiedAuthority();
    const rl = limiter(() => true);
    for (let i = 0; i < 10; i++) {
      const res = await call(me(old), { SIGNING_AUTHORITY: spy.binding, SESSION_LIMITER: rl.binding });
      expect(res.status).toBe(302);
    }
    expect(spy.calls).toEqual(["getSessionSecret"]);
    expect(rl.keys).toHaveLength(1);
  });
});
