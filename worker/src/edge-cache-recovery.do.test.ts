/// <reference types="@cloudflare/vitest-plugin/types" />
/**
 * edge-cache-recovery.do.test.ts — one Cache API error must not disable edge
 * caching for the life of the isolate, and an "authority unavailable" 503 is
 * cached for a few seconds rather than re-asked on every request
 * (notme-a34dad, overnight review M3).
 *
 * Every request here is PRODUCTION-shaped (auth.notme.bot, an https SITE_URL):
 * a local-shaped request switches the Cache API off for the isolate on
 * purpose, which would make every assertion below vacuous.
 */
import { env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import worker from "../worker";
import { cacheKey } from "./cache-key";

const PROD_ENV = { SITE_URL: "https://notme.bot", SIGNET_AUTHORITY_URL: "https://auth.notme.bot" };
const JWKS = "https://auth.notme.bot/.well-known/jwks.json";

const get = (url: string, extra: Record<string, unknown>) =>
  worker.fetch(new Request(url, { headers: { host: "auth.notme.bot" } }), { ...env, ...PROD_ENV, ...extra } as never);

/** The SIGNING_AUTHORITY namespace with each RPC recorded; `fail` names methods that reject. */
function spiedAuthority(fail: string[] = []) {
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
            if (fail.includes(prop)) return Promise.reject(new Error("Durable Object is overloaded"));
            return (target as unknown as Record<string, (...a: unknown[]) => unknown>)[prop]!(...args);
          };
        },
      });
    },
  };
  return { calls, binding };
}

const cache = () => (caches as unknown as { default: Cache }).default;
const realMatch = cache().match;

beforeEach(async () => {
  await cache().delete(cacheKey(new Request(JWKS)));
});
afterEach(() => {
  (cache() as unknown as { match: typeof realMatch }).match = realMatch;
});

describe("cache.error-backoff — the edge cache recovers from an error (M3)", () => {
  it("one failed match backs off briefly, then the cache is used again", async () => {
    let failNext = true;
    (cache() as unknown as { match: typeof realMatch }).match = function (this: Cache, ...a: Parameters<Cache["match"]>) {
      if (failNext) {
        failNext = false;
        return Promise.reject(new Error("cache unavailable"));
      }
      return realMatch.apply(this, a);
    } as typeof realMatch;

    const spy = spiedAuthority();
    expect((await get(JWKS, { SIGNING_AUTHORITY: spy.binding })).status).toBe(200); // match throws: DO
    await new Promise((r) => setTimeout(r, 1_100)); // past the first backoff
    expect((await get(JWKS, { SIGNING_AUTHORITY: spy.binding })).status).toBe(200); // miss: DO, and stored
    expect((await get(JWKS, { SIGNING_AUTHORITY: spy.binding })).status).toBe(200); // hit
    // Latched off, the third request was a third DO call.
    expect(spy.calls).toEqual(["getPublicKeyJwk", "getPublicKeyJwk"]);
  });
});

describe("cache.negative-503 — an authority-unavailable 503 is cached for seconds (M3)", () => {
  it("the second request inside the window is answered from the edge, not the overloaded DO", async () => {
    const spy = spiedAuthority(["getPublicKeyJwk"]);
    const first = await get(JWKS, { SIGNING_AUTHORITY: spy.binding });
    expect(first.status).toBe(503);
    expect(first.headers.get("cache-control")).toBe("public, max-age=5");
    const second = await get(JWKS, { SIGNING_AUTHORITY: spy.binding });
    expect(second.status).toBe(503);
    expect(spy.calls).toEqual(["getPublicKeyJwk"]);
  });

  it("a DO call that throws on a builder with no catch is a 503 too, not a Worker exception", async () => {
    // epochs.json's builder does not catch: an overloaded DO used to escape
    // as an uncaught error (Cloudflare 1101) on every request.
    const url = "https://auth.notme.bot/.well-known/epochs.json";
    await cache().delete(cacheKey(new Request(url)));
    const spy = spiedAuthority(["getSignedEpochHistory"]);
    const res = await get(url, { SIGNING_AUTHORITY: spy.binding });
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "authority unavailable" });
  });
});
