/// <reference types="@cloudflare/vitest-plugin/types" />
/**
 * well-known-cache-key.do.test.ts — a query string must not buy a cache miss
 * on /.well-known/* (notme-ed6114).
 *
 * The Cache API key kept the caller's query string, so
 * `/.well-known/jwks.json?x=<random>` always missed and called the singleton
 * SigningAuthority: an unauthenticated, uncapped DO call per request. No
 * /.well-known route reads its query, so the query is not part of what the
 * response depends on and must not be part of the key.
 *
 * Its own file because the Cache API is disabled for the isolate's lifetime
 * once any request carries a localhost SITE_URL (worker.ts `cacheEnabled`),
 * which every other pool suite uses.
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../worker";

const AUTH = "https://auth.notme.bot";
const DEPLOYED_ENV = { SITE_URL: "https://notme.bot", SIGNET_AUTHORITY_URL: AUTH };

/** SIGNING_AUTHORITY with every stub RPC recorded by method name. */
function spiedAuthority() {
  const calls: string[] = [];
  const ns = env.SIGNING_AUTHORITY;
  return {
    calls,
    binding: {
      idFromName: (name: string) => ns.idFromName(name),
      get: (id: DurableObjectId) => {
        const stub = ns.get(id);
        return new Proxy(stub, {
          get(target, prop) {
            const value = Reflect.get(target, prop);
            if (typeof prop !== "string" || prop === "then" || typeof value !== "function") return value;
            return (...args: unknown[]) => {
              calls.push(prop);
              // Through the stub: on an RPC stub `.apply` is itself remote.
              return (target as unknown as Record<string, (...a: unknown[]) => unknown>)[prop]!(...args);
            };
          },
        });
      },
    },
  };
}

/** A fresh 40-hex "commit": only a well-formed one stamps the build. */
const randomCommit = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(20)), (b) => b.toString(16).padStart(2, "0")).join("");

const get = (url: string, extra: Record<string, unknown>) =>
  worker.fetch(new Request(url, { headers: { host: new URL(url).host } }), {
    ...env,
    ...DEPLOYED_ENV,
    // A distinct build per test: the build is part of every key
    // (src/cache-key.ts), so no test is answered from another's entry.
    ...extra,
  } as never);

// THREAT_MODEL §8 `routing.cache.query-ignored`.
describe("routing.cache.query-ignored", () => {
  it("control: identical URLs make one DO call, so the cache is live here", async () => {
    const spy = spiedAuthority();
    const extra = { SIGNING_AUTHORITY: spy.binding, BUILD_SHA: randomCommit() };
    await get(`${AUTH}/.well-known/jwks.json`, extra);
    await get(`${AUTH}/.well-known/jwks.json`, extra);
    expect(spy.calls).toEqual(["getPublicKeyJwk"]);
  });

  for (const [path, rpc] of [
    ["/.well-known/jwks.json", "getPublicKeyJwk"],
    ["/.well-known/epochs.json", "getSignedEpochHistory"],
    ["/.well-known/ct-not-delivered.json", "listNotDeliveredCerts"],
    ["/.well-known/ca-bundle.pem", "getCACertificatePem"],
  ] as const) {
    it(`${path}: two requests differing only by query make one DO call`, async () => {
      const spy = spiedAuthority();
      const extra = { SIGNING_AUTHORITY: spy.binding, BUILD_SHA: randomCommit() };
      const a = await get(`${AUTH}${path}?x=${crypto.randomUUID()}`, extra);
      const b = await get(`${AUTH}${path}?x=${crypto.randomUUID()}`, extra);
      expect(a.status).toBe(200);
      expect(b.status).toBe(200);
      expect(await b.text()).toBe(await a.text());
      expect(spy.calls.filter((c) => c === rpc)).toEqual([rpc]);
    });
  }
});

// A rotate() reaches a verifier of these documents only when both the edge
// entry and the verifier's own copy expire: nothing purges either. 300 s
// matches BUNDLE_MAX_AGE_MS, the bound ADR-019 D7 sets for the CABundle
// (review F3). At 3600 s, a compromised key stayed trusted ~2 h.
describe("routing.cache.rotation-bound", () => {
  for (const path of ["/.well-known/jwks.json", "/.well-known/ca-bundle.pem"]) {
    it(`${path} is cached for at most 300 s, at the edge and by the client`, async () => {
      const res = await get(`${AUTH}${path}`, { BUILD_SHA: randomCommit() });
      expect(res.status).toBe(200);
      expect(res.headers.get("cache-control")).toBe("public, max-age=300");
    });
  }
});

// THREAT_MODEL §8 `routing.cache.method-gate`. The Cache API serves GET
// only, so before this any other method missed the cache every time — the
// same free DO call the query string used to buy (review F1).
describe("routing.cache.method-gate", () => {
  const send = (url: string, method: string, extra: Record<string, unknown>) =>
    worker.fetch(new Request(url, { method, headers: { host: new URL(url).host } }), {
      ...env,
      ...DEPLOYED_ENV,
      ...extra,
    } as never);

  for (const [path, rpc] of [
    ["/.well-known/jwks.json", "getPublicKeyJwk"],
    ["/.well-known/epochs.json", "getSignedEpochHistory"],
    ["/.well-known/ct-not-delivered.json", "listNotDeliveredCerts"],
    ["/.well-known/ca-bundle.pem", "getCACertificatePem"],
  ] as const) {
    it(`${path}: after one GET, HEAD is served from the cache and POST is 405, with no further DO call`, async () => {
      const spy = spiedAuthority();
      const extra = { SIGNING_AUTHORITY: spy.binding, BUILD_SHA: randomCommit() };
      const warm = await send(`${AUTH}${path}`, "GET", extra);
      expect(warm.status).toBe(200);
      const head = await send(`${AUTH}${path}`, "HEAD", extra);
      expect(head.status).toBe(200);
      expect(head.headers.get("cache-control")).toBe(warm.headers.get("cache-control"));
      expect(await head.text()).toBe("");
      for (const method of ["POST", "PUT", "DELETE"]) {
        const res = await send(`${AUTH}${path}`, method, extra);
        expect(res.status, method).toBe(405);
        expect(res.headers.get("allow")).toBe("GET, HEAD");
      }
      expect(spy.calls.filter((c) => c === rpc)).toEqual([rpc]);
    });

    it(`${path}: a cold HEAD warms the GET entry`, async () => {
      const spy = spiedAuthority();
      const extra = { SIGNING_AUTHORITY: spy.binding, BUILD_SHA: randomCommit() };
      expect((await send(`${AUTH}${path}`, "HEAD", extra)).status).toBe(200);
      expect((await send(`${AUTH}${path}`, "HEAD", extra)).status).toBe(200);
      expect((await send(`${AUTH}${path}`, "GET", extra)).status).toBe(200);
      expect(spy.calls.filter((c) => c === rpc)).toEqual([rpc]);
    });
  }
});
