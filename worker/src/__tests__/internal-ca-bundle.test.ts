import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  __resetCABundleMemoForTests,
  BYPASS_FLOOR_MS,
  ensureCurrentCABundle,
  handleInternalCABundle,
} from "../internal-ca-bundle";
import type { Platform } from "../platform";
import type { CABundle } from "../revocation";

const sampleBundle: CABundle = {
  epoch: 1,
  seqno: 2,
  keys: { active: "cHVibGljLWtleQ==" },
  keyId: "active",
  issuedAt: 1_735_689_600,
  signature: "c2lnbmF0dXJl",
};

function makeHarness(
  options: {
    cached?: string | null;
    generated?: CABundle;
    generateError?: Error;
  } = {},
) {
  const cache = {
    get: vi.fn(async () => options.cached ?? null),
    put: vi.fn(async () => undefined),
  };
  const authority = {
    generateBundle: options.generateError
      ? vi.fn(async () => {
          throw options.generateError;
        })
      : vi.fn(async () => options.generated ?? sampleBundle),
  };
  const env = {
    SIGNING_AUTHORITY: {
      idFromName: vi.fn(() => "default-id"),
      get: vi.fn(() => authority),
    },
  };
  const platform = { keyStorage: "ephemeral", cache } as unknown as Platform;
  return { env, platform, cache, authority };
}

// Each test starts as a cold isolate: the handler keeps its last answer.
beforeEach(() => __resetCABundleMemoForTests());

describe("internal CA bundle endpoint", () => {
  it("returns the cached signed CABundle without touching the authority", async () => {
    // FRESH issuedAt: since the staleness gate landed, a cache hit only
    // short-circuits for a bundle inside the window — which is this test's
    // actual claim. sampleBundle's 2025 timestamp would (correctly) regenerate.
    const freshCached = {
      ...sampleBundle,
      issuedAt: Math.floor(Date.now() / 1000),
    };
    const { env, platform, cache, authority } = makeHarness({
      cached: JSON.stringify(freshCached),
    });

    const response = await handleInternalCABundle(
      new Request("https://notme-bot/internal/ca-bundle"),
      env,
      platform,
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(response.headers.get("cache-control")).toBe("no-store");
    await expect(response.json()).resolves.toEqual(freshCached);
    expect(cache.get).toHaveBeenCalledWith("bundle:current");
    expect(authority.generateBundle).not.toHaveBeenCalled();
    expect(cache.put).not.toHaveBeenCalled();
  });

  it("generates and stores a bundle on cache miss", async () => {
    const { env, platform, cache, authority } = makeHarness({ cached: null });

    await expect(ensureCurrentCABundle(env, platform)).resolves.toEqual(
      sampleBundle,
    );

    expect(env.SIGNING_AUTHORITY.idFromName).toHaveBeenCalledWith("default");
    expect(env.SIGNING_AUTHORITY.get).toHaveBeenCalledWith("default-id");
    expect(authority.generateBundle).toHaveBeenCalledTimes(1);
    expect(cache.put).toHaveBeenCalledWith(
      "bundle:current",
      JSON.stringify(sampleBundle),
    );
    // And with NO third argument: a KV TTL turns a stale bundle into an
    // absent one, and checkRevocation fails OPEN on absent
    // (bundle-no-ttl.test.ts). The read-time staleness check is the bound.
    expect(cache.put.mock.calls[0]).toHaveLength(2);
  });

  it("regenerates when the cached bundle is malformed", async () => {
    const { env, platform, cache, authority } = makeHarness({
      cached: "not json",
    });

    await expect(ensureCurrentCABundle(env, platform)).resolves.toEqual(
      sampleBundle,
    );

    expect(authority.generateBundle).toHaveBeenCalledTimes(1);
    expect(cache.put).toHaveBeenCalledWith(
      "bundle:current",
      JSON.stringify(sampleBundle),
    );
    // And with NO third argument: a KV TTL turns a stale bundle into an
    // absent one, and checkRevocation fails OPEN on absent
    // (bundle-no-ttl.test.ts). The read-time staleness check is the bound.
    expect(cache.put.mock.calls[0]).toHaveLength(2);
  });

  it("regenerates when the cached bundle is STALE — the read path is the third safeguard", async () => {
    // The 130-day incident (notme-77a024) needed two failures to line up: a
    // dead refresh alarm AND a TTL-less KV write. Both are fixed, and both
    // could regress. This gate is the third, independent one: even a bundle
    // that somehow survives in cache past the staleness window is refused AT
    // THE READ and regenerated — the serving path can no longer hand out a
    // fossil, whatever the cache layer does (notme-8d3018).
    const fresh: CABundle = {
      ...sampleBundle,
      seqno: 3,
      issuedAt: Math.floor(Date.now() / 1000),
    };
    const { env, platform, authority, cache } = makeHarness({
      cached: JSON.stringify(sampleBundle), // issuedAt 2025 — long stale
      generated: fresh,
    });

    const bundle = await ensureCurrentCABundle(env, platform);

    expect(authority.generateBundle).toHaveBeenCalledTimes(1);
    expect(bundle).toEqual(fresh);
    expect(cache.put).toHaveBeenCalled();
  });

  it("rejects non-GET methods before reaching storage", async () => {
    const { env, platform, cache, authority } = makeHarness();

    const response = await handleInternalCABundle(
      new Request("https://notme-bot/internal/ca-bundle", { method: "POST" }),
      env,
      platform,
    );

    expect(response.status).toBe(405);
    await expect(response.json()).resolves.toEqual({
      error: "method not allowed",
    });
    expect(cache.get).not.toHaveBeenCalled();
    expect(authority.generateBundle).not.toHaveBeenCalled();
  });

  it("reports authority failures as unavailable", async () => {
    const { env, platform } = makeHarness({
      cached: null,
      generateError: new Error("boom"),
    });

    const response = await handleInternalCABundle(
      new Request("https://notme-bot/internal/ca-bundle"),
      env,
      platform,
    );

    expect(response.status).toBe(503);
    // A constant body: the authority's message is logged, not returned
    // (notme-b567c9).
    await expect(response.json()).resolves.toEqual({
      error: "authority unavailable",
    });
  });
});

describe("ca-bundle.single-flight — /internal/ca-bundle under load (notme-a34dad, review M1)", () => {
  const nowS = () => Math.floor(Date.now() / 1000);
  const req = (headers: Record<string, string> = {}) =>
    new Request("https://notme-bot/internal/ca-bundle", { headers });

  /** A Cache API stand-in that stores what it is given and reports each max-age. */
  function fakeEdge() {
    const store = new Map<string, Response>();
    const maxAges: number[] = [];
    return {
      store,
      maxAges,
      edge: {
        match: vi.fn(async (k: Request) => store.get(k.url)?.clone()),
        put: vi.fn(async (k: Request, v: Response) => {
          maxAges.push(Number(/max-age=(\d+)/.exec(v.headers.get("cache-control") || "")?.[1]));
          store.set(k.url, v);
        }),
      },
      edgeKey: new Request("https://notme-bot/internal/ca-bundle?_build=t"),
    };
  }

  afterEach(() => vi.useRealTimers());

  it("N concurrent requests against a STALE bundle make one KV read and one DO call", async () => {
    // The herd: every request used to read KV, find the bundle stale, run its
    // own generateBundle() on the singleton and its own KV put to one key.
    const fresh: CABundle = { ...sampleBundle, seqno: 9, issuedAt: nowS() };
    const { env, platform, cache, authority } = makeHarness({
      cached: JSON.stringify(sampleBundle), // issuedAt 2025: stale
      generated: fresh,
    });
    const N = 25;
    const responses = await Promise.all(Array.from({ length: N }, () => handleInternalCABundle(req(), env, platform)));
    for (const r of responses) {
      expect(r.status).toBe(200);
      expect(r.headers.get("cache-control")).toBe("no-store");
      await expect(r.json()).resolves.toEqual(fresh);
    }
    expect(cache.get).toHaveBeenCalledTimes(1);
    expect(authority.generateBundle).toHaveBeenCalledTimes(1);
    expect(cache.put).toHaveBeenCalledTimes(1);
  });

  it("sequential requests inside the serve window are answered without KV", async () => {
    const { env, platform, cache } = makeHarness({ cached: JSON.stringify({ ...sampleBundle, issuedAt: nowS() }) });
    for (let i = 0; i < 10; i++) expect((await handleInternalCABundle(req(), env, platform)).status).toBe(200);
    expect(cache.get).toHaveBeenCalledTimes(1);
  });

  it("never serves a bundle older than BUNDLE_MAX_AGE_MS: the window shrinks to what is left of its 300 s", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-04T00:00:00Z"));
    const issuedAt = nowS() - 290; // 10 s of freshness left
    const nearlyStale: CABundle = { ...sampleBundle, issuedAt };
    const regenerated: CABundle = { ...sampleBundle, seqno: 3, issuedAt: nowS() + 11 };
    const { env, platform, cache, authority } = makeHarness({ cached: JSON.stringify(nearlyStale), generated: regenerated });
    const f = fakeEdge();
    await handleInternalCABundle(req(), env, platform, f);
    expect(f.maxAges).toEqual([10]);
    // 9 s on: still inside the window, from memory.
    vi.setSystemTime(Date.now() + 9_000);
    const mid = await handleInternalCABundle(req(), env, platform);
    await expect(mid.json()).resolves.toEqual(nearlyStale);
    expect(cache.get).toHaveBeenCalledTimes(1);
    // 11 s on: the copy would be 301 s old, so it is not served; KV still holds
    // the stale one, so the DO regenerates.
    vi.setSystemTime(Date.now() + 2_000);
    const late = await handleInternalCABundle(req(), env, platform);
    await expect(late.json()).resolves.toEqual(regenerated);
    expect(authority.generateBundle).toHaveBeenCalledTimes(1);
  });

  it("is served from the edge, with an edge max-age of at most 30 s, and still no-store to the client", async () => {
    const { env, platform, cache } = makeHarness({ cached: JSON.stringify({ ...sampleBundle, issuedAt: nowS() }) });
    const f = fakeEdge();
    const first = await handleInternalCABundle(req(), env, platform, f);
    expect(first.headers.get("cache-control")).toBe("no-store");
    expect(f.maxAges).toEqual([30]);
    __resetCABundleMemoForTests(); // another isolate in the same colo
    const second = await handleInternalCABundle(req(), env, platform, f);
    expect(second.status).toBe(200);
    expect(second.headers.get("cache-control")).toBe("no-store");
    expect(cache.get).toHaveBeenCalledTimes(1);
  });

  it("Cache-Control: no-cache reads past the edge and memory (the trust-anchor gate), within its limiter", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-05T00:00:00Z"));
    const { env, platform, cache } = makeHarness({ cached: JSON.stringify({ ...sampleBundle, issuedAt: nowS() }) });
    const f = fakeEdge();
    await handleInternalCABundle(req(), env, platform, f);
    // Past the bypass floor (L5): a copy read from KV this recently would answer it.
    vi.setSystemTime(Date.now() + BYPASS_FLOOR_MS + 1);
    const allowed = await handleInternalCABundle(req({ "cache-control": "no-cache" }), env, platform, {
      ...f,
      bypassAllowed: async () => true,
    });
    expect(allowed.status).toBe(200);
    expect(cache.get).toHaveBeenCalledTimes(2);
    const refused = await handleInternalCABundle(req({ "cache-control": "no-cache" }), env, platform, {
      ...f,
      bypassAllowed: async () => false,
    });
    expect(refused.status).toBe(429);
    expect(cache.get).toHaveBeenCalledTimes(2);
  });

  it("a failed refresh is answered 503 for a few seconds without asking the authority again (M3)", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-04T00:00:00Z"));
    const { env, platform, authority } = makeHarness({ cached: null, generateError: new Error("overloaded") });
    const f = fakeEdge();
    expect((await handleInternalCABundle(req(), env, platform)).status).toBe(503);
    expect((await handleInternalCABundle(req(), env, platform)).status).toBe(503);
    expect(authority.generateBundle).toHaveBeenCalledTimes(1);
    vi.setSystemTime(Date.now() + 5_001);
    expect((await handleInternalCABundle(req(), env, platform, f)).status).toBe(503);
    expect(authority.generateBundle).toHaveBeenCalledTimes(2);
    // ...and the colo's edge holds that 503 for 5 s too.
    expect(f.maxAges).toEqual([5]);
  });
});

describe("ca-bundle.edge-read-gate — review round 2 (notme-a34dad M1, L1, L2, L5)", () => {
  const nowS = () => Math.floor(Date.now() / 1000);
  const req = (headers: Record<string, string> = {}) =>
    new Request("https://notme-bot/internal/ca-bundle", { headers });
  /** A Cache API stand-in that keeps whatever it is given, max-age or not. */
  function sloppyEdge() {
    const store = new Map<string, Response>();
    return {
      store,
      edgeKey: new Request("https://notme-bot/internal/ca-bundle?_build=t"),
      edge: {
        match: vi.fn(async (k: Request) => store.get(k.url)?.clone()),
        put: vi.fn(async (k: Request, v: Response) => void store.set(k.url, v)),
      },
    };
  }
  afterEach(() => vi.useRealTimers());

  it("M1: an edge hit past the 300 s window is not served, even if the cache kept it", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-05T00:00:00Z"));
    const old: CABundle = { ...sampleBundle, seqno: 1, issuedAt: nowS() };
    const f = sloppyEdge();
    f.store.set(
      f.edgeKey.url,
      new Response(JSON.stringify(old), { headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=999" } }),
    );
    vi.setSystemTime(Date.now() + 301_000);
    const regenerated: CABundle = { ...sampleBundle, seqno: 2, issuedAt: nowS() };
    const { env, platform, authority } = makeHarness({ cached: JSON.stringify(old), generated: regenerated });
    const res = await handleInternalCABundle(req(), env, platform, f);
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual(regenerated);
    expect(authority.generateBundle).toHaveBeenCalledTimes(1);
  });

  it("M1: an edge hit inside the window is served, and a malformed one is a miss", async () => {
    const good: CABundle = { ...sampleBundle, issuedAt: nowS() };
    const f = sloppyEdge();
    f.store.set(f.edgeKey.url, new Response(JSON.stringify(good), { headers: { "Content-Type": "application/json" } }));
    const h1 = makeHarness({ cached: null });
    await expect((await handleInternalCABundle(req(), h1.env, h1.platform, f)).json()).resolves.toEqual(good);
    expect(h1.cache.get).not.toHaveBeenCalled();
    __resetCABundleMemoForTests();
    f.store.set(f.edgeKey.url, new Response("not json", { headers: { "Content-Type": "application/json" } }));
    const h2 = makeHarness({ cached: JSON.stringify(good) });
    expect((await handleInternalCABundle(req(), h2.env, h2.platform, f)).status).toBe(200);
    expect(h2.cache.get).toHaveBeenCalledTimes(1);
  });

  it("L1: a colo-wide 503 at the edge does not override this isolate's valid copy", async () => {
    const good: CABundle = { ...sampleBundle, issuedAt: nowS() };
    const { env, platform } = makeHarness({ cached: JSON.stringify(good) });
    const f = sloppyEdge();
    expect((await handleInternalCABundle(req(), env, platform, f)).status).toBe(200); // memo filled
    // Another isolate's failed refresh negatively caches the colo.
    f.store.set(f.edgeKey.url, new Response(JSON.stringify({ error: "authority unavailable" }), { status: 503 }));
    const res = await handleInternalCABundle(req(), env, platform, f);
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual(good);
  });

  it("L2: a failed KV put still returns the freshly generated bundle, and logs it", async () => {
    const fresh: CABundle = { ...sampleBundle, seqno: 5, issuedAt: nowS() };
    const { env, platform, cache } = makeHarness({ cached: null, generated: fresh });
    cache.put.mockRejectedValueOnce(new Error("KV PUT failed: 429 Too Many Requests"));
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const res = await handleInternalCABundle(req(), env, platform);
      expect(res.status).toBe(200);
      await expect(res.json()).resolves.toEqual(fresh);
      expect(err.mock.calls.some((c) => String(c[0]).includes("bundle:current"))).toBe(true);
    } finally {
      err.mockRestore();
    }
  });

  it("L5: no-cache reads within BYPASS_FLOOR_MS of a refresh share it; after it, they read KV again", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-05T00:00:00Z"));
    const { env, platform, cache } = makeHarness({ cached: JSON.stringify({ ...sampleBundle, issuedAt: nowS() }) });
    const bypass = () => handleInternalCABundle(req({ "cache-control": "no-cache" }), env, platform, { bypassAllowed: async () => true });
    // A /48 fanned over many /64s: each passes its own per-IP bucket.
    for (let i = 0; i < 50; i++) expect((await bypass()).status).toBe(200);
    expect(cache.get).toHaveBeenCalledTimes(1);
    vi.setSystemTime(Date.now() + BYPASS_FLOOR_MS + 1);
    await bypass();
    expect(cache.get).toHaveBeenCalledTimes(2);
  });
});
