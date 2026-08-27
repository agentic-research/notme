import { describe, expect, it, vi } from "vitest";

import {
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
      // The TTL IS the fix. Without it the first bundle generated is pinned in
      // KV permanently — production served one issued 2026-03-29, 130 days
      // old, against a five-minute staleness window, so every conformant
      // consumer rejected it (notme-77a024). Asserted rather than assumed
      // because a silently-dropped TTL restores the original bug exactly.
      { expirationTtl: 60 },
    );
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
      // The TTL IS the fix. Without it the first bundle generated is pinned in
      // KV permanently — production served one issued 2026-03-29, 130 days
      // old, against a five-minute staleness window, so every conformant
      // consumer rejected it (notme-77a024). Asserted rather than assumed
      // because a silently-dropped TTL restores the original bug exactly.
      { expirationTtl: 60 },
    );
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
    await expect(response.json()).resolves.toEqual({
      error: "authority unavailable: boom",
    });
  });
});
