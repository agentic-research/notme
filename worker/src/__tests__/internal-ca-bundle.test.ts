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
    const { env, platform, cache, authority } = makeHarness({
      cached: JSON.stringify(sampleBundle),
    });

    const response = await handleInternalCABundle(
      new Request("https://notme-bot/internal/ca-bundle"),
      env,
      platform,
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(response.headers.get("cache-control")).toBe("no-store");
    await expect(response.json()).resolves.toEqual(sampleBundle);
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
