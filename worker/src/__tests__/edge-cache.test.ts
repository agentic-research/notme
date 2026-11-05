/**
 * edge-cache.test.ts — a Cache API failure backs off and recovers; it does not
 * disable the cache for the isolate's lifetime (notme-a34dad, review M3).
 */
import { beforeEach, describe, expect, it } from "vitest";
import {
  BACKOFF_MAX_MS,
  __edgeCacheStateForTests,
  __resetEdgeCacheForTests,
  disableForIsolate,
  edgeMatch,
  edgePut,
  noteUnavailable,
  unavailableFor,
} from "../edge-cache";

const key = new Request("https://auth.notme.bot/.well-known/jwks.json?_build=t");

function fakeCache(failures: number) {
  let left = failures;
  let calls = 0;
  return {
    get calls() {
      return calls;
    },
    match: async () => {
      calls++;
      if (left-- > 0) throw new Error("cache unavailable");
      return undefined;
    },
    put: async () => {
      calls++;
      if (left-- > 0) throw new Error("cache unavailable");
    },
  };
}

beforeEach(() => __resetEdgeCacheForTests());

describe("edge cache backoff", () => {
  it("skips the cache for 1 s after one failure, then uses it again", async () => {
    const c = fakeCache(1);
    const t0 = 1_000_000;
    await edgeMatch(key, c, t0);
    await edgeMatch(key, c, t0 + 999);
    expect(c.calls).toBe(1); // inside the backoff: not even attempted
    await edgeMatch(key, c, t0 + 1_000);
    expect(c.calls).toBe(2);
    expect(__edgeCacheStateForTests().failures).toBe(0); // the success reset it
  });

  it("doubles per consecutive failure and caps at 60 s", async () => {
    const c = fakeCache(100);
    let now = 1_000_000;
    const waits: number[] = [];
    for (let i = 0; i < 9; i++) {
      await edgePut(key, new Response("x"), c, now);
      const { disabledUntil } = __edgeCacheStateForTests();
      waits.push(disabledUntil - now);
      now = disabledUntil;
    }
    expect(waits).toEqual([1_000, 2_000, 4_000, 8_000, 16_000, 32_000, BACKOFF_MAX_MS, BACKOFF_MAX_MS, BACKOFF_MAX_MS]);
  });

  it("local workerd's off switch is the only permanent one", async () => {
    const c = fakeCache(0);
    disableForIsolate();
    await edgeMatch(key, c, Date.now() + 10 * BACKOFF_MAX_MS);
    expect(c.calls).toBe(0);
  });

  it("a remembered 503 lasts NEGATIVE_CACHE_SECONDS and then is forgotten", () => {
    const t0 = 2_000_000;
    noteUnavailable(key, t0);
    expect(unavailableFor(key, t0 + 1)).toBe(5);
    expect(unavailableFor(key, t0 + 4_001)).toBe(1);
    expect(unavailableFor(key, t0 + 5_000)).toBe(0);
  });
});
