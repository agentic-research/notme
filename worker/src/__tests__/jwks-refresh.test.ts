/**
 * jwks-refresh.test.ts — a JWKS key rotation or an upstream outage does not
 * take OIDC verification down (notme-a36d10, overnight review M2).
 *
 * Both verifiers are driven for real: genuinely signed tokens, a JWKS served
 * to the module's own `fetch`, and the verifier's module-scope cache (fresh
 * per file, as vitest isolates modules per test file). Only Date is faked, to
 * move past the refetch window and the TTL.
 *
 * Maps to THREAT_MODEL.md: oidc.jwks.rotation, oidc.jwks.stale-on-error,
 * oidc.jwks.refetch-bounded.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { JWKS_POLICY, JwksCache } from "../auth/jwks-cache";
import { verifyOIDC } from "../auth/verify-proof";
import { validateGHAToken } from "../gha-oidc";
import { b64u, GHA_ISSUER } from "./helpers/gha-token";

const OTHER_ISSUER = "https://issuer.jwks-refresh.test";
const AUD = "notme.bot";
const MIN = 60 * 1000;
const HOUR = 60 * MIN;

interface Signer {
  kid: string;
  jwk: Record<string, unknown>;
  sign(claims: Record<string, unknown>): Promise<string>;
}

async function signer(kid: string): Promise<Signer> {
  const kp = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const pub = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as JsonWebKey;
  return {
    kid,
    jwk: { kty: "RSA", n: pub.n, e: pub.e, kid, alg: "RS256", use: "sig" },
    async sign(claims) {
      const h = b64u(JSON.stringify({ alg: "RS256", typ: "JWT", kid }));
      const p = b64u(JSON.stringify(claims));
      const sig = new Uint8Array(
        await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${h}.${p}`)),
      );
      return `${h}.${p}.${b64u(sig)}`;
    },
  };
}

const ghaClaims = () => {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: GHA_ISSUER,
    aud: AUD,
    sub: "repo:agentic-research/jwks:ref:refs/heads/main",
    exp: now + 300,
    iat: now,
    jti: crypto.randomUUID(),
    repository: "agentic-research/jwks",
    repository_owner: "agentic-research",
    ref: "refs/heads/main",
    sha: "a".repeat(40),
    actor: "a",
    workflow: "w",
    job_workflow_ref: "agentic-research/jwks/.github/workflows/t.yml@refs/heads/main",
    run_id: "1",
    event_name: "push",
  };
};
const oidcClaims = () => ({ iss: OTHER_ISSUER, aud: AUD, sub: "u1", exp: Math.floor(Date.now() / 1000) + 300 });

/** A JWKS host per issuer: what it serves, whether it is up, and every fetch it saw. */
let served: Record<string, Signer[]> = {};
let down = false;
let fetches: Array<{ url: string; cache?: string }> = [];
let realFetch: typeof fetch;

beforeEach(() => {
  served = {};
  down = false;
  fetches = [];
  realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const issuer = [GHA_ISSUER, OTHER_ISSUER].find((i) => url.startsWith(i));
    if (!issuer) return realFetch(input as RequestInfo, init);
    fetches.push({ url, cache: init?.cache });
    if (down) return new Response("unavailable", { status: 503 });
    if (!url.endsWith("/.well-known/jwks")) return new Response("no", { status: 404 });
    return Response.json({ keys: (served[issuer] ?? []).map((s) => s.jwk) });
  }) as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
  vi.useRealTimers();
});

/** Move the faked clock forward. */
let clock = 0;
const startClock = () => {
  clock = Date.now();
  vi.useFakeTimers({ toFake: ["Date"], now: clock });
};
const advance = (ms: number) => {
  clock += ms;
  vi.setSystemTime(clock);
};

const verifiers = [
  {
    name: "GitHub (gha-oidc.ts)",
    issuer: GHA_ISSUER,
    verify: (t: string) => validateGHAToken(t, AUD),
    claims: ghaClaims,
  },
  {
    name: "generic OIDC (verify-proof.ts)",
    issuer: OTHER_ISSUER,
    verify: (t: string) => verifyOIDC(t, { [OTHER_ISSUER]: AUD }),
    claims: oidcClaims,
  },
] as const;

// One describe per verifier; within it the tests share that verifier's
// module-scope cache, so each test moves the clock well past every window
// the previous one could have opened.
for (const v of verifiers) {
  describe(`JWKS refresh: ${v.name}`, () => {
    const fetchesFor = () => fetches.filter((f) => f.url.startsWith(v.issuer));

    it("oidc.jwks.rotation — a token under a rotated-in key is accepted after ONE refetch, past the edge cache", async () => {
      startClock();
      advance(10 * 24 * HOUR);
      const old = await signer(`old-${v.issuer}`);
      const rotated = await signer(`new-${v.issuer}`);
      served[v.issuer] = [old];
      await v.verify(await old.sign(v.claims()));
      const before = fetchesFor().length;

      // The upstream rotates; the isolate's cache (younger than its TTL) still
      // holds only the old key.
      served[v.issuer] = [old, rotated];
      advance(2 * MIN);
      await expect(v.verify(await rotated.sign(v.claims()))).resolves.toBeTruthy();
      const refetches = fetchesFor().slice(before);
      expect(refetches).toHaveLength(1);
      expect(refetches[0]!.cache, "the refetch must not be answered by the edge cache").toBe("no-store");
    });

    it("oidc.jwks.stale-on-error — a failed refresh serves the cached keys, until the 24 h max-stale limit", async () => {
      startClock();
      advance(20 * 24 * HOUR);
      const k = await signer(`stale-${v.issuer}`);
      served[v.issuer] = [k];
      await v.verify(await k.sign(v.claims())); // cached now

      down = true;
      advance(2 * HOUR); // past the TTL: the next call refreshes, and the refresh fails
      await expect(v.verify(await k.sign(v.claims()))).resolves.toBeTruthy();
      advance(20 * HOUR); // 22 h old, still inside max-stale
      await expect(v.verify(await k.sign(v.claims()))).resolves.toBeTruthy();
      advance(3 * HOUR); // 25 h old: past it, the error surfaces
      await expect(v.verify(await k.sign(v.claims()))).rejects.toThrow();
    });

    it("oidc.jwks.refetch-bounded — a flood of unknown kids makes at most one upstream fetch per window", async () => {
      startClock();
      advance(30 * 24 * HOUR);
      const k = await signer(`flood-${v.issuer}`);
      served[v.issuer] = [k];
      await v.verify(await k.sign(v.claims()));
      advance(2 * MIN);
      const before = fetchesFor().length;
      const bogus = await Promise.all(
        Array.from({ length: 40 }, (_, i) => signer(`bogus-${i}`).then((s) => s.sign(v.claims()))),
      );
      // Concurrent and sequential, inside one window.
      await Promise.allSettled(bogus.slice(0, 20).map((t) => v.verify(t)));
      for (const t of bogus.slice(20)) await expect(v.verify(t)).rejects.toThrow(/unknown key id/);
      expect(fetchesFor().length - before).toBe(1);
      // The real key still verifies, from cache.
      await expect(v.verify(await k.sign(v.claims()))).resolves.toBeTruthy();
      expect(fetchesFor().length - before).toBe(1);
      // The next window allows one more.
      advance(2 * MIN);
      await expect(v.verify(bogus[0]!)).rejects.toThrow(/unknown key id/);
      expect(fetchesFor().length - before).toBe(2);
    });
  });
}

describe("JwksCache single-flight", () => {
  it("oidc.jwks.refetch-bounded — concurrent callers on a cold issuer share one fetch", async () => {
    let calls = 0;
    let release!: (k: string[]) => void;
    const cache = new JwksCache<string>(
      () => {
        calls++;
        return new Promise<string[]>((r) => (release = r));
      },
      JWKS_POLICY,
      () => 0,
    );
    const all = Promise.all(Array.from({ length: 25 }, () => cache.get("https://cold.test")));
    release(["k1"]);
    expect(await all).toEqual(Array.from({ length: 25 }, () => ["k1"]));
    expect(calls).toBe(1);
  });
});
