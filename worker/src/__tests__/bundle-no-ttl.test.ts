/**
 * bundle-no-ttl.test.ts — the Worker must never give `bundle:current` a KV TTL.
 *
 * checkRevocation treats a STALE bundle and an ABSENT one oppositely: stale
 * fails closed (`bundle_stale`), absent fails open (the bootstrap case,
 * revocation.ts). The DO's #publishBundle writes the key with no TTL for
 * exactly that reason (rotate-publishes-bundle.do.test.ts pins it). The
 * Worker's own lazy write in ensureCurrentCABundle used `expirationTtl: 60`,
 * so once the refresh alarm stopped, the key the Worker last wrote expired
 * out of KV a minute later, and from then on every revoked certificate was
 * accepted.
 *
 * The fake KV below honours expirationTtl against the (fake) clock, as KV
 * does, so the test observes the expiry rather than asserting an option.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { __resetCABundleMemoForTests, ensureCurrentCABundle } from "../internal-ca-bundle";
import type { Platform } from "../platform";
import { type CABundle, checkRevocation } from "../revocation";

function expiringKv() {
  const rows = new Map<string, { value: string; expiresAt: number | null }>();
  const live = (k: string) => {
    const r = rows.get(k);
    if (!r) return null;
    if (r.expiresAt !== null && Date.now() >= r.expiresAt) {
      rows.delete(k);
      return null;
    }
    return r.value;
  };
  return {
    rows,
    async get(k: string, type?: string) {
      const v = live(k);
      return v !== null && type === "json" ? JSON.parse(v) : v;
    },
    async put(k: string, value: string, opts?: { expirationTtl?: number }) {
      rows.set(k, { value, expiresAt: opts?.expirationTtl ? Date.now() + opts.expirationTtl * 1000 : null });
    },
  };
}

afterEach(() => {
  vi.useRealTimers();
  __resetCABundleMemoForTests();
});

describe("bundle.kv.no-ttl — bundle:current never expires out of KV", () => {
  it("with the alarm stopped, a revoked certificate is still refused after the Worker's write would have expired", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-05T00:00:00Z"));
    const kv = expiringKv();
    // The epoch-2 bundle a revocation produced; the token below is from epoch 1.
    const revokedEpochBundle: CABundle = {
      epoch: 2,
      seqno: 7,
      keys: { active: "cHVibGljLWtleQ==" },
      keyId: "active",
      issuedAt: Math.floor(Date.now() / 1000),
      signature: "c2lnbmF0dXJl",
    };
    const env = {
      SIGNING_AUTHORITY: { idFromName: () => "id", get: () => ({ generateBundle: async () => revokedEpochBundle }) },
    };
    const platform = { keyStorage: "ephemeral", cache: kv } as unknown as Platform;
    await ensureCurrentCABundle(env, platform); // KV empty: the Worker generates and writes it

    // The alarm is dead: nothing writes the key again. Six minutes on, the
    // bundle is past BUNDLE_MAX_AGE_MS — and still in KV, so it fails CLOSED.
    vi.setSystemTime(Date.now() + 6 * 60 * 1000);
    expect(kv.rows.has("bundle:current")).toBe(true);
    const result = await checkRevocation(
      { keyId: "active", epoch: 1 },
      { CA_BUNDLE_CACHE: kv as unknown as KVNamespace, REVOCATION: {} as DurableObjectNamespace },
      "unused-before-the-staleness-check",
    );
    expect(result).toEqual({ revoked: true, reason: "bundle_stale" });
  });

  it("no write the Worker makes carries a TTL", async () => {
    const kv = expiringKv();
    const env = {
      SIGNING_AUTHORITY: {
        idFromName: () => "id",
        get: () => ({
          generateBundle: async (): Promise<CABundle> => ({
            epoch: 1,
            seqno: 1,
            keys: { a: "eA==" },
            keyId: "a",
            issuedAt: Math.floor(Date.now() / 1000),
            signature: "eA==",
          }),
        }),
      },
    };
    await ensureCurrentCABundle(env, { keyStorage: "ephemeral", cache: kv } as unknown as Platform);
    expect(kv.rows.get("bundle:current")?.expiresAt).toBeNull();
  });
});
