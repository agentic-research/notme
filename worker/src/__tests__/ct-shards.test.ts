/**
 * ct-shards.test.ts — the shard set the authority logs to (notme-afa9d8).
 *
 * Pure: parseShards / selectShard / notAfterOf have no DO or Worker imports.
 * The CT-pool suite (ct-mint.do.test.ts, "ct.shards") checks the same rules
 * end to end against a two-shard stub log.
 */
import { createHash, generateKeyPairSync } from "node:crypto";
import * as x509 from "@peculiar/x509";
import { describe, expect, it } from "vitest";
import {
  parseShards,
  selectShard,
  shardEndHealth,
  SHARD_WARN_DAYS,
  type CtShard,
} from "../ct/shards";
import { notAfterOf } from "../ct/verify-sct";

function logKey(): { log_id: string; key: string } {
  const spki = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({
    type: "spki",
    format: "der",
  });
  return { key: spki.toString("base64"), log_id: createHash("sha256").update(spki).digest("base64") };
}
const A = logKey();
const B = logKey();

const shard = (
  path: string,
  k: { log_id: string; key: string },
  start: string,
  end: string,
) => ({ path, ...k, temporal_interval: { start_inclusive: start, end_exclusive: end } });

const TWO = [
  shard("/logs/notme", A, "2026-07-01T00:00:00Z", "2027-07-01T00:00:00Z"),
  shard("/logs/notme2027h2", B, "2027-07-01T00:00:00Z", "2028-01-01T00:00:00Z"),
];

async function ok(env: Parameters<typeof parseShards>[0]): Promise<CtShard[]> {
  const r = await parseShards(env);
  if ("error" in r) throw new Error(r.error);
  return r.shards;
}
async function err(env: Parameters<typeof parseShards>[0]): Promise<string> {
  const r = await parseShards(env);
  if (!("error" in r)) throw new Error("expected an error");
  return r.error;
}

describe("parseShards — the single pin, unchanged", () => {
  it("CT_LOG_ID / CT_LOG_KEY alone are one shard with no interval, at CT_LOG_PATH or the default", async () => {
    const [s, ...rest] = await ok({ CT_LOG_ID: A.log_id, CT_LOG_KEY: A.key });
    expect(rest).toEqual([]);
    expect(s!.path).toBe("/logs/notme");
    expect(s!.pin.id).toBe(A.log_id);
    expect(s!.startMs).toBe(Number.NEGATIVE_INFINITY);
    expect(s!.endMs).toBe(Number.POSITIVE_INFINITY);
    const [p] = await ok({ CT_LOG_ID: A.log_id, CT_LOG_KEY: A.key, CT_LOG_PATH: "/logs/other" });
    expect(p!.path).toBe("/logs/other");
  });

  it("the single pin's own errors are reported as before", async () => {
    expect(await err({ CT_LOG_KEY: A.key })).toBe("CT_LOG_ID missing");
    expect(await err({ CT_LOG_ID: A.log_id })).toBe("CT_LOG_KEY missing");
    expect(await err({ CT_LOG_ID: B.log_id, CT_LOG_KEY: A.key })).toBe(
      "CT_LOG_ID is not SHA-256(CT_LOG_KEY)",
    );
  });
});

describe("parseShards — CT_LOG_SHARDS", () => {
  it("parses a JSON string, and an already-parsed array (a wrangler [vars] table)", async () => {
    for (const v of [JSON.stringify(TWO), TWO]) {
      const s = await ok({ CT_LOG_SHARDS: v });
      expect(s.map((x) => x.path)).toEqual(["/logs/notme", "/logs/notme2027h2"]);
      expect(s[0]!.startMs).toBe(Date.parse("2026-07-01T00:00:00Z"));
      expect(s[0]!.endMs).toBe(Date.parse("2027-07-01T00:00:00Z"));
      expect(s[1]!.pin.id).toBe(B.log_id);
    }
  });

  it("is refused alongside any single-pin variable: two sources for one pin", async () => {
    for (const extra of [{ CT_LOG_ID: A.log_id }, { CT_LOG_KEY: A.key }, { CT_LOG_PATH: "/logs/notme" }]) {
      expect(await err({ CT_LOG_SHARDS: TWO, ...extra })).toMatch(/not both/);
    }
  });

  const bad: Array<[string, unknown, RegExp]> = [
    ["not JSON", "[{", /not JSON/],
    ["not an array", JSON.stringify({ a: 1 }), /non-empty array/],
    ["empty", "[]", /non-empty array/],
    ["a bad path", [shard("logs/x", A, "2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z")], /\[0\].*path/],
    ["a trailing slash", [shard("/logs/x/", A, "2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z")], /\[0\].*path/],
    ["a bad key", [{ ...TWO[0], key: "not base64!" }], /\[0\].*CT_LOG_KEY is not base64/],
    ["an id that is not the key's", [{ ...TWO[0], log_id: B.log_id }], /\[0\].*not SHA-256/],
    ["no interval", [{ path: "/logs/x", ...A }], /\[0\].*temporal_interval/],
    ["a non-UTC time", [shard("/logs/x", A, "2026-01-01T00:00:00+01:00", "2026-06-01T00:00:00Z")], /\[0\].*start_inclusive/],
    ["start not before end", [shard("/logs/x", A, "2026-06-01T00:00:00Z", "2026-06-01T00:00:00Z")], /\[0\].*before/],
    ["a duplicate path", [TWO[0], { ...TWO[1], path: "/logs/notme" }], /\[1\].*path .* twice/],
    ["a duplicate log", [TWO[0], { ...TWO[1], ...A }], /\[1\].*log_id .* twice/],
    [
      "overlapping intervals",
      [TWO[0], shard("/logs/b", B, "2027-06-30T23:59:59Z", "2028-01-01T00:00:00Z")],
      /overlap/,
    ],
  ];
  for (const [label, v, want] of bad) {
    it(`refuses ${label}, naming CT_LOG_SHARDS`, async () => {
      const e = await err({ CT_LOG_SHARDS: v as string });
      expect(e).toMatch(/^CT_LOG_SHARDS/);
      expect(e).toMatch(want);
    });
  }

  it("adjacent intervals (one's end is the next's start) do not overlap", async () => {
    expect(await ok({ CT_LOG_SHARDS: TWO })).toHaveLength(2);
  });
});

describe("selectShard — notAfter in [start_inclusive, end_exclusive)", () => {
  it("picks the one shard whose interval holds the instant, inclusive start and exclusive end", async () => {
    const s = await ok({ CT_LOG_SHARDS: [TWO[1], TWO[0]] }); // order in the config does not matter
    const end = Date.parse("2027-07-01T00:00:00Z");
    expect(selectShard(s, end - 1)?.path).toBe("/logs/notme");
    expect(selectShard(s, end)?.path).toBe("/logs/notme2027h2");
    expect(selectShard(s, Date.parse("2026-07-01T00:00:00Z"))?.path).toBe("/logs/notme");
  });

  it("returns null outside every shard, and for a NaN instant", async () => {
    const s = await ok({ CT_LOG_SHARDS: TWO });
    expect(selectShard(s, Date.parse("2026-06-30T23:59:59Z"))).toBeNull();
    expect(selectShard(s, Date.parse("2028-01-01T00:00:00Z"))).toBeNull();
    expect(selectShard(s, Number.NaN)).toBeNull();
  });

  it("the single pin covers every instant", async () => {
    const s = await ok({ CT_LOG_ID: A.log_id, CT_LOG_KEY: A.key });
    expect(selectShard(s, 0)?.path).toBe("/logs/notme");
    expect(selectShard(s, Date.parse("2999-01-01T00:00:00Z"))?.path).toBe("/logs/notme");
  });
});

describe("notAfterOf — the certificate's own notAfter", () => {
  async function cert(notAfter: Date): Promise<Uint8Array> {
    const alg = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
    const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
    const c = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: "01",
      name: "CN=t",
      notBefore: new Date("2026-01-01T00:00:00Z"),
      notAfter,
      keys,
      signingAlgorithm: alg,
    });
    return new Uint8Array(c.rawData);
  }

  it("reads UTCTime (before 2050) to the second", async () => {
    const t = new Date("2027-06-30T23:59:59Z");
    expect(notAfterOf(await cert(t))).toBe(t.getTime());
  });

  it("reads GeneralizedTime (2050 on)", async () => {
    const t = new Date("2061-02-03T04:05:06Z");
    expect(notAfterOf(await cert(t))).toBe(t.getTime());
  });

  it("throws on bytes that are not a certificate", () => {
    expect(() => notAfterOf(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x00]))).toThrow();
  });
});

describe("shardEndHealth — warn before the newest shard closes (notme-a806d0)", () => {
  // A pinned clock: the function takes `now`, so nothing reads the real time.
  const DAY = 24 * 60 * 60 * 1000;
  const END = Date.parse("2027-07-01T00:00:00Z");
  const before = (days: number) => END - days * DAY;

  it("the threshold is 60 days", () => {
    expect(SHARD_WARN_DAYS).toBe(60);
  });

  it("reports the NEWEST shard's end, whatever the config order", async () => {
    const s = await ok({ CT_LOG_SHARDS: [TWO[1], TWO[0]] });
    const h = shardEndHealth(s, Date.parse("2027-06-01T00:00:00Z"));
    expect(h.shardEndsAt).toBe("2028-01-01T00:00:00.000Z");
    expect(h.shardClosingSoon).toBe(false);
  });

  it("closing soon strictly inside 60 days, not at exactly 60", async () => {
    const s = await ok({ CT_LOG_SHARDS: [TWO[0]] });
    expect(shardEndHealth(s, before(60))).toEqual({
      shardEndsAt: "2027-07-01T00:00:00.000Z",
      shardEndsInDays: 60,
      shardClosingSoon: false,
    });
    const h = shardEndHealth(s, before(60) + 1);
    expect(h.shardEndsInDays).toBe(59);
    expect(h.shardClosingSoon).toBe(true);
    expect(shardEndHealth(s, before(200))).toMatchObject({ shardEndsInDays: 200, shardClosingSoon: false });
  });

  it("stays closing-soon, with a zero or negative day count, once the newest shard has closed", async () => {
    const s = await ok({ CT_LOG_SHARDS: [TWO[0]] });
    expect(shardEndHealth(s, END)).toMatchObject({ shardEndsInDays: 0, shardClosingSoon: true });
    expect(shardEndHealth(s, END + 3 * DAY)).toMatchObject({ shardEndsInDays: -3, shardClosingSoon: true });
  });

  it("the single pin has no interval: null, never closing", async () => {
    const s = await ok({ CT_LOG_ID: A.log_id, CT_LOG_KEY: A.key });
    expect(shardEndHealth(s, END)).toEqual({ shardEndsAt: null, shardEndsInDays: null, shardClosingSoon: false });
  });
});
