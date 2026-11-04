// epoch-history.test.ts — the signed epoch history behind
// /.well-known/epochs.json (notme-6a4f23).
//
// Pure-function tests: the canonical signing input, its golden fixtures in
// schema/fixtures/ (the files a Go verifier such as signet vendors), the
// signature over them, and the verifier rule ADR-019 D7 states for a
// signature made at a trusted time T.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { assertFixtures } from "../../../scripts/fixture-manifest";
import {
  EPOCH_HISTORY_DOMAIN,
  type EpochHistory,
  epochHistoryCanonical,
  epochStatusAt,
  verifyEpochHistorySignature,
} from "../epoch-history";
import { bundleCanonical } from "../revocation";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "../../../schema/fixtures");

/**
 * The fixtures' signing root: the Ed25519 key whose 32-byte seed is
 * 0x00..0x1f. Its public half, standard base64. Documented in
 * schema/fixtures/README.md so a consumer can verify without this file.
 */
const FIXTURE_ROOT_PUB_B64 = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=";

function load(name: string): { doc: EpochHistory; expected: Uint8Array } {
  // No fixture byte is trusted until every file matches SHA256SUMS
  // (notme-1629fe), exactly as bundle-canonical.test.ts loads its vectors.
  assertFixtures(FIXTURES);
  const doc = JSON.parse(readFileSync(join(FIXTURES, `${name}.json`), "utf-8")) as EpochHistory;
  const hex = readFileSync(join(FIXTURES, `${name}.expected.hex`), "utf-8").trim();
  return { doc, expected: new Uint8Array(Buffer.from(hex, "hex")) };
}

const FIXTURE_NAMES = ["epochhistory-basic", "epochhistory-revoked"] as const;

// ── Independent RFC 8949 §4.2 encoder ──────────────────────────────────────
// Written from the RFC, sharing no code with epoch-history.ts, as
// bundle-canonical.test.ts does for the CABundle. Extended with the two
// major types the history uses and the bundle does not: arrays (4) and the
// simple value null (0xf6).
function head(major: number, n: number): number[] {
  const m = major << 5;
  if (n < 24) return [m | n];
  if (n < 0x100) return [m | 24, n];
  if (n < 0x10000) return [m | 25, n >> 8, n & 0xff];
  if (n < 0x100000000) return [m | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
  let v = BigInt(n);
  const out: number[] = [];
  for (let i = 0; i < 8; i++) {
    out.unshift(Number(v & 0xffn));
    v >>= 8n;
  }
  return [m | 27, ...out];
}
const uint = (n: number) => head(0, n);
const text = (s: string) => {
  const b = [...new TextEncoder().encode(s)];
  return [...head(3, b.length), ...b];
};
const bytes = (b64: string) => {
  const b = [...Buffer.from(b64, "base64")];
  return [...head(2, b.length), ...b];
};
const nullable = (n: number | null) => (n === null ? [0xf6] : uint(n));
const array = (items: number[][]) => [...head(4, items.length), ...items.flat()];
function map(entries: Array<[number[], number[]]>): number[] {
  const sorted = [...entries].sort(([a], [b]) => {
    for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
    return a.length - b.length;
  });
  return [...head(5, sorted.length), ...sorted.flatMap(([k, v]) => [...k, ...v])];
}
function refCanonical(d: EpochHistory): Uint8Array {
  return new Uint8Array(
    map([
      [uint(0), text(EPOCH_HISTORY_DOMAIN)],
      [uint(1), uint(d.seqno)],
      [uint(2), uint(d.issuedAt)],
      [uint(3), uint(d.currentEpoch)],
      [
        uint(4),
        array(
          d.epochs.map((e) =>
            map([
              [uint(1), uint(e.epoch)],
              [uint(2), nullable(e.untilEpoch)],
              [uint(3), text(e.keyId)],
              [uint(4), bytes(e.publicRawB64)],
              [uint(5), nullable(e.retiredAt)],
            ]),
          ),
        ),
      ],
      [
        uint(5),
        array(
          d.revocations.map((r) =>
            map([
              [uint(1), uint(r.epoch)],
              [uint(2), uint(r.revokedAt)],
              [uint(3), text(r.reason)],
            ]),
          ),
        ),
      ],
    ]),
  );
}

describe("epoch history canonical form (notme-6a4f23)", () => {
  it("matches every golden fixture byte for byte", () => {
    for (const name of FIXTURE_NAMES) {
      const { doc, expected } = load(name);
      expect(epochHistoryCanonical(doc), name).toEqual(expected);
    }
  });

  it("is re-derived from the fixtures by an encoder written from RFC 8949", () => {
    for (const name of FIXTURE_NAMES) {
      const { doc, expected } = load(name);
      expect(refCanonical(doc), name).toEqual(expected);
    }
  });

  it("excludes the signature, so a signed document re-encodes to the signed bytes", () => {
    const { doc } = load("epochhistory-revoked");
    expect(epochHistoryCanonical({ ...doc, signature: "decoy" })).toEqual(epochHistoryCanonical(doc));
  });

  it("fixtures exercise null, a revocation, a retired key and a live key", () => {
    const { doc } = load("epochhistory-revoked");
    expect(doc.revocations.length).toBeGreaterThan(0);
    expect(doc.epochs.some((e) => e.untilEpoch === null && e.retiredAt === null)).toBe(true);
    expect(doc.epochs.some((e) => typeof e.retiredAt === "number")).toBe(true);
  });

  it("can never equal a CABundle's signing input (domain separation)", () => {
    // Same key signs both. The history leads with map key 0 = the domain
    // string, which no CABundle encoding carries, so a signature over one
    // can never verify as the other.
    const { doc } = load("epochhistory-basic");
    const bundle = {
      epoch: doc.currentEpoch,
      seqno: doc.seqno,
      keys: {},
      keyId: "",
      issuedAt: doc.issuedAt,
    };
    expect(epochHistoryCanonical(doc)).not.toEqual(bundleCanonical(bundle));
    expect(epochHistoryCanonical(doc)[1]).toBe(0x00); // first key: uint 0
  });

  it("refuses a non-integer number rather than signing a float", () => {
    const { doc } = load("epochhistory-basic");
    expect(() => epochHistoryCanonical({ ...doc, seqno: 1.5 })).toThrow();
    expect(() => epochHistoryCanonical({ ...doc, issuedAt: -1 })).toThrow();
  });
});

describe("epoch history signature (notme-6a4f23)", () => {
  it("every fixture's signature verifies under the fixture root", async () => {
    for (const name of FIXTURE_NAMES) {
      const { doc } = load(name);
      expect(await verifyEpochHistorySignature(doc, FIXTURE_ROOT_PUB_B64), name).toBe(true);
    }
  });

  it("a tampered document does not verify", async () => {
    const { doc } = load("epochhistory-revoked");
    const tampered: EpochHistory[] = [
      { ...doc, seqno: doc.seqno + 1 },
      { ...doc, issuedAt: doc.issuedAt + 1 },
      { ...doc, currentEpoch: doc.currentEpoch + 1 },
      // Erase the revocation: the forgery a server-side attacker wants most.
      { ...doc, revocations: [] },
      { ...doc, revocations: doc.revocations.map((r) => ({ ...r, revokedAt: r.revokedAt + 3600 })) },
      { ...doc, revocations: doc.revocations.map((r) => ({ ...r, reason: "rotation" })) },
      { ...doc, epochs: doc.epochs.map((e) => ({ ...e, retiredAt: null })) },
      { ...doc, epochs: doc.epochs.slice(1) },
    ];
    for (const t of tampered) {
      expect(await verifyEpochHistorySignature(t, FIXTURE_ROOT_PUB_B64), JSON.stringify(t)).toBe(false);
    }
  });

  it("does not verify under a different key", async () => {
    const { doc } = load("epochhistory-basic");
    const other = Buffer.alloc(32, 7).toString("base64");
    expect(await verifyEpochHistorySignature(doc, other)).toBe(false);
  });
});

describe("verifier rule at trusted time T (ADR-019 D7, notme-6a4f23)", () => {
  // epochhistory-revoked: epoch 1 revoked at R, current epoch 2.
  const { doc } = load("epochhistory-revoked");
  const R = doc.revocations.find((r) => r.epoch === 1)!.revokedAt;
  const before = R - 1;

  it("accepts a revoked epoch's signature made strictly BEFORE the revocation", () => {
    expect(epochStatusAt(doc, 1, before)).toEqual({ ok: true });
  });

  it("refuses a revoked epoch's signature made AT or after the revocation", () => {
    expect(epochStatusAt(doc, 1, R)).toEqual({ ok: false, reason: "epoch_revoked" });
    expect(epochStatusAt(doc, 1, R + 1)).toEqual({ ok: false, reason: "epoch_revoked" });
  });

  it("strict mode refuses a revoked epoch outright, whatever T", () => {
    expect(epochStatusAt(doc, 1, before, { strict: true })).toEqual({ ok: false, reason: "epoch_revoked" });
    expect(epochStatusAt(doc, 2, before, { strict: true })).toEqual({ ok: true });
  });

  it("accepts the current epoch, and refuses one the authority never reached", () => {
    expect(epochStatusAt(doc, 2, before)).toEqual({ ok: true });
    expect(epochStatusAt(doc, 3, before)).toEqual({ ok: false, reason: "epoch_unknown" });
  });

  it("refuses an ended epoch with no recorded revocation (fail closed)", () => {
    const noRecord = { ...doc, revocations: [] };
    expect(epochStatusAt(noRecord, 1, before)).toEqual({ ok: false, reason: "epoch_end_unrecorded" });
  });

  it("refuses to answer for a T the document was not issued after", () => {
    // A history issued at or before T cannot know of a revocation between
    // its issuedAt and T.
    expect(epochStatusAt(doc, 2, doc.issuedAt)).toEqual({ ok: false, reason: "history_too_old" });
    expect(epochStatusAt(doc, 2, doc.issuedAt - 1)).toEqual({ ok: true });
  });
});
