// bundle-canonical.test.ts — pure-function tests for bundleCanonical.
//
// Per ADR-010 + signet ADR-002 §2.3: canonical bytes are CBOR canonical
// (RFC 8949 §4.2), integer-keyed map matching
// signet/pkg/revocation/checker.go:168-188:
//   1=Epoch, 2=Seqno, 3=Keys, 4=KeyID, 5=PrevKeyID, 6=IssuedAt.
//
// Signature field (would be 7) is NOT included in the signing input.
//
// These tests live under src/__tests__/ so they actually run in CI
// (vitest.config.ts only includes src/__tests__/**). The DO-backed
// revocation tests now run under the workers pool as
// src/revocation.do.test.ts (`pnpm test:do`); notme-c38bb6 flagged the
// original dead-test gap and is closed.

import { cpSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { assertFixtures } from "../../../scripts/fixture-manifest";
import { type CABundle, bundleCanonical } from "../revocation";

// The ADR-010 cross-implementation fixture gate (notme-e9d2b8). The input
// bundles and expected canonical bytes live in schema/fixtures/ as
// language-neutral files so signet (Go) and ley-line-open (Rust) consume the
// SAME fixtures instead of hand-copying hex between test files — the drift
// mode that silently breaks signature verification across implementations.
const FIXTURES = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../schema/fixtures",
);

function loadFixture(
  name: string,
  dir: string = FIXTURES,
): {
  bundle: CABundle;
  expected: Uint8Array;
} {
  // The integrity anchor (notme-1629fe): no fixture byte is trusted until
  // every file in the dir matches schema/fixtures/SHA256SUMS and each .bin
  // equals its .expected.hex. Checked BEFORE parsing, so a vector edited in
  // step with the encoder is refused here rather than compared and accepted.
  assertFixtures(dir);
  const input = JSON.parse(
    readFileSync(join(dir, `${name}.json`), "utf-8"),
  ) as {
    epoch: number;
    seqno: number;
    keys: Record<string, string>;
    keyId: string;
    prevKeyId: string;
    issuedAt: number;
  };
  const hex = readFileSync(join(dir, `${name}.expected.hex`), "utf-8")
    .trim()
    .replace(/\s+/g, "");
  const expected = new Uint8Array(
    hex.match(/.{2}/g)!.map((b) => parseInt(b, 16)),
  );
  // signature is part of the wire type but excluded from the signing input;
  // fixtures deliberately omit it and the test supplies a decoy to prove
  // the exclusion.
  return { bundle: { ...input, signature: "ignored" }, expected };
}

function makeBundle(overrides: Partial<CABundle> = {}): CABundle {
  return {
    epoch: 1,
    seqno: 1,
    keys: { kid1: btoa("\x00".repeat(32)) },
    keyId: "kid1",
    prevKeyId: "",
    issuedAt: 1700000000,
    signature: "",
    ...overrides,
  };
}

describe("bundleCanonical (CBOR canonical, RFC 8949 §4.2)", () => {
  it("emits a 6-entry CBOR map (signature field excluded)", () => {
    const bundle = makeBundle({ signature: "abc123" });
    const canonical = bundleCanonical(bundle);
    // CBOR major type 5 = map; immediate value 6 = six entries → byte 0xa6.
    expect(canonical[0]).toBe(0xa6);
  });

  it("is deterministic — same input → same bytes (RFC 8949 §4.2)", () => {
    const bundle = makeBundle();
    expect(bundleCanonical(bundle)).toEqual(bundleCanonical(bundle));
  });

  it("is independent of TS field insertion order", () => {
    const a = makeBundle();
    const b: CABundle = {
      signature: a.signature,
      keyId: a.keyId,
      epoch: a.epoch,
      seqno: a.seqno,
      keys: a.keys,
      prevKeyId: a.prevKeyId,
      issuedAt: a.issuedAt,
    };
    expect(bundleCanonical(a)).toEqual(bundleCanonical(b));
  });

  it("encodes prevKeyId='' rather than omitting it (matches signet string zero value)", () => {
    const noPrev = makeBundle({ prevKeyId: undefined });
    const emptyPrev = makeBundle({ prevKeyId: "" });
    expect(bundleCanonical(noPrev)).toEqual(bundleCanonical(emptyPrev));
  });

  it("matches a hand-computed CBOR fixture (locks in cross-runtime byte shape)", () => {
    // Fixture: epoch=1, seqno=1, keys={"kid": h'abcd'},
    //          keyId="kid", prevKeyId="", issuedAt=1234.
    // Hand-computed RFC 8949 §4.2 canonical encoding (25 bytes):
    //   a6                          map(6)
    //     01 01                     1 → 1
    //     02 01                     2 → 1
    //     03 a1 63 6b6964 42 abcd   3 → {"kid": h'abcd'}
    //     04 63 6b6964              4 → "kid"
    //     05 60                     5 → ""
    //     06 19 04d2                6 → 1234
    //
    // The same fixture, encoded by signet's
    //   cbor.CanonicalEncOptions().EncMode().Marshal(map[int]interface{}{
    //     1:uint64(1), 2:uint64(1),
    //     3:map[string][]byte{"kid":{0xab,0xcd}},
    //     4:"kid", 5:"", 6:int64(1234),
    //   })
    // produces the same 25 bytes. The bytes live in schema/fixtures/ (the
    // ADR-010 mandated gate, notme-e9d2b8) so the Go/Rust sides consume the
    // SAME files rather than a hand-copied hex literal.
    const { bundle, expected } = loadFixture("cabundle-basic");
    expect(bundleCanonical(bundle)).toEqual(expected);
  });

  it("sorts multi-key keys map per RFC 8949 §4.2 (length-then-bytewise, NOT alphabetical)", () => {
    // Keys map with two entries chosen specifically to expose the
    // canonical ordering rule: "b" (length 1) and "ab" (length 2).
    //
    // RFC 8949 §4.2 says map keys MUST be sorted "in the bytewise
    // lexicographic order of their deterministic encodings." For text
    // strings, the encoding is length-prefixed, so the rule reduces to:
    // shorter strings first; equal-length strings compared bytewise.
    //
    // Naive alphabetical sort would put "ab" before "b" (a < b).
    // Canonical sort puts "b" before "ab" (length 1 < length 2).
    //
    // If sortStringKeysCanonical regresses to plain alphabetical or
    // skips sorting, this fixture catches it. JSON key order in the fixture
    // file is intentionally reversed ("ab" before "b") so a pass can only
    // come from sorting, never from insertion order.
    const { bundle, expected } = loadFixture("cabundle-multikey");
    expect(bundleCanonical(bundle)).toEqual(expected);
  });

  it("sorts equal-length kids bytewise: the branch production takes (notme-32270b)", () => {
    // Real kids are lowercasehex(SHA-256(SPKI)[:16]) (key-id.ts): ALWAYS 32
    // chars. cabundle-multikey ("ab" vs "b") is decided on the LENGTH branch of
    // sortStringKeysCanonical, which a real bundle never reaches; this fixture
    // is decided only by the bytewise tiebreak. It is also the rotation-grace
    // state generateBundle emits: two keys, prevKeyId set, a 32-byte key value.
    const { bundle, expected } = loadFixture("cabundle-rotation");
    const kids = Object.keys(bundle.keys);

    // Shape pins, so the fixture cannot quietly stop exercising the branch.
    expect(kids).toHaveLength(2);
    expect(kids.every((k) => /^[0-9a-f]{32}$/.test(k))).toBe(true);
    expect(bundle.prevKeyId).toMatch(/^[0-9a-f]{32}$/);
    expect(kids).toContain(bundle.prevKeyId);
    expect(kids).toContain(bundle.keyId);
    expect(bundle.keyId).not.toBe(bundle.prevKeyId);
    // JSON order is the REVERSE of canonical, so only sorting can pass.
    expect(kids).not.toEqual([...kids].sort());

    expect(bundleCanonical(bundle)).toEqual(expected);
  });
});

// --- notme-1629fe: the fixture gate's integrity anchor -----------------------
//
// The golden vectors above are the encoder's own output restated as a file, so
// on their own they only catch an ACCIDENTAL encoder change. Two things below
// make them a gate rather than a mirror:
//
//   1. Every fixture file is pinned by SHA-256 in schema/fixtures/SHA256SUMS,
//      and loadFixture refuses to hand out bytes until the manifest checks out
//      (including .bin == hex_decode(.expected.hex), which nothing used to
//      read). An encoder change now needs a three-file diff (encoder, vector,
//      manifest) that names itself and hits CODEOWNERS on schema/fixtures/.
//   2. An independent RFC 8949 §4.2 encoder, written from the RFC and sharing
//      no code with revocation.ts, re-derives both vectors from their .json
//      and agrees with bundleCanonical over generated bundles. It does not
//      share the encoder's provenance, so a paired encoder+vector edit fails
//      here even if the manifest is updated too.

/** Copy the fixture dir somewhere disposable so a test can tamper with it. */
function fixtureCopy(): string {
  const dir = mkdtempSync(join(tmpdir(), "notme-fixtures-"));
  cpSync(FIXTURES, dir, { recursive: true });
  return dir;
}

describe("fixture integrity anchor (notme-1629fe)", () => {
  it("accepts the committed fixtures", () => {
    expect(() => loadFixture("cabundle-basic")).not.toThrow();
    expect(() => loadFixture("cabundle-multikey")).not.toThrow();
    expect(() => loadFixture("cabundle-rotation")).not.toThrow();
  });

  it("refuses a fixture whose .bin was edited (the file a Go/Rust consumer reads)", () => {
    const dir = fixtureCopy();
    const bin = readFileSync(join(dir, "cabundle-basic.bin"));
    bin[bin.length - 1] ^= 0x01;
    writeFileSync(join(dir, "cabundle-basic.bin"), bin);
    expect(() => loadFixture("cabundle-basic", dir)).toThrow(/cabundle-basic\.bin/);
  });

  it("refuses a fixture whose .expected.hex was edited, before any encoder comparison", () => {
    // The paired-edit attack: change the encoder AND the vector. Simulated by
    // editing the vector alone and asserting the gate rejects it on the
    // manifest, not on a comparison with an encoder the attacker also edited.
    const dir = fixtureCopy();
    const p = join(dir, "cabundle-multikey.expected.hex");
    const hex = readFileSync(p, "utf-8").trim();
    writeFileSync(p, `${hex.slice(0, -1)}${hex.endsWith("0") ? "1" : "0"}\n`);
    expect(() => loadFixture("cabundle-multikey", dir)).toThrow(
      /cabundle-multikey\.expected\.hex/,
    );
  });

  it("refuses a fixture whose .json input was edited", () => {
    const dir = fixtureCopy();
    const p = join(dir, "cabundle-basic.json");
    writeFileSync(p, readFileSync(p, "utf-8").replace('"seqno": 1', '"seqno": 2'));
    expect(() => loadFixture("cabundle-basic", dir)).toThrow(/cabundle-basic\.json/);
  });

  it("refuses a fixture file that the manifest does not pin", () => {
    const dir = fixtureCopy();
    writeFileSync(join(dir, "cabundle-extra.bin"), new Uint8Array([0xa0]));
    expect(() => loadFixture("cabundle-basic", dir)).toThrow(/cabundle-extra\.bin/);
  });
});

// Independent RFC 8949 §4.2 deterministic encoder, restricted to the CABundle
// shape (unsigned/negative ints, text, bytes, maps). Written from the RFC, not
// from revocation.ts: map entries are ordered by the bytewise lexicographic
// order of each key's ENCODED form (§4.2.1), the literal rule, rather than the
// length-then-bytewise shortcut bundleCanonical uses.
function refHead(major: number, n: number): number[] {
  const m = major << 5;
  if (n < 24) return [m | n];
  if (n < 0x100) return [m | 24, n];
  if (n < 0x10000) return [m | 25, n >> 8, n & 0xff];
  if (n < 0x100000000) {
    return [m | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
  }
  let v = BigInt(n);
  const bytes: number[] = [];
  for (let i = 0; i < 8; i++) {
    bytes.unshift(Number(v & 0xffn));
    v >>= 8n;
  }
  return [m | 27, ...bytes];
}

const refInt = (n: number): number[] => (n >= 0 ? refHead(0, n) : refHead(1, -1 - n));

function refText(s: string): number[] {
  const b = [...new TextEncoder().encode(s)];
  return [...refHead(3, b.length), ...b];
}

const refBytes = (b: Uint8Array): number[] => [...refHead(2, b.length), ...b];

function refMap(entries: Array<[number[], number[]]>): number[] {
  const sorted = [...entries].sort(([a], [b]) => {
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      if (a[i] !== b[i]) return a[i] - b[i];
    }
    return a.length - b.length;
  });
  return [...refHead(5, sorted.length), ...sorted.flatMap(([k, v]) => [...k, ...v])];
}

function refCanonical(b: Omit<CABundle, "signature">): Uint8Array {
  const keys = refMap(
    Object.entries(b.keys).map(([kid, b64]): [number[], number[]] => [
      refText(kid),
      refBytes(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))),
    ]),
  );
  return new Uint8Array(
    refMap([
      [refInt(1), refInt(b.epoch)],
      [refInt(2), refInt(b.seqno)],
      [refInt(3), keys],
      [refInt(4), refText(b.keyId)],
      [refInt(5), refText(b.prevKeyId ?? "")],
      [refInt(6), refInt(b.issuedAt)],
    ]),
  );
}

/** mulberry32 — a fixed seed keeps any failure reproducible. */
function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

describe("independent RFC 8949 §4.2 derivation (notme-1629fe)", () => {
  it("re-derives every golden vector from their .json without bundleCanonical", () => {
    for (const name of ["cabundle-basic", "cabundle-multikey", "cabundle-rotation"]) {
      const { bundle, expected } = loadFixture(name);
      expect(refCanonical(bundle), name).toEqual(expected);
    }
  });

  it("agrees with bundleCanonical over generated key maps (key-ordering property)", () => {
    const rand = prng(0x1629fe);
    const pick = <T,>(xs: readonly T[]): T => xs[Math.floor(rand() * xs.length)];
    // Digits are deliberate: JS orders integer-like object keys numerically
    // ahead of the rest, which is neither insertion nor canonical order.
    // Multi-byte chars make UTF-8 length differ from string length.
    const alphabet = ["a", "b", "z", "A", "0", "1", "9", "-", "_", "é", "ß", "€", "😀"];
    const ints = [0, 1, 23, 24, 255, 256, 65535, 65536, 0xffffffff, 1700000000];
    const randInt = () => (rand() < 0.5 ? pick(ints) : Math.floor(rand() * 0x100000000));
    for (let i = 0; i < 500; i++) {
      const keys: Record<string, string> = {};
      const nKeys = Math.floor(rand() * 8);
      for (let k = 0; k < nKeys; k++) {
        let kid = "";
        // some keys run long enough to cross the 24-byte text-header boundary
        const len = Math.floor(rand() * (rand() < 0.2 ? 30 : 5));
        for (let c = 0; c < len; c++) kid += pick(alphabet);
        const val = new Uint8Array(Math.floor(rand() * 40));
        for (let v = 0; v < val.length; v++) val[v] = Math.floor(rand() * 256);
        keys[kid] = btoa(String.fromCharCode(...val));
      }
      const bundle = makeBundle({
        epoch: randInt(),
        seqno: randInt(),
        keys,
        keyId: Object.keys(keys)[0] ?? "",
        prevKeyId: rand() < 0.5 ? "" : pick(alphabet),
        issuedAt: randInt(),
      });
      expect(bundleCanonical(bundle), JSON.stringify(bundle)).toEqual(refCanonical(bundle));
    }
  });
});
