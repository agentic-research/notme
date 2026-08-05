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
// (vitest.config.ts only includes src/__tests__/**). The legacy tests
// at src/revocation.test.ts use cloudflare:test (DO bindings) and have
// not been wired into vitest's pool — see notme-c38bb6 (P1, "revocation
// tests dead since vitest config carved them out").

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
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

function loadFixture(name: string): {
  bundle: CABundle;
  expected: Uint8Array;
} {
  const input = JSON.parse(
    readFileSync(join(FIXTURES, `${name}.json`), "utf-8"),
  ) as {
    epoch: number;
    seqno: number;
    keys: Record<string, string>;
    keyId: string;
    prevKeyId: string;
    issuedAt: number;
  };
  const hex = readFileSync(join(FIXTURES, `${name}.expected.hex`), "utf-8")
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
});
