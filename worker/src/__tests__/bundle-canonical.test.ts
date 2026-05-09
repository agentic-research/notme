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
// not been wired into vitest's pool — see notme-XXX (revocation tests
// dead since vitest config carved them out).

import { describe, expect, it } from "vitest";
import { type CABundle, bundleCanonical } from "../revocation";

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
    // produces the same 25 bytes. A future bead adds a Go-side test that
    // emits this fixture; this test then becomes the cross-runtime gate.
    const bundle: CABundle = {
      epoch: 1,
      seqno: 1,
      keys: { kid: btoa("\xab\xcd") }, // base64-standard of bytes [0xab, 0xcd]
      keyId: "kid",
      prevKeyId: "",
      issuedAt: 1234,
      signature: "ignored",
    };
    const expected = new Uint8Array([
      0xa6,
      0x01, 0x01,
      0x02, 0x01,
      0x03, 0xa1, 0x63, 0x6b, 0x69, 0x64, 0x42, 0xab, 0xcd,
      0x04, 0x63, 0x6b, 0x69, 0x64,
      0x05, 0x60,
      0x06, 0x19, 0x04, 0xd2,
    ]);
    expect(bundleCanonical(bundle)).toEqual(expected);
  });
});
