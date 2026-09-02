/**
 * der-integer.test.ts — the epoch must be MINIMALLY encoded, or strict DER
 * parsers cannot read it (notme-229dc3 neighbourhood; found 2026-09-02).
 *
 * HOW THIS WAS FOUND, because it explains why no existing test caught it:
 * a claim-ledger row said "gen/go/verify consumers are unaffected by the
 * identity change". Discharging that row by actually RUNNING the Go verifier
 * against a freshly minted certificate printed `Epoch 0` for a cert minted
 * with epoch 1.
 *
 * `derInteger` emitted a fixed-width `02 04 00 00 00 01`. DER requires the
 * shortest form — `02 01 01` — and Go's encoding/asn1 enforces it, returning
 * "integer not minimally encoded". gen/go/verify swallowed that error and
 * left Epoch at its zero value, so EVERY notme certificate has reported
 * epoch 0 to every Go consumer since the extension was introduced.
 *
 * Epoch is the revocation lever. A consumer that reads it as 0 cannot
 * enforce rotation — the exact class of defect this repo keeps finding: a
 * control that is written, documented, and unreadable by the thing meant to
 * act on it.
 *
 * The round-trip below is deliberately asymmetric: encode with our encoder,
 * decode with a hand-written strict reader that implements DER's rule rather
 * than ours. A fixture produced and checked by the same code proves only
 * self-consistency, which is how this survived.
 */
import { describe, expect, it } from "vitest";
import { certEpoch } from "../auth/verify-proof";
import { derIntegerBytes } from "../cert-authority";

/** Strict DER integer reader — rejects non-minimal encodings, as Go does. */
function strictDerInteger(der: Uint8Array): number {
  if (der[0] !== 0x02) throw new Error("not an INTEGER");
  const len = der[1]!;
  if (len === 0) throw new Error("zero-length INTEGER");
  if (der.length !== 2 + len) throw new Error("length mismatch");
  const body = der.subarray(2);
  // DER §8.3.2: the first nine bits may not all be ones or all be zeros.
  if (len > 1 && body[0] === 0x00 && (body[1]! & 0x80) === 0) {
    throw new Error("integer not minimally encoded");
  }
  if (body[0]! & 0x80) throw new Error("negative not expected");
  let n = 0;
  for (const b of body) n = n * 256 + b;
  return n;
}

describe("derIntegerBytes — minimal DER, which strict parsers require", () => {
  it("encodes small epochs in one byte, not four", () => {
    expect(Array.from(derIntegerBytes(1))).toEqual([0x02, 0x01, 0x01]);
    expect(Array.from(derIntegerBytes(127))).toEqual([0x02, 0x01, 0x7f]);
  });

  it("pads only when the high bit would read as negative", () => {
    // 128 needs a leading zero or it is -128; that zero IS minimal.
    expect(Array.from(derIntegerBytes(128))).toEqual([0x02, 0x02, 0x00, 0x80]);
    expect(Array.from(derIntegerBytes(255))).toEqual([0x02, 0x02, 0x00, 0xff]);
    expect(Array.from(derIntegerBytes(256))).toEqual([0x02, 0x02, 0x01, 0x00]);
  });

  it("encodes zero as a single zero byte", () => {
    expect(Array.from(derIntegerBytes(0))).toEqual([0x02, 0x01, 0x00]);
  });

  it("survives a STRICT reader — the one that rejected the old encoding", () => {
    for (const n of [0, 1, 2, 127, 128, 255, 256, 65535, 16777216, 2147483647]) {
      expect(strictDerInteger(derIntegerBytes(n)), `epoch ${n}`).toBe(n);
    }
  });

  it("still round-trips through OUR reader — both must agree", () => {
    for (const n of [0, 1, 42, 128, 300, 70000]) {
      const ext = { getExtension: () => ({ value: derIntegerBytes(n).buffer }) };
      expect(certEpoch(ext as never), `epoch ${n}`).toBe(n);
    }
  });
});
