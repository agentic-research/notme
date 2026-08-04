/**
 * receipt-commitment.test.ts — the validator that stops /internal/sign-receipt
 * being a forgery oracle on the CA master key (ADR-014).
 *
 * The cases that matter most are the CROSS-PROTOCOL ones. The same Ed25519
 * key signs X.509 TBSCertificate DER and at+jwt access tokens, and the
 * Interlace spec signs the commitment with no domain separator — so "sign
 * these bytes" would let a caller submit a crafted certificate body and
 * assemble one that chains to this authority. Those tests are not
 * hypothetical hygiene; they are the reason this module exists.
 */

import { describe, expect, it } from "vitest";
import { Encoder } from "cbor-x";
import { CommitmentError, validateCommitment } from "../receipts/commitment";

const cbor = new Encoder({
  mapsAsObjects: false,
  useRecords: false,
  tagUint8Array: false,
});

const ACTOR_FP = new Uint8Array(32).fill(0xa1);
const EPOCH = 7;
// Fixed clock so the timestamp bound is exercised deterministically rather
// than depending on when the suite happens to run.
const NOW_MS = 1_775_000_000_000;
const FACTS = { actorFp: ACTOR_FP, epoch: EPOCH, nowMs: NOW_MS };

function digest(fill: number) {
  return new Uint8Array(32).fill(fill);
}

/** A well-formed commitment, in RFC 8949 §4.2 canonical key order. */
function commitment(overrides: Record<string, unknown> = {}) {
  const base = new Map<string, unknown>([
    ["epoch", EPOCH],
    ["nonce", new Uint8Array(16).fill(0x11)],
    ["status", 200],
    ["actor_fp", ACTOR_FP],
    ["body_hash", digest(0xbb)],
    ["headers_hash", digest(0xcc)],
    ["request_hash", digest(0xdd)],
    ["timestamp_ms", NOW_MS],
  ]);
  for (const [k, v] of Object.entries(overrides)) {
    if (v === undefined) base.delete(k);
    else base.set(k, v);
  }
  return new Uint8Array(cbor.encode(base));
}

function expectCode(fn: () => unknown, code: string) {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(CommitmentError);
    expect((e as CommitmentError).code).toBe(code);
    return;
  }
  throw new Error(`expected CommitmentError(${code}), but nothing was thrown`);
}

describe("validateCommitment — cross-protocol forgery (the reason this exists)", () => {
  it("refuses a DER SEQUENCE, i.e. an X.509 TBSCertificate body", () => {
    // 0x30 = ASN.1 SEQUENCE. Every TBSCertificate starts this way. If this
    // were signed, the result assembles into a certificate that
    // derive-credentials.ts verifies against this very key — total CA
    // compromise, for any identity and any scopes.
    const der = new Uint8Array([0x30, 0x82, 0x01, 0x0a, 0x02, 0x01, 0x02]);
    // Rejected at the decode layer (NOT_CBOR) rather than the shape layer:
    // 0x30 is a CBOR text-string head, so the decoder fails before there is
    // anything to inspect. Asserted as CommitmentError rather than a specific
    // code because WHICH layer catches it is an implementation detail — that
    // it is refused before reaching crypto.subtle.sign is the invariant.
    expect(() => validateCommitment(der, FACTS)).toThrow(CommitmentError);
  });

  it("refuses a JWT signing input", () => {
    // `base64url(header).base64url(payload)` — ASCII. Signed, it forges an
    // at+jwt access token for any subject and scope.
    const jwt = new TextEncoder().encode(
      "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJhZG1pbiIsInNjb3BlIjoiYXV0aG9yaXR5TWFuYWdlIn0",
    );
    expect(() => validateCommitment(jwt, FACTS)).toThrow(CommitmentError);
  });

  it("refuses arbitrary bytes", () => {
    const junk = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    expect(() => validateCommitment(junk, FACTS)).toThrow(CommitmentError);
  });

  it("refuses empty input", () => {
    expectCode(
      () => validateCommitment(new Uint8Array(0), FACTS),
      "EMPTY_INPUT",
    );
  });

  it("refuses a CBOR value that is not a map", () => {
    expectCode(
      () => validateCommitment(new Uint8Array(cbor.encode([1, 2, 3])), FACTS),
      "NOT_A_MAP",
    );
  });
});

describe("validateCommitment — canonical-encoding smuggling", () => {
  it("refuses non-canonical key order", () => {
    // Decodes to a structurally valid commitment, but the SIGNED BYTES differ
    // from the canonical encoding. Without the re-encode-and-compare step
    // this passes every structural check while carrying attacker-chosen
    // layout into the signature.
    const scrambled = new Map<string, unknown>([
      ["timestamp_ms", NOW_MS],
      ["nonce", new Uint8Array(16).fill(0x11)],
      ["epoch", EPOCH],
      ["actor_fp", ACTOR_FP],
      ["status", 200],
      ["body_hash", digest(0xbb)],
      ["headers_hash", digest(0xcc)],
      ["request_hash", digest(0xdd)],
    ]);
    expectCode(
      () => validateCommitment(new Uint8Array(cbor.encode(scrambled)), FACTS),
      "NOT_CANONICAL",
    );
  });

  it("accepts the canonical encoding and returns identical bytes", () => {
    // Built BY HAND from §4.2, not with cbor-x. Using an encoder to build the
    // fixture for the encoder under test is a fixed point, not a conformance
    // check — that is exactly how the float64 timestamp bug survived review.
    const input = handEncodeCommitment({});
    const out = validateCommitment(input, FACTS);
    expect(Array.from(out)).toEqual(Array.from(input));
  });
});

describe("validateCommitment — structure", () => {
  it("refuses an extra key", () => {
    // Signed-but-unspecified data: a place to park bytes a verifier ignores
    // and something else interprets.
    expectCode(
      () => validateCommitment(commitment({ extra: 1 }), FACTS),
      "WRONG_KEY_COUNT",
    );
  });

  it("refuses a missing key", () => {
    expectCode(
      () => validateCommitment(commitment({ nonce: undefined }), FACTS),
      "WRONG_KEY_COUNT",
    );
  });

  it("refuses a short nonce", () => {
    expectCode(
      () => validateCommitment(commitment({ nonce: new Uint8Array(8) }), FACTS),
      "NONCE_TOO_SHORT",
    );
  });

  it("refuses a digest field of the wrong length", () => {
    for (const field of [
      "request_hash",
      "body_hash",
      "headers_hash",
      "actor_fp",
    ]) {
      expectCode(
        () =>
          validateCommitment(
            commitment({ [field]: new Uint8Array(31) }),
            FACTS,
          ),
        "FIELD_WRONG_LENGTH",
      );
    }
  });

  it("refuses a text string where bytes are required", () => {
    expectCode(
      () => validateCommitment(commitment({ nonce: "not-bytes" }), FACTS),
      "FIELD_NOT_BYTES",
    );
  });

  it("refuses a non-2xx status", () => {
    // A receipt attests an ADMITTED response. Signing one for a 4xx/5xx
    // manufactures evidence that a request the actor never served succeeded.
    for (const status of [199, 300, 404, 500]) {
      expectCode(
        () => validateCommitment(commitment({ status }), FACTS),
        "STATUS_NOT_2XX",
      );
    }
  });

  it("accepts the 2xx boundaries", () => {
    for (const status of [200, 299]) {
      expect(() =>
        validateCommitment(handEncodeCommitment({ status }), FACTS),
      ).not.toThrow();
    }
  });

  it("refuses a negative or fractional integer field", () => {
    expectCode(
      () => validateCommitment(commitment({ timestamp_ms: -1 }), FACTS),
      "FIELD_NOT_UINT",
    );
    expectCode(
      () => validateCommitment(commitment({ timestamp_ms: 1.5 }), FACTS),
      "FIELD_NOT_UINT",
    );
  });
});

describe("validateCommitment — derived, never received (notme-6ad276)", () => {
  it("refuses an actor_fp that is not this authority's", () => {
    // Otherwise a caller mints receipts attributed to a DIFFERENT actor,
    // signed by this authority's key.
    expectCode(
      () => validateCommitment(commitment({ actor_fp: digest(0xff) }), FACTS),
      "ACTOR_FP_MISMATCH",
    );
  });

  it("refuses an epoch that is not the authority's current one", () => {
    // Otherwise a caller pins a receipt to a retired key epoch, changing
    // which public key a verifier resolves it against.
    expectCode(
      () => validateCommitment(commitment({ epoch: EPOCH + 1 }), FACTS),
      "EPOCH_MISMATCH",
    );
    expectCode(
      () => validateCommitment(commitment({ epoch: EPOCH - 1 }), FACTS),
      "EPOCH_MISMATCH",
    );
  });
});

describe("validateCommitment — timestamp bound (adversarial review of PR #61)", () => {
  it("refuses a backdated timestamp", () => {
    // The attack this closes: a compromised binding holder mints receipts
    // spread across years, each a valid signature over a canonical commitment
    // and each provable evidence that the actor admitted a request it never
    // served. Clamped, the same compromise only yields receipts datable to
    // the window in which the attacker actually held the binding.
    expectCode(
      () =>
        validateCommitment(
          commitment({ timestamp_ms: NOW_MS - 86_400_000 }),
          FACTS,
        ),
      "TIMESTAMP_OUT_OF_RANGE",
    );
  });

  it("refuses a postdated timestamp", () => {
    expectCode(
      () =>
        validateCommitment(
          commitment({ timestamp_ms: NOW_MS + 86_400_000 }),
          FACTS,
        ),
      "TIMESTAMP_OUT_OF_RANGE",
    );
  });

  it("accepts skew a conformant verifier would accept", () => {
    // The bound equals RECEIPTS.md §2.2.1 step 12's ±300s rather than
    // something tighter. A narrower window here would reject receipts every
    // conformant peer would have accepted — a defence that becomes an outage.
    for (const offset of [-299_000, -1000, 0, 1000, 299_000]) {
      expect(() =>
        validateCommitment(
          handEncodeCommitment({ timestampMs: NOW_MS + offset }),
          FACTS,
        ),
      ).not.toThrow();
    }
  });

  it("refuses just outside the window", () => {
    for (const offset of [-300_001, 300_001]) {
      expectCode(
        () =>
          validateCommitment(
            commitment({ timestamp_ms: NOW_MS + offset }),
            FACTS,
          ),
        "TIMESTAMP_OUT_OF_RANGE",
      );
    }
  });
});

describe("canonical encoding conforms to RFC 8949 §4.2, not to cbor-x", () => {
  // These are the tests that were missing. Every fixture above is built with
  // an encoder and validated against the same encoder — a fixed point that
  // ANY self-consistent encoder satisfies, including a wrong one. These build
  // the bytes BY HAND from the spec instead.

  it("accepts the shortest-form uint64 a conformant encoder emits", () => {
    // Go's fxamacker/cbor under CanonicalEncOptions, ciborium, and every other
    // §4.2 encoder emit `0x1b` for a millisecond timestamp. cbor-x emits a
    // float64 and decodes `0x1b` to BigInt, so before the hand-rolled encoder
    // this input was rejected with FIELD_NOT_UINT — i.e. notme refused 100% of
    // conformant callers.
    const ts = 1_775_000_000_000;
    const hand = handEncodeCommitment({ timestampMs: ts });
    expect(hand[hand.length - 9]).toBe(0x1b); // uint64 head, not 0xfb float64
    expect(() =>
      validateCommitment(hand, { ...FACTS, nowMs: ts }),
    ).not.toThrow();
  });

  it("signs bytes containing no float64 — the spec forbids floats outright", () => {
    // RECEIPTS.md §3.1: "Floats and NaN are forbidden … canonical receipt
    // schemas in this spec contain no float fields at all."
    const ts = 1_775_000_000_000;
    const out = validateCommitment(handEncodeCommitment({ timestampMs: ts }), {
      ...FACTS,
      nowMs: ts,
    });
    expect(Array.from(out)).not.toContain(0xfb);
  });

  it("emits the exact byte sequence the spec prescribes", () => {
    // Pins the full encoding, so a future encoder swap cannot silently change
    // what the CA master key signs.
    const ts = 1_775_000_000_000;
    const out = validateCommitment(handEncodeCommitment({ timestampMs: ts }), {
      ...FACTS,
      nowMs: ts,
    });
    expect(out[0]).toBe(0xa8); // map(8), definite length
    expect(Array.from(out.slice(1, 7))).toEqual([
      0x65,
      0x65,
      0x70,
      0x6f,
      0x63,
      0x68, // text(5) "epoch" — first canonical key
    ]);
  });

  it("uses shortest-form integer heads across the size boundaries", () => {
    // 23/24, 255/256, 65535/65536, 2^32-1/2^32 — where a non-shortest or
    // float-promoting encoder diverges.
    for (const [ts, head] of [
      [23, 0x17],
      [24, 0x18],
      [255, 0x18],
      [256, 0x19],
      [65_535, 0x19],
      [65_536, 0x1a],
      [4_294_967_295, 0x1a],
      [4_294_967_296, 0x1b],
    ] as Array<[number, number]>) {
      const hand = handEncodeCommitment({ timestampMs: ts });
      const out = validateCommitment(hand, { ...FACTS, nowMs: ts });
      // timestamp_ms is the last field; its head follows the 12-byte key.
      const keyEnd =
        out.length -
        (head < 0x18
          ? 1
          : head === 0x18
            ? 2
            : head === 0x19
              ? 3
              : head === 0x1a
                ? 5
                : 9);
      expect(out[keyEnd]).toBe(head);
    }
  });
});

/** Build a commitment BY HAND from RFC 8949 §4.2, with no encoder involved. */
function handEncodeCommitment(opts: {
  timestampMs?: number;
  status?: number;
}): Uint8Array {
  const parts: number[] = [0xa8]; // map(8)
  const text = (s: string) => {
    const b = [...new TextEncoder().encode(s)];
    return [0x60 | b.length, ...b];
  };
  const bytes = (b: Uint8Array) => [0x58, b.byteLength, ...b];
  const uint = (v: number) => {
    if (v < 24) return [v];
    if (v < 0x100) return [0x18, v];
    if (v < 0x10000) return [0x19, v >> 8, v & 0xff];
    if (v < 0x100000000) {
      return [
        0x1a,
        (v >>> 24) & 0xff,
        (v >>> 16) & 0xff,
        (v >>> 8) & 0xff,
        v & 0xff,
      ];
    }
    const bv = BigInt(v);
    const out = [0x1b];
    for (let i = 7; i >= 0; i--)
      out.push(Number((bv >> BigInt(i * 8)) & 0xffn));
    return out;
  };
  // 16-byte nonce uses the 0x50 short form, not 0x58.
  const shortBytes = (b: Uint8Array) => [0x40 | b.byteLength, ...b];

  parts.push(...text("epoch"), ...uint(EPOCH));
  parts.push(...text("nonce"), ...shortBytes(new Uint8Array(16).fill(0x11)));
  parts.push(...text("status"), ...uint(opts.status ?? 200));
  parts.push(...text("actor_fp"), ...bytes(ACTOR_FP));
  parts.push(...text("body_hash"), ...bytes(digest(0xbb)));
  parts.push(...text("headers_hash"), ...bytes(digest(0xcc)));
  parts.push(...text("request_hash"), ...bytes(digest(0xdd)));
  parts.push(...text("timestamp_ms"), ...uint(opts.timestampMs ?? NOW_MS));
  return new Uint8Array(parts);
}
