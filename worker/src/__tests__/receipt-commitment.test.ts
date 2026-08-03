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
const FACTS = { actorFp: ACTOR_FP, epoch: EPOCH };

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
    ["timestamp_ms", 1_775_000_000_000],
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
    expectCode(() => validateCommitment(new Uint8Array(0), FACTS), "EMPTY_INPUT");
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
      ["timestamp_ms", 1_775_000_000_000],
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
    const input = commitment();
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
    for (const field of ["request_hash", "body_hash", "headers_hash", "actor_fp"]) {
      expectCode(
        () => validateCommitment(commitment({ [field]: new Uint8Array(31) }), FACTS),
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
      expect(() => validateCommitment(commitment({ status }), FACTS)).not.toThrow();
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
