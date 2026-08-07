/**
 * receipt-delegation.test.ts — a receipt may carry WHO WAS ACTING UNDER WHOSE
 * DELEGATION (notme-9f84e6, ADR-014).
 *
 * THE GAP THIS CLOSES. The Interlace 0.2.0 commitment has eight fields —
 * `nonce`, `request_hash`, `body_hash`, `headers_hash`, `status`,
 * `timestamp_ms`, `actor_fp`, `epoch`. Every one describes WHAT WAS ASKED or
 * WHICH AUTHORITY ANSWERED. None names the acting principal or the delegation
 * it acted under. So a receipt proves a request occurred and was signed by
 * this authority, and cannot answer "on whose behalf" — which is the question
 * an incident actually asks, and the one revocation needs an answer to before
 * "revoke this machine's tasks" can enumerate anything.
 *
 * ── WHY THE FIELD IS OPTIONAL RATHER THAN ADDED TO THE SCHEMA ──
 * `validateCommitment` rejects anything that is not EXACTLY eight keys, and
 * cloister's verifier implements the same 0.2.0 shape. Adding a ninth key
 * unconditionally would invalidate every receipt notme mints for every
 * existing verifier — a unilateral break of a spec another repo owns.
 *
 * So the caller OPTS IN by sending the field, and notme accepts either shape.
 * A 0.2.0 verifier keeps working because nothing changes for callers that do
 * not send it, and a caller only sends it when it knows its verifier
 * understands it. Compatibility stays where the knowledge is.
 *
 * ── WHY IT IS STILL DERIVED-NOT-RECEIVED ──
 * The field is caller-SENT but authority-CHECKED, exactly like `actor_fp` and
 * `epoch`. It has to be sent, because the byte-equality check means notme can
 * only sign bytes the caller already produced. It has to be checked, because a
 * delegation a caller could assert freely would let it attribute its actions
 * to another principal — which is worse than the current absence, since a
 * false attribution is evidence and a missing one is only a gap.
 *
 * ── WHY BYTES AND NOT A TEXT STRING ──
 * `canonical-cbor.ts` deliberately encodes only uints and byte strings, and
 * its header says it must not become a general encoder. UTF-8 bytes of the
 * correlation key preserve prefix matching, which is the entire point of the
 * key's shape, without widening the signing surface.
 */

import * as cbor from "cbor-x";
import { describe, expect, it } from "vitest";
import { correlationKey } from "../auth/correlation-key";
import { encodeCanonicalMap, type CborValue } from "../receipts/canonical-cbor";
import { CommitmentError, validateCommitment } from "../receipts/commitment";

const ACTOR_FP = new Uint8Array(32).fill(0xaa);
const EPOCH = 7;
const NOW_MS = 1_775_000_000_000;

const PRINCIPAL = "wimse://notme.bot/passkey/11111111-1111-1111-1111-111111111111";
const BINDING = "a".repeat(64);
const DELEGATION = correlationKey({
  principal: PRINCIPAL,
  binding: BINDING,
  task: "task-1",
});
const DELEGATION_BYTES = new TextEncoder().encode(DELEGATION);

const FACTS_NO_DELEGATION = { actorFp: ACTOR_FP, epoch: EPOCH, nowMs: NOW_MS };
const FACTS = { ...FACTS_NO_DELEGATION, delegation: DELEGATION_BYTES };

const digest = (fill: number) => new Uint8Array(32).fill(fill);

/**
 * Build a commitment in RFC 8949 §4.2 canonical key order.
 *
 * `delegation` is 10 bytes, so it sorts after `body_hash` (9) and before
 * `headers_hash` (12).
 *
 * Uses `encodeCanonicalMap` rather than cbor-x, because cbor-x encodes any
 * number ≥ 2^32 as a float64 and `timestamp_ms` is unix milliseconds — so an
 * encoder-built commitment is never canonical and fails NOT_CANONICAL before
 * reaching anything this file is testing. That is the exact defect recorded in
 * canonical-cbor.ts's header, still biting.
 *
 * cbor-x is kept below ONLY for inputs that are meant to be malformed, where
 * field validation fires before the canonical-bytes check.
 */
function canonical(opts: { delegation?: Uint8Array } = {}): Uint8Array {
  const entries: Array<[string, CborValue]> = [
    ["epoch", { uint: EPOCH }],
    ["nonce", { bytes: new Uint8Array(16).fill(0x11) }],
    ["status", { uint: 200 }],
    ["actor_fp", { bytes: ACTOR_FP }],
    ["body_hash", { bytes: digest(0xbb) }],
  ];
  if (opts.delegation) entries.push(["delegation", { bytes: opts.delegation }]);
  entries.push(
    ["headers_hash", { bytes: digest(0xcc) }],
    ["request_hash", { bytes: digest(0xdd) }],
    ["timestamp_ms", { uint: NOW_MS }],
  );
  return encodeCanonicalMap(entries);
}

function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(CommitmentError);
    return (e as CommitmentError).code;
  }
  throw new Error("expected a CommitmentError, none thrown");
}

describe("receipt delegation field (notme-9f84e6)", () => {
  it("still accepts an Interlace 0.2.0 commitment unchanged", async () => {
    // The compatibility guarantee. A caller that knows nothing about
    // delegation must be unaffected, whether or not the authority has a
    // delegation to offer.
    expect(() => validateCommitment(canonical(), FACTS_NO_DELEGATION)).not.toThrow();
    expect(() => validateCommitment(canonical(), FACTS)).not.toThrow();
  });

  it("accepts a commitment carrying the delegation the authority derived", () => {
    const bytes = canonical({ delegation: DELEGATION_BYTES });
    const signed = validateCommitment(bytes, FACTS);
    // Returned bytes are the re-encoded canonical form and must equal input.
    expect(Array.from(signed)).toEqual(Array.from(bytes));
  });

  it("REFUSES a delegation the caller made up", () => {
    // The load-bearing test. Without this the field is worse than useless:
    // a caller could attribute its requests to another principal and get a
    // master-key signature saying so.
    const forged = new TextEncoder().encode(
      correlationKey({
        principal: "wimse://notme.bot/passkey/22222222-2222-2222-2222-222222222222",
        binding: BINDING,
        task: "task-1",
      }),
    );
    expect(codeOf(() => validateCommitment(canonical({ delegation: forged }), FACTS)))
      .toBe("DELEGATION_MISMATCH");
  });

  it("REFUSES a delegation when the authority has none to check it against", () => {
    // Fails closed. An authority that cannot verify the claim must not sign
    // it — signing an unverifiable attribution is exactly the forgery this
    // field would otherwise enable.
    expect(
      codeOf(() =>
        validateCommitment(
          canonical({ delegation: DELEGATION_BYTES }),
          FACTS_NO_DELEGATION,
        ),
      ),
    ).toBe("DELEGATION_MISMATCH");
  });

  it("rejects a ninth key that is not `delegation`", () => {
    // The original schema comment's concern — an extra key is a place to park
    // bytes a verifier ignores and something else interprets. Exactly one
    // additional key is admissible, and only by name.
    const entries: Array<[string, unknown]> = [
      ["epoch", EPOCH],
      ["nonce", new Uint8Array(16).fill(0x11)],
      ["status", 200],
      ["actor_fp", ACTOR_FP],
      ["body_hash", digest(0xbb)],
      ["smuggled", new Uint8Array([1, 2, 3])],
      ["headers_hash", digest(0xcc)],
      ["request_hash", digest(0xdd)],
      ["timestamp_ms", NOW_MS],
    ];
    // WRONG_KEY_COUNT, not a new code: this is what an extra key produced
    // before `delegation` existed, and the error codes are a wire contract.
    // A consumer branching on "extra key" should not have to learn a new code
    // because an unrelated optional field was added.
    const bytes = new Uint8Array(cbor.encode(new Map(entries)));
    expect(codeOf(() => validateCommitment(bytes, FACTS))).toBe("WRONG_KEY_COUNT");
  });

  it("rejects ten keys outright", () => {
    const entries: Array<[string, unknown]> = [
      ["epoch", EPOCH],
      ["nonce", new Uint8Array(16).fill(0x11)],
      ["status", 200],
      ["actor_fp", ACTOR_FP],
      ["body_hash", digest(0xbb)],
      ["delegation", DELEGATION_BYTES],
      ["extra_pad", new Uint8Array([9])],
      ["headers_hash", digest(0xcc)],
      ["request_hash", digest(0xdd)],
      ["timestamp_ms", NOW_MS],
    ];
    const bytes = new Uint8Array(cbor.encode(new Map(entries)));
    expect(codeOf(() => validateCommitment(bytes, FACTS))).toBe("WRONG_KEY_COUNT");
  });

  it("rejects a delegation that is not a byte string", () => {
    const entries: Array<[string, unknown]> = [
      ["epoch", EPOCH],
      ["nonce", new Uint8Array(16).fill(0x11)],
      ["status", 200],
      ["actor_fp", ACTOR_FP],
      ["body_hash", digest(0xbb)],
      ["delegation", DELEGATION], // text, not bytes
      ["headers_hash", digest(0xcc)],
      ["request_hash", digest(0xdd)],
      ["timestamp_ms", NOW_MS],
    ];
    const bytes = new Uint8Array(cbor.encode(new Map(entries)));
    expect(codeOf(() => validateCommitment(bytes, FACTS))).toBe("FIELD_NOT_BYTES");
  });

  it("keeps the canonical-bytes check working with the field present", () => {
    // `delegation` sorts between body_hash and headers_hash. A commitment
    // with the right keys in the WRONG order must still be refused, or the
    // signed bytes stop being the ones the structure encodes to.
    const misordered: Array<[string, unknown]> = [
      ["epoch", EPOCH],
      ["nonce", new Uint8Array(16).fill(0x11)],
      ["status", 200],
      ["actor_fp", ACTOR_FP],
      ["delegation", DELEGATION_BYTES], // too early — belongs after body_hash
      ["body_hash", digest(0xbb)],
      ["headers_hash", digest(0xcc)],
      ["request_hash", digest(0xdd)],
      ["timestamp_ms", NOW_MS],
    ];
    const bytes = new Uint8Array(cbor.encode(new Map(misordered)));
    expect(codeOf(() => validateCommitment(bytes, FACTS))).toBe("NOT_CANONICAL");
  });
});
