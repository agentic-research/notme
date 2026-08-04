/**
 * commitment.ts — parse, validate and canonically re-encode an Interlace
 * 0.2.0 receipt commitment (ADR-014, cloister RECEIPTS.md §2.1).
 *
 * THE POINT OF THIS FILE: the authority must never sign bytes a caller handed
 * it. The master Ed25519 key that signs receipts also signs X.509
 * `TBSCertificate` DER and `at+jwt` access tokens, and the Interlace spec
 * signs the commitment with no domain separator. So an endpoint that signed
 * arbitrary input would be a universal forgery oracle: submit a crafted
 * TBSCertificate, get a signature, assemble a certificate that chains to this
 * authority for any identity and any scopes.
 *
 * Instead the input is decoded, structurally validated, canonically
 * re-encoded, and the result is required to equal the input byte for byte.
 * Only then is it signed. A DER certificate is not a CBOR map of these eight
 * keys; a JWT signing input is ASCII; and non-canonical CBOR — the obvious
 * place to smuggle attacker-chosen bytes — fails the equality check.
 */

import { Decoder } from "cbor-x";
import { encodeCanonicalMap, type CborValue } from "./canonical-cbor";

/**
 * Strict decoder.
 *
 * `mapsAsObjects: false` keeps CBOR maps as `Map`, which matters for
 * validation: a JS object would silently merge duplicate keys, and duplicate
 * keys are exactly the kind of malformed input this function exists to
 * reject.
 */
const cborDecoder = new Decoder({
  mapsAsObjects: false,
  useRecords: false,
  tagUint8Array: false,
});

/** The eight fields RECEIPTS.md §2.1 defines. No more, no fewer. */
const REQUIRED_KEYS = [
  "actor_fp",
  "body_hash",
  "epoch",
  "headers_hash",
  "nonce",
  "request_hash",
  "status",
  "timestamp_ms",
] as const;

/** Minimum `nonce` length per RECEIPTS.md ("bytes-16+"). */
const MIN_NONCE_BYTES = 16;
/** SHA-256 digest fields are exactly 32 bytes. */
const DIGEST_BYTES = 32;

/**
 * Every rejection code `validateCommitment` can produce. Exhaustive.
 *
 * Exported as a union so a caller can `switch` and have the compiler catch a
 * missing arm, rather than string-matching and guessing. Cloister asked for
 * this specifically: it must branch exhaustively and fail closed on anything
 * unrecognised.
 *
 * Only ONE code is retryable: EPOCH_MISMATCH — see `RETRYABLE_CODES`. Every
 * other code means the commitment is malformed and retrying it unchanged will
 * fail identically.
 *
 * These are a wire contract. Renaming one is a breaking change for every
 * consumer branching on it.
 */
export type CommitmentErrorCode =
  // — input is not a commitment at all —
  | "EMPTY_INPUT"
  | "NOT_CBOR" // where DER certs and JWT signing inputs land
  | "NOT_A_MAP"
  // — shape is wrong —
  | "WRONG_KEY_COUNT"
  | "MISSING_KEY"
  | "FIELD_NOT_BYTES"
  | "FIELD_NOT_UINT"
  | "FIELD_WRONG_LENGTH"
  | "NONCE_TOO_SHORT"
  // — values are out of contract —
  | "STATUS_NOT_2XX"
  | "TIMESTAMP_OUT_OF_RANGE"
  // — caller disagrees with the authority about the authority —
  | "ACTOR_FP_MISMATCH"
  | "EPOCH_MISMATCH" // RETRYABLE: re-read receiptFacts(), retry ONCE
  // — bytes are not the canonical encoding of the validated structure —
  | "NOT_CANONICAL";

/**
 * The codes worth retrying, and the only one there is.
 *
 * A caller that re-reads `receiptFacts()` and retries on EPOCH_MISMATCH
 * MUST bound that to a single attempt. Rotation can move again between the
 * re-read and the retry, and this call sits on cloister's response path in a
 * `finally` — an unbounded loop there stalls a proxied request that already
 * succeeded upstream. One retry, then surface the code.
 */
export const RETRYABLE_CODES: ReadonlySet<CommitmentErrorCode> = new Set([
  "EPOCH_MISMATCH",
]);

export class CommitmentError extends Error {
  constructor(
    readonly code: CommitmentErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "CommitmentError";
  }
}

function fail(code: CommitmentErrorCode, message: string): never {
  throw new CommitmentError(code, message);
}

/**
 * A CBOR byte string, as this decoder produces them.
 *
 * Deliberately NOT also requiring `byteOffset === 0`: cbor-x decodes byte
 * strings as Node `Buffer` views into a shared ~8KB pool, so a legitimate
 * 32-byte digest arrives at some arbitrary offset into a much larger buffer.
 * An offset check here would reject every well-formed commitment.
 *
 * Nothing is lost by allowing views. The guarantee that matters comes from
 * re-encoding and comparing against the input, which reads each field's
 * logical contents — a view and a copy of the same bytes encode identically.
 * The one place a view IS dangerous is the RPC boundary, where comparing
 * against a view over a larger buffer would compare against neighbouring
 * data; `ReceiptSigner.signReceipt` copies there for exactly that reason.
 */
function isBytes(v: unknown): v is Uint8Array {
  return v instanceof Uint8Array;
}

function requireBytes(m: Map<unknown, unknown>, key: string, len?: number) {
  const v = m.get(key);
  if (!isBytes(v))
    fail("FIELD_NOT_BYTES", `"${key}" must be a CBOR byte string`);
  if (len !== undefined && v.byteLength !== len) {
    fail(
      "FIELD_WRONG_LENGTH",
      `"${key}" must be exactly ${len} bytes, got ${v.byteLength}`,
    );
  }
  return v;
}

/**
 * Read a CBOR unsigned integer, accepting BOTH `number` and `bigint`.
 *
 * Accepting bigint is required for conformance, not convenience. cbor-x
 * decodes a shortest-form uint64 (`0x1b …`) to a BigInt, and every real
 * `timestamp_ms` is above 2^32 — so an earlier `typeof v !== "number"` guard
 * rejected 100% of commitments from any spec-conformant encoder, with a
 * message ("must be a non-negative CBOR integer") describing exactly what the
 * caller had correctly sent.
 *
 * Normalized to `number` after a safe-integer check so the range comparisons
 * below stay ordinary arithmetic. Milliseconds stay exact well past year
 * 275760; anything beyond Number.MAX_SAFE_INTEGER is refused rather than
 * silently rounded.
 */
function requireUint(m: Map<unknown, unknown>, key: string): number {
  const v = m.get(key);
  if (typeof v === "bigint") {
    if (v < 0n || v > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail("FIELD_NOT_UINT", `"${key}" is outside the safe integer range`);
    }
    return Number(v);
  }
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) {
    fail("FIELD_NOT_UINT", `"${key}" must be a non-negative CBOR integer`);
  }
  return v;
}

export interface CommitmentFacts {
  /** SHA-256 of the authority's master public key. */
  actorFp: Uint8Array;
  /** The authority's current key epoch. */
  epoch: number;
  /**
   * The authority's clock, in unix ms. Injected rather than read here so it
   * stays derived-not-received alongside the other two facts, and so the
   * bound is testable without faking time globally.
   */
  nowMs: number;
}

/**
 * Tolerance on `timestamp_ms`, matching RECEIPTS.md §2.2.1 step 12 — the
 * window a conformant peer already applies against its own clock.
 *
 * Chosen to equal the spec's rather than something tighter: a bound narrower
 * than the verifier's would reject receipts that every conformant P would
 * have accepted, turning a defence into an outage.
 */
const MAX_TIMESTAMP_SKEW_MS = 300_000;

/**
 * Validate `input` as a canonical Interlace commitment and return the bytes to
 * sign.
 *
 * @param input  Caller-supplied candidate commitment CBOR.
 * @param facts  Values DERIVED from the authority — never from the caller.
 *               `actor_fp` and `epoch` are claims about notme, so a caller
 *               asserting them could attribute a receipt to another actor or
 *               resolve it against a retired key. Mismatches are rejected
 *               rather than overwritten, so the caller learns its state is
 *               stale instead of silently getting a receipt it did not expect.
 *
 * @returns The canonically re-encoded bytes. Byte-identical to `input` — the
 *          equality check below guarantees it — so callers may sign either;
 *          returning the re-encoded copy makes the provenance explicit.
 */
export function validateCommitment(
  input: Uint8Array,
  facts: CommitmentFacts,
): Uint8Array {
  if (input.byteLength === 0) fail("EMPTY_INPUT", "commitment is empty");

  let decoded: unknown;
  try {
    decoded = cborDecoder.decode(input);
  } catch (e: any) {
    // This is where a DER certificate and a JWT signing input both land.
    fail("NOT_CBOR", `commitment is not decodable CBOR: ${e.message}`);
  }

  if (!(decoded instanceof Map)) {
    fail("NOT_A_MAP", "commitment must be a CBOR map");
  }

  // Exactly the eight keys. An extra key would be signed-but-unspecified
  // data — a place to park bytes a verifier ignores and something else
  // interprets.
  if (decoded.size !== REQUIRED_KEYS.length) {
    fail(
      "WRONG_KEY_COUNT",
      `commitment must have exactly ${REQUIRED_KEYS.length} keys, got ${decoded.size}`,
    );
  }
  for (const key of REQUIRED_KEYS) {
    if (!decoded.has(key))
      fail("MISSING_KEY", `commitment is missing "${key}"`);
  }

  const nonce = requireBytes(decoded, "nonce");
  if (nonce.byteLength < MIN_NONCE_BYTES) {
    fail(
      "NONCE_TOO_SHORT",
      `"nonce" must be at least ${MIN_NONCE_BYTES} bytes, got ${nonce.byteLength}`,
    );
  }
  const requestHash = requireBytes(decoded, "request_hash", DIGEST_BYTES);
  const bodyHash = requireBytes(decoded, "body_hash", DIGEST_BYTES);
  const headersHash = requireBytes(decoded, "headers_hash", DIGEST_BYTES);
  const actorFp = requireBytes(decoded, "actor_fp", DIGEST_BYTES);

  const status = requireUint(decoded, "status");
  // RECEIPTS.md §2.1 pins this to 2xx: a receipt attests an ADMITTED
  // response. Signing one for a 4xx/5xx would let a caller manufacture
  // evidence that a request it never served succeeded.
  if (status < 200 || status > 299) {
    fail("STATUS_NOT_2XX", `"status" must be 200..299, got ${status}`);
  }

  const timestampMs = requireUint(decoded, "timestamp_ms");
  // Bounded to the authority's clock, because this is the ONE remaining field
  // that is fully caller-chosen, semantically load-bearing, and cheaply
  // checkable here.
  //
  // The other free fields are free for a reason: `nonce`, `request_hash`,
  // `body_hash` and `headers_hash` describe a request notme structurally
  // cannot see, so it has nothing to check them against. notme has a clock.
  //
  // Without this, a compromised binding holder mints receipts backdated
  // across years — each a valid signature under the master key over a
  // canonical commitment, each provable evidence that the actor admitted a
  // request it never served, and none of them disprovable. Clamped, the same
  // compromise yields receipts datable only to the window in which the
  // attacker actually held the binding.
  if (Math.abs(timestampMs - facts.nowMs) > MAX_TIMESTAMP_SKEW_MS) {
    fail(
      "TIMESTAMP_OUT_OF_RANGE",
      `"timestamp_ms" is ${timestampMs}, outside ±${MAX_TIMESTAMP_SKEW_MS}ms of the authority clock`,
    );
  }
  const epoch = requireUint(decoded, "epoch");

  // ── Derived, not received (ADR-014) ──
  if (!bytesEqual(actorFp, facts.actorFp)) {
    fail(
      "ACTOR_FP_MISMATCH",
      '"actor_fp" does not match this authority\'s master public key',
    );
  }
  if (epoch !== facts.epoch) {
    fail(
      "EPOCH_MISMATCH",
      `"epoch" is ${epoch} but this authority's current epoch is ${facts.epoch}`,
    );
  }

  // Re-encode from the validated values. Key insertion order here is the
  // RFC 8949 §4.2 canonical order (length-then-bytewise over the encoded
  // keys), which the equality check below then proves against the input.
  const canonical: ReadonlyArray<readonly [string, CborValue]> = [
    ["epoch", { uint: epoch }],
    ["nonce", { bytes: nonce }],
    ["status", { uint: status }],
    ["actor_fp", { bytes: actorFp }],
    ["body_hash", { bytes: bodyHash }],
    ["headers_hash", { bytes: headersHash }],
    ["request_hash", { bytes: requestHash }],
    ["timestamp_ms", { uint: timestampMs }],
  ];
  const reencoded = encodeCanonicalMap(canonical);

  // THE LOAD-BEARING CHECK. Everything above proves the STRUCTURE is a
  // commitment; this proves the BYTES are the ones that structure encodes to.
  // Without it a caller could hide attacker-chosen data in indefinite-length
  // encodings or non-shortest integer forms — decoding to a valid commitment
  // while the signed bytes say something else.
  if (!bytesEqual(reencoded, input)) {
    fail(
      "NOT_CANONICAL",
      "commitment is not RFC 8949 §4.2 canonical — re-encoding produced different bytes",
    );
  }

  return reencoded;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
