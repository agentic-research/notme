/**
 * commitment-vector.ts — build an Interlace commitment BY HAND from
 * RFC 8949 §4.2, with no CBOR library involved.
 *
 * This exists because the obvious way to write these fixtures is wrong.
 * Encoding a fixture with the same encoder the validator re-encodes with is a
 * FIXED POINT, not a conformance check: any self-consistent encoder satisfies
 * it, including one that emits bytes the spec forbids. That is precisely how a
 * float64 `timestamp_ms` — banned outright by RECEIPTS.md §3.1 — passed 17
 * green tests and would have shipped.
 *
 * So the bytes here are assembled from the spec text. When these agree with
 * the production encoder, that is evidence; when they agree with cbor-x, that
 * would have been a coincidence.
 */

const enc = new TextEncoder();

/** Major type 3, text string. All commitment keys are short ASCII. */
function text(s: string): number[] {
  const b = [...enc.encode(s)];
  return [0x60 | b.length, ...b];
}

/** Major type 2, byte string, shortest-form head. */
function bytes(b: Uint8Array): number[] {
  if (b.byteLength < 24) return [0x40 | b.byteLength, ...b];
  return [0x58, b.byteLength, ...b];
}

/** Major type 0, unsigned integer, shortest form (§4.2.1). */
function uint(v: number): number[] {
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
  // The eight-byte form every real millisecond timestamp needs, and the one
  // cbor-x never emits.
  const bv = BigInt(v);
  const out = [0x1b];
  for (let i = 7; i >= 0; i--) out.push(Number((bv >> BigInt(i * 8)) & 0xffn));
  return out;
}

export interface CommitmentVectorOpts {
  actorFp: Uint8Array;
  epoch: number;
  timestampMs: number;
  status?: number;
  nonce?: Uint8Array;
  bodyHash?: Uint8Array;
  headersHash?: Uint8Array;
  requestHash?: Uint8Array;
}

/**
 * Keys are emitted in RFC 8949 §4.2 canonical order — bytewise lexicographic
 * over the encoded keys, which for these names is shorter-first then bytewise:
 * epoch, nonce, status, actor_fp, body_hash, headers_hash, request_hash,
 * timestamp_ms. Hardcoded rather than sorted so the order is reviewable.
 */
export function commitmentVector(opts: CommitmentVectorOpts): Uint8Array {
  const d = (fill: number) => new Uint8Array(32).fill(fill);
  const parts: number[] = [0xa8]; // map(8), definite length

  parts.push(...text("epoch"), ...uint(opts.epoch));
  parts.push(
    ...text("nonce"),
    ...bytes(opts.nonce ?? new Uint8Array(16).fill(0x11)),
  );
  parts.push(...text("status"), ...uint(opts.status ?? 200));
  parts.push(...text("actor_fp"), ...bytes(opts.actorFp));
  parts.push(...text("body_hash"), ...bytes(opts.bodyHash ?? d(0xbb)));
  parts.push(...text("headers_hash"), ...bytes(opts.headersHash ?? d(0xcc)));
  parts.push(...text("request_hash"), ...bytes(opts.requestHash ?? d(0xdd)));
  parts.push(...text("timestamp_ms"), ...uint(opts.timestampMs));

  return new Uint8Array(parts);
}
