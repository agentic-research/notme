/**
 * canonical-cbor.ts — a hand-rolled RFC 8949 §4.2 encoder for the exact shape
 * an Interlace receipt commitment has (ADR-014).
 *
 * WHY NOT cbor-x, which this repo already depends on:
 *
 * cbor-x has no integer type above int32. It encodes any JS number ≥ 2^32 as
 * a **float64** (major type 7), and decodes a canonical uint64 (`0x1b …`) to a
 * **BigInt**. Measured on the pinned 1.6.4:
 *
 *     encode(1775000000000)  ->  fb 4279d463e9600000   (float64)
 *     decode(1b 0000019d…)   ->  1775000000000n        (bigint)
 *
 * `timestamp_ms` is unix MILLISECONDS, so every real commitment since
 * 1970-02-19 crosses that boundary. Delegating the signing input to cbor-x
 * therefore produced two failures at once:
 *
 *   1. A conformant caller — Go's fxamacker/cbor under CanonicalEncOptions,
 *      ciborium, anything following §4.2 — sends shortest-form uint64 and gets
 *      rejected, because the decoder hands back a BigInt.
 *   2. The only form that WAS accepted got signed as a float64, and
 *      RECEIPTS.md §3.1 is explicit: "Floats and NaN are forbidden … canonical
 *      receipt schemas in this spec contain no float fields at all."
 *
 * So the authority was signing bytes the spec forbids, and no independent
 * verifier could reproduce them — which is the whole point of the feature.
 *
 * It survived review because the tests built their fixtures with the same
 * encoder they validated against. That is a fixed point, not a conformance
 * check: any self-consistent encoder passes it, including a wrong one.
 *
 * The deeper reason to hand-roll: the signing input for the CA master key
 * should be defined by the SPEC, not by a caret-ranged dependency's incidental
 * behaviour. Under the old arrangement a cbor-x minor bump fixing this exact
 * bug would silently change what the key signs and make every prior receipt
 * unreproducible.
 *
 * Scope is deliberately tiny: definite-length map, text-string keys, uint and
 * byte-string values. That is the entire commitment schema. It is not a
 * general CBOR encoder and must not become one.
 */

/** Shortest-form unsigned integer head (RFC 8949 §3, major type in bits 5-7). */
function uintHead(major: number, value: number | bigint): Uint8Array {
  const mt = major << 5;
  const v = typeof value === "bigint" ? value : BigInt(Math.trunc(value));

  if (v < 24n) return new Uint8Array([mt | Number(v)]);
  if (v < 0x100n) return new Uint8Array([mt | 24, Number(v)]);
  if (v < 0x10000n) {
    return new Uint8Array([mt | 25, Number(v >> 8n) & 0xff, Number(v) & 0xff]);
  }
  if (v < 0x100000000n) {
    return new Uint8Array([
      mt | 26,
      Number((v >> 24n) & 0xffn),
      Number((v >> 16n) & 0xffn),
      Number((v >> 8n) & 0xffn),
      Number(v & 0xffn),
    ]);
  }
  // 0x1b — the eight-byte form cbor-x never emits and which every real
  // millisecond timestamp requires.
  const out = new Uint8Array(9);
  out[0] = mt | 27;
  for (let i = 8; i >= 1; i--) {
    out[i] = Number((v >> BigInt((8 - i) * 8)) & 0xffn);
  }
  return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.byteLength;
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.byteLength;
  }
  return out;
}

/** Major type 3 — a text string. Keys only; all are ASCII here. */
function textString(s: string): Uint8Array {
  const bytes = new TextEncoder().encode(s);
  return concat([uintHead(3, bytes.byteLength), bytes]);
}

/** Major type 2 — a byte string. */
function byteString(b: Uint8Array): Uint8Array {
  return concat([uintHead(2, b.byteLength), b]);
}

/** Major type 0 — an unsigned integer, shortest form. */
function uint(v: number | bigint): Uint8Array {
  return uintHead(0, v);
}

export type CborValue = { uint: number | bigint } | { bytes: Uint8Array };

/**
 * Encode a definite-length map with text-string keys.
 *
 * `entries` MUST already be in RFC 8949 §4.2 order — bytewise lexicographic
 * over the *encoded* keys, which for these ASCII names is shorter-first then
 * bytewise. The caller owns that ordering because the commitment schema is
 * fixed and hardcoding the order makes it reviewable; sorting here would hide
 * it behind a comparator nobody re-reads.
 */
export function encodeCanonicalMap(
  entries: ReadonlyArray<readonly [string, CborValue]>,
): Uint8Array {
  const parts: Uint8Array[] = [uintHead(5, entries.length)];
  for (const [key, value] of entries) {
    parts.push(textString(key));
    parts.push("uint" in value ? uint(value.uint) : byteString(value.bytes));
  }
  return concat(parts);
}
