/**
 * Small-order Ed25519 public keys (notme-48226d).
 *
 * The edwards25519 group has a torsion subgroup of order 8. A public key in it
 * has no private key behind it, and a signature for it can be made with
 * nothing at all: with R a small-order point and S = 0, the cofactorless
 * equation [S]B = R + [k]A holds whenever [k]A = -R, which for an order-8 A
 * happens for about one message in eight, and for the identity key
 * (01 00…00) for EVERY message.
 *
 * MEASURED, not assumed: workerd's `crypto.subtle` imports all 8 such keys
 * and its Ed25519 `verify` accepts those forgeries (ed25519-small-order.do.test.ts
 * pins it). So a proof of possession "for" such a key proves nothing, and a
 * certificate bound to one is a certificate anyone can sign as. RFC 8032
 * §5.1.7 does not require rejecting them, so the check is ours to make.
 *
 * The test is libsodium's `has_small_order` (src/libsodium/crypto_core/
 * ed25519/ref10/ref10.c): compare the encoding, with the x sign bit masked
 * off, against the seven y-coordinates of the small-order points, including
 * the non-canonical aliases p (≡ 0) and p+1 (≡ 1). Masking the sign bit is
 * what folds the 8 canonical points and their non-canonical twins into 7 rows.
 */

import { ED25519 } from "./platform";

const BLOCKLIST: readonly Uint8Array[] = [
  // y = 0 (order 4)
  "0000000000000000000000000000000000000000000000000000000000000000",
  // y = 1 (order 1, the identity)
  "0100000000000000000000000000000000000000000000000000000000000000",
  // order 8
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  // order 8
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  // y = p - 1 (order 2)
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  // y = p, non-canonical 0 (order 4)
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  // y = p + 1, non-canonical 1 (order 1)
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
].map((h) => Uint8Array.from(h.match(/../g)!, (b) => parseInt(b, 16)));

/** True for a 32-byte Ed25519 public key encoding of a small-order point. */
export function isSmallOrderEd25519(raw: Uint8Array): boolean {
  if (raw.length !== 32) return false;
  return BLOCKLIST.some((row) => {
    for (let i = 0; i < 31; i++) if (raw[i] !== row[i]) return false;
    return (raw[31]! & 0x7f) === row[31];
  });
}

/**
 * True if `key` is an Ed25519 key on a small-order point. Fails CLOSED: a key
 * whose raw bytes cannot be read is treated as small-order, since the caller
 * is about to trust a signature under it.
 */
export async function isSmallOrderEd25519Key(key: CryptoKey): Promise<boolean> {
  try {
    const raw = new Uint8Array((await crypto.subtle.exportKey("raw", key)) as ArrayBuffer);
    return isSmallOrderEd25519(raw);
  } catch {
    return true;
  }
}

/**
 * Ed25519 `verify` that refuses a small-order key, for every site where the
 * key came from a caller. Never throws: a key or signature WebCrypto rejects
 * is a failed verification, as everywhere else in this repo.
 */
export async function verifyEd25519(
  key: CryptoKey,
  signature: BufferSource,
  data: BufferSource,
): Promise<boolean> {
  if (await isSmallOrderEd25519Key(key)) return false;
  try {
    return await crypto.subtle.verify(ED25519, key, signature, data);
  } catch {
    return false;
  }
}
