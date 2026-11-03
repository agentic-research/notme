/**
 * What a machine signs to collect its delegation tier (notme-486e8a).
 *
 * Shared by the authority (signing-authority.ts, which verifies) and the
 * client (scripts/task-cert, which signs) so both sides are the SAME bytes by
 * construction. A copy on each side would drift silently, and the only
 * symptom would be `invalid_proof` at enrolment time.
 *
 * Domain-separated: the same Ed25519 key type signs other bindings in this
 * authority, and a proof for one must never verify as a proof for another.
 *
 * Pure — no Worker or DO imports — so the client can run it under Node.
 */
export const TIER_ENROL_TAG = "notme/tier-enrol/v1\0";

export function tierEnrolmentBinding(spki: Uint8Array, deviceCodeHash: Uint8Array): Uint8Array {
  if (deviceCodeHash.length !== 32) throw new Error("device code hash must be SHA-256 (32 bytes)");
  const tag = new TextEncoder().encode(TIER_ENROL_TAG);
  const out = new Uint8Array(tag.length + spki.length + 32);
  out.set(tag, 0);
  out.set(spki, tag.length);
  out.set(deviceCodeHash, tag.length + spki.length);
  return out;
}

export async function deviceCodeHash(deviceCode: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(deviceCode)));
}

/**
 * What a machine signs to RENEW its tier (notme-337d82).
 *
 *   "notme/tier-renew/v1\0" || SPKI || uint64be(iat)
 *
 * iat may be up to RENEWAL_RETRY_WINDOW_S old and at most RENEWAL_SKEW_S
 * ahead of the authority's clock, so a request that never arrived can be
 * resent as is (notme-747cc7). Replaying one is harmless: renewal returns a
 * PUBLIC certificate for a key the replayer does not hold. What the proof
 * establishes is that the renewer still holds the tier key.
 */
export const TIER_RENEW_TAG = "notme/tier-renew/v1\0";
export const RENEWAL_SKEW_S = 120;

export function tierRenewalBinding(spki: Uint8Array, iat: number): Uint8Array {
  if (!Number.isSafeInteger(iat) || iat < 0) throw new Error("iat must be a non-negative integer");
  const tag = new TextEncoder().encode(TIER_RENEW_TAG);
  const ts = new Uint8Array(8);
  new DataView(ts.buffer).setBigUint64(0, BigInt(iat));
  const out = new Uint8Array(tag.length + spki.length + 8);
  out.set(tag, 0);
  out.set(spki, tag.length);
  out.set(ts, tag.length + spki.length);
  return out;
}

/**
 * Renewal binding v2 (notme-747cc7): commits to the renewal GENERATION so a
 * copied machine key is detected as a fork.
 *
 *   "notme/tier-renew/v2\0" || SPKI || uint64be(iat) || uint64be(generation)
 *
 * Distinct tag from v1, so a v1 proof never verifies as a v2 proof.
 */
export const TIER_RENEW_V2_TAG = "notme/tier-renew/v2\0";

/** How long a renewal request may be retried against the same digest. */
export const RENEWAL_RETRY_WINDOW_S = 3600;

export function tierRenewalBindingV2(spki: Uint8Array, iat: number, generation: number): Uint8Array {
  if (!Number.isSafeInteger(iat) || iat < 0) throw new Error("iat must be a non-negative integer");
  if (!Number.isSafeInteger(generation) || generation < 0) {
    throw new Error("generation must be a non-negative safe integer");
  }
  const tag = new TextEncoder().encode(TIER_RENEW_V2_TAG);
  const nums = new Uint8Array(16);
  const view = new DataView(nums.buffer);
  view.setBigUint64(0, BigInt(iat));
  view.setBigUint64(8, BigInt(generation));
  const out = new Uint8Array(tag.length + spki.length + 16);
  out.set(tag, 0);
  out.set(spki, tag.length);
  out.set(nums, tag.length + spki.length);
  return out;
}

/**
 * The enrollment's public identifier (notme-c9fc8c): 32 bytes, derived from
 * the device-code hash under its own tag, so it names ONE enrollment without
 * being the row's key. The authority returns it, hex, at collect and on every
 * renewal; a v3 renewal signs it.
 */
export const TIER_ENROLMENT_ID_TAG = "notme/tier-enrolment-id/v1\0";

export async function tierEnrolmentId(deviceCodeHash: Uint8Array): Promise<Uint8Array> {
  if (deviceCodeHash.length !== 32) throw new Error("device code hash must be SHA-256 (32 bytes)");
  const tag = new TextEncoder().encode(TIER_ENROLMENT_ID_TAG);
  const input = new Uint8Array(tag.length + 32);
  input.set(tag, 0);
  input.set(deviceCodeHash, tag.length);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", input));
}

/**
 * Renewal binding v3 (notme-c9fc8c): v2 plus the ENROLLMENT, so a request
 * signed for one enrollment of a key never counts for another enrollment of
 * the same key (a re-enrollment through the API).
 *
 *   "notme/tier-renew/v3\0" || SPKI || uint64be(iat) || uint64be(generation) || enrollment_id
 *
 * enrollment_id is the 32 raw bytes of tierEnrolmentId. Distinct tag, so no
 * v1 or v2 proof verifies as v3.
 */
export const TIER_RENEW_V3_TAG = "notme/tier-renew/v3\0";

export function tierRenewalBindingV3(
  spki: Uint8Array,
  iat: number,
  generation: number,
  enrolmentId: Uint8Array,
): Uint8Array {
  if (!Number.isSafeInteger(iat) || iat < 0) throw new Error("iat must be a non-negative integer");
  if (!Number.isSafeInteger(generation) || generation < 0) {
    throw new Error("generation must be a non-negative safe integer");
  }
  if (enrolmentId.length !== 32) throw new Error("enrollment id must be 32 bytes");
  const tag = new TextEncoder().encode(TIER_RENEW_V3_TAG);
  const nums = new Uint8Array(16);
  const view = new DataView(nums.buffer);
  view.setBigUint64(0, BigInt(iat));
  view.setBigUint64(8, BigInt(generation));
  const out = new Uint8Array(tag.length + spki.length + 16 + 32);
  out.set(tag, 0);
  out.set(spki, tag.length);
  out.set(nums, tag.length + spki.length);
  out.set(enrolmentId, tag.length + spki.length + 16);
  return out;
}

/** The hex form of an enrollment id on the wire: exactly 64 lowercase hex digits. */
export const ENROLMENT_ID_HEX = /^[0-9a-f]{64}$/;

/** Lowercase hex SHA-256 of a renewal binding: the idempotency key for retries. */
export async function renewalRequestDigest(binding: Uint8Array): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", binding));
  return Array.from(d, (b) => b.toString(16).padStart(2, "0")).join("");
}
