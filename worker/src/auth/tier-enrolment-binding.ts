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
 * iat must be within RENEWAL_SKEW_S of the authority's clock, so a proof is
 * only usable briefly. Replaying one is harmless anyway: renewal returns a
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
