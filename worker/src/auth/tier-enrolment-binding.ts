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
