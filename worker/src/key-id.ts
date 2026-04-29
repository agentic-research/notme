/**
 * Derive a stable key ID from an Ed25519 SPKI (base64).
 *
 * Returns 16 hex chars (8 bytes / 64 bits) of SHA-256(spki). RFC 7638
 * truncation pattern.
 *
 * Width: 64 bits is the smallest size where birthday-paradox collisions
 * stay infeasible across realistic key-rotation volumes — roughly 4
 * billion keys before 50% collision odds. The prior 32-bit truncation
 * gave ~65k, which an attacker who can influence rotation timing could
 * grind through. See rosary-808b0e for the analysis.
 *
 * **Migration policy** (no separate sweeper):
 *
 *   - Existing 8-hex-char keyIds persisted in deployed DOs are NOT
 *     rewritten. This function only runs when generating a new keypair
 *     or backfilling an unset `key_id` column.
 *   - 5-minute cert TTL means certs minted with an old 8-hex keyId
 *     drain naturally — every cert in the wild expires within 5 minutes.
 *   - Bundle keyId / prevKeyId fields accept either width (string
 *     comparison, no fixed-length parser).
 *
 * If you need to actively re-id existing keys, generate a new keypair
 * via key rotation (epoch bump) — the new keypair gets a 16-hex id, and
 * the old 8-hex id moves to `prevKeyId` for the rotation grace window.
 * No code change needed in this function.
 *
 * In its own file (no DO dependencies) so unit tests can import directly.
 */
export async function keyIdFromSpki(spkiB64: string): Promise<string> {
  const raw = atob(spkiB64);
  const keyBytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) keyBytes[i] = raw.charCodeAt(i);
  const hashBuf = await crypto.subtle.digest("SHA-256", keyBytes);
  return Array.from(new Uint8Array(hashBuf).slice(0, 8))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
