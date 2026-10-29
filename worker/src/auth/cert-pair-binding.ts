/**
 * What a browser (or any session holder) signs to obtain a cert pair from
 * /cert/passkey or /cert's session branch (notme-486e8a).
 *
 *   "notme/cert-pair/v1\0" || mtlsSPKI || signingSPKI || SHA-256(nonce)
 *
 * The session term exists so a captured keys+proofs pair cannot be replayed
 * under another session to bind the victim's keys to the attacker's identity.
 * It used to be SHA-256 of the session cookie — which is HttpOnly, so no
 * browser could compute it and /cert/passkey was uncallable — and /cert's
 * session branch had no session term at all, so it WAS replayable. The nonce
 * is issued by POST /cert/nonce (same-origin, cookie sent automatically),
 * bound to the session's principal server-side, and single-use.
 *
 * Pure, so a client can import the same bytes.
 */
export const CERT_PAIR_TAG = "notme/cert-pair/v1\0";

export async function certPairBinding(
  mtlsSpki: Uint8Array,
  signingSpki: Uint8Array,
  nonce: string,
): Promise<Uint8Array> {
  const tag = new TextEncoder().encode(CERT_PAIR_TAG);
  const nonceHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(nonce)),
  );
  const out = new Uint8Array(tag.length + mtlsSpki.length + signingSpki.length + 32);
  out.set(tag, 0);
  out.set(mtlsSpki, tag.length);
  out.set(signingSpki, tag.length + mtlsSpki.length);
  out.set(nonceHash, tag.length + mtlsSpki.length + signingSpki.length);
  return out;
}
