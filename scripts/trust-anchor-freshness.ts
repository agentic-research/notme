/**
 * Is a served root certificate under the key the authority signs with NOW?
 * (notme-ed6114, review F2.)
 *
 * /.well-known/ca-bundle.pem is edge-cached, and nothing purges the cache on
 * rotate(): for up to its max-age a colo can keep serving the previous root.
 * A trust-anchor check that compares trust/ only with that copy can agree
 * with it, and the release then signs an anchor production no longer uses.
 *
 * The KV CABundle at /internal/ca-bundle is served no-store, regenerated
 * when stale (5 min, BUNDLE_MAX_AGE_MS), and names the live key as
 * `keys[keyId]`. A root whose SPKI does not carry exactly that key is not
 * evidence of what production serves, whatever the edge says.
 *
 * Pure — no fetch, no x509 parsing — so it runs under Node and in tests.
 */

/** DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410): 12 bytes, then the 32-byte key. */
const ED25519_SPKI_PREFIX = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

export function rootKeyIsCurrent(
  rootSpkiDer: Uint8Array,
  bundle: { keyId: string; keys: Record<string, string> },
): boolean {
  if (rootSpkiDer.length !== 44 || !ED25519_SPKI_PREFIX.every((b, i) => rootSpkiDer[i] === b)) return false;
  const current = bundle.keys[bundle.keyId];
  if (typeof current !== "string") return false;
  return btoa(String.fromCharCode(...rootSpkiDer.slice(12))) === current;
}
