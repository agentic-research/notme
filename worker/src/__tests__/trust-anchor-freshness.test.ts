/**
 * trust-anchor-freshness.test.ts — a served root is only evidence if its key
 * is the one the authority signs with NOW (notme-ed6114, review F2).
 *
 * ca-bundle.pem is edge-cached and nothing purges it on rotate(), so for up
 * to its max-age it can serve the previous root. The KV CABundle
 * (/internal/ca-bundle, no-store) names the live key; refresh-trust-anchor.ts
 * and release.yml refuse to act on a root whose key the bundle does not
 * name as current.
 */
import { describe, expect, it } from "vitest";
import { rootKeyIsCurrent } from "../../../scripts/trust-anchor-freshness";

const ED25519 = { name: "Ed25519" } as const;

async function key() {
  const kp = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = new Uint8Array((await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer);
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", kp.publicKey)) as ArrayBuffer);
  return { spki, rawB64: btoa(String.fromCharCode(...raw)) };
}

describe("rootKeyIsCurrent", () => {
  it("accepts a root whose key is the bundle's current key", async () => {
    const k = await key();
    expect(rootKeyIsCurrent(k.spki, { keyId: "k1", keys: { k1: k.rawB64 } })).toBe(true);
  });

  it("refuses a root under the PREVIOUS key, even while the bundle still publishes it", async () => {
    // The rotation grace window: the bundle carries prevKeyId's key so old
    // tokens verify, but a root under it is the stale one.
    const old = await key();
    const cur = await key();
    expect(rootKeyIsCurrent(old.spki, { keyId: "new", keys: { new: cur.rawB64, old: old.rawB64 } })).toBe(false);
  });

  it("refuses when the bundle names no key for its keyId", async () => {
    const k = await key();
    expect(rootKeyIsCurrent(k.spki, { keyId: "missing", keys: { k1: k.rawB64 } })).toBe(false);
  });

  it("refuses a non-Ed25519 SPKI rather than comparing its tail", async () => {
    const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const spki = new Uint8Array((await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer);
    const tail = btoa(String.fromCharCode(...spki.slice(-32)));
    expect(rootKeyIsCurrent(spki, { keyId: "k", keys: { k: tail } })).toBe(false);
  });
});
