import { describe, it, expect } from "vitest";

/**
 * adversarial.test.ts — Verify key extraction invariants.
 *
 * Maps to THREAT_MODEL.md: signing.key.isolation (invariant #4)
 *
 * These tests verify that the WebCrypto patterns used in SigningAuthority
 * correctly prevent private key extraction. The DO itself can't be
 * instantiated outside Workerd, but the crypto invariants hold in any
 * conformant SubtleCrypto implementation.
 */

describe("adversarial: key extraction", () => {
  it("non-extractable key rejects exportKey (invariant #4)", async () => {
    // This mirrors the cf-managed code path: generate extractable, then
    // re-import as non-extractable — same as signing-authority.ts.
    const kp = (await crypto.subtle.generateKey(
      { name: "Ed25519" } as any,
      true, // extractable initially (to export JWK for storage)
      ["sign", "verify"],
    )) as CryptoKeyPair;

    const privateJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);

    // Re-import as non-extractable — this is the steady-state in SigningAuthority
    const lockedKey = await crypto.subtle.importKey(
      "jwk",
      privateJwk,
      { name: "Ed25519" } as any,
      false, // NON-EXTRACTABLE
      ["sign"],
    );

    // The locked key must reject all export formats
    await expect(
      crypto.subtle.exportKey("jwk", lockedKey),
    ).rejects.toThrow();
    await expect(
      crypto.subtle.exportKey("pkcs8", lockedKey),
    ).rejects.toThrow();
    await expect(
      crypto.subtle.exportKey("raw", lockedKey),
    ).rejects.toThrow();
  });

  it("ephemeral mode: generateKey(extractable:false) rejects export", async () => {
    // This mirrors the ephemeral code path: key born non-extractable
    const kp = (await crypto.subtle.generateKey(
      { name: "Ed25519" } as any,
      false, // non-extractable from birth
      ["sign", "verify"],
    )) as CryptoKeyPair;

    // Private key must reject export
    await expect(
      crypto.subtle.exportKey("jwk", kp.privateKey),
    ).rejects.toThrow();

    // Public key should still be exportable (SubtleCrypto allows this)
    const spki = await crypto.subtle.exportKey("spki", kp.publicKey);
    expect(spki).toBeInstanceOf(ArrayBuffer);
    expect(spki.byteLength).toBeGreaterThan(0);
  });

  it("non-extractable key can still sign (functional after lockdown)", async () => {
    const kp = (await crypto.subtle.generateKey(
      { name: "Ed25519" } as any,
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;

    const privateJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
    const lockedKey = await crypto.subtle.importKey(
      "jwk",
      privateJwk,
      { name: "Ed25519" } as any,
      false,
      ["sign"],
    );

    // Sign must succeed — key is non-extractable but still usable
    const data = new TextEncoder().encode("test payload");
    const sig = await crypto.subtle.sign("Ed25519" as any, lockedKey, data);
    expect(sig).toBeInstanceOf(ArrayBuffer);
    expect(sig.byteLength).toBe(64); // Ed25519 signature is 64 bytes

    // Verify with the public key
    const valid = await crypto.subtle.verify(
      "Ed25519" as any,
      kp.publicKey,
      sig,
      data,
    );
    expect(valid).toBe(true);
  });

  it("no private key material in JWK public key export", async () => {
    const kp = (await crypto.subtle.generateKey(
      { name: "Ed25519" } as any,
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;

    // Export public key as JWK (mirrors getPublicKeyJwk path)
    const raw = await crypto.subtle.exportKey("raw", kp.publicKey);
    const rawBytes = new Uint8Array(raw as ArrayBuffer);

    // Raw export of public key should be 32 bytes (Ed25519 public key)
    expect(rawBytes.byteLength).toBe(32);

    // SPKI export should not contain "d" field (private key component)
    const spki = await crypto.subtle.exportKey("spki", kp.publicKey);
    const spkiB64 = btoa(String.fromCharCode(...new Uint8Array(spki as ArrayBuffer)));
    expect(spkiB64).not.toMatch(/"d"\s*:\s*"[A-Za-z0-9_-]+"/);

    // Public JWK should not contain "d" field
    const pubJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
    expect(pubJwk).not.toHaveProperty("d");
    expect(pubJwk).toHaveProperty("x"); // public component
  });

  it("public key stays extractable when private is locked", async () => {
    // Mirrors: importKey("spki", ..., true) for verifyKey
    const kp = (await crypto.subtle.generateKey(
      { name: "Ed25519" } as any,
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;

    // Export public SPKI, then re-import as extractable (like signing-authority import path)
    const spki = await crypto.subtle.exportKey("spki", kp.publicKey);
    const verifyKey = await crypto.subtle.importKey(
      "spki",
      spki,
      { name: "Ed25519" } as any,
      true, // extractable — needed for JWKS endpoint
      ["verify"],
    );

    // Must be exportable in all public formats
    const raw = await crypto.subtle.exportKey("raw", verifyKey);
    expect(raw).toBeInstanceOf(ArrayBuffer);
    const spki2 = await crypto.subtle.exportKey("spki", verifyKey);
    expect(spki2).toBeInstanceOf(ArrayBuffer);
  });
});
