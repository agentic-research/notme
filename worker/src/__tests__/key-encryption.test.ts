import { describe, expect, it } from "vitest";
import {
  deriveKek,
  isSealed,
  readStoredJwk,
  sealPrivateJwk,
  serialiseJwkForStorage,
  unsealPrivateJwk,
} from "../key-encryption";

const SECRET = "test-kek-secret-do-not-use-in-production";

async function anEd25519PrivateJwk(): Promise<JsonWebKey> {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" } as any, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  return (await crypto.subtle.exportKey("jwk", kp.privateKey)) as JsonWebKey;
}

describe("key-encryption", () => {
  it("round-trips a private JWK", async () => {
    const kek = await deriveKek(SECRET);
    const jwk = await anEd25519PrivateJwk();
    const out = await unsealPrivateJwk(await sealPrivateJwk(jwk, kek), kek);
    expect(out.d).toBe(jwk.d);
    expect(out.x).toBe(jwk.x);
    expect(out.crv).toBe("Ed25519");
  });

  // THE acceptance criterion for notme-41d0d3, and the literal restatement of
  // ADR-007's bar: `cat *.sqlite | strings | grep '"d"'` must not yield the key.
  it("leaves no cleartext private scalar in the stored column", async () => {
    const kek = await deriveKek(SECRET);
    const jwk = await anEd25519PrivateJwk();
    const stored = await serialiseJwkForStorage(jwk, kek);

    expect(stored).not.toContain(jwk.d!);
    expect(stored).not.toContain('"d"');
    // Guard against a future change that stores the JWK alongside the
    // envelope — the assertions above would still pass if `d` were merely
    // renamed, so also assert the whole plaintext JSON is absent.
    expect(stored).not.toContain(JSON.stringify(jwk));
  });

  it("derives the same KEK from the same secret and a different one otherwise", async () => {
    const jwk = await anEd25519PrivateJwk();
    const sealed = await sealPrivateJwk(jwk, await deriveKek(SECRET));

    // Same secret, freshly derived — a restarted Worker must be able to read
    // what a previous instance sealed.
    const again = await unsealPrivateJwk(sealed, await deriveKek(SECRET));
    expect(again.d).toBe(jwk.d);

    await expect(
      unsealPrivateJwk(sealed, await deriveKek("a-different-secret")),
    ).rejects.toThrow();
  });

  it("rejects a tampered envelope rather than returning garbage", async () => {
    const kek = await deriveKek(SECRET);
    const sealed = await sealPrivateJwk(await anEd25519PrivateJwk(), kek);
    // Flip a character in the ciphertext. AES-GCM is authenticated, so this
    // must fail the tag check rather than decrypt to something.
    const ct = sealed.ciphertext;
    const tampered = {
      ...sealed,
      ciphertext: (ct[0] === "A" ? "B" : "A") + ct.slice(1),
    };
    await expect(unsealPrivateJwk(tampered, kek)).rejects.toThrow();
  });

  it("refuses an empty secret instead of deriving a guessable KEK", async () => {
    await expect(deriveKek("")).rejects.toThrow(/secret is empty/);
  });

  describe("migration", () => {
    it("reads a legacy bare JWK and reports it was not sealed", async () => {
      const jwk = await anEd25519PrivateJwk();
      const { jwk: out, wasSealed } = await readStoredJwk(
        JSON.stringify(jwk),
        await deriveKek(SECRET),
      );
      expect(wasSealed).toBe(false);
      expect(out.d).toBe(jwk.d);
    });

    it("reads a sealed row and reports it was sealed", async () => {
      const kek = await deriveKek(SECRET);
      const jwk = await anEd25519PrivateJwk();
      const { jwk: out, wasSealed } = await readStoredJwk(
        await serialiseJwkForStorage(jwk, kek),
        kek,
      );
      expect(wasSealed).toBe(true);
      expect(out.d).toBe(jwk.d);
    });

    // The dangerous case: a sealed row met with no KEK. Returning null would
    // let the caller fall through to key generation and silently invalidate
    // every certificate and token the authority ever issued.
    it("throws on a sealed row with no KEK rather than falling through", async () => {
      const stored = await serialiseJwkForStorage(
        await anEd25519PrivateJwk(),
        await deriveKek(SECRET),
      );
      await expect(readStoredJwk(stored, null)).rejects.toThrow(
        /sealed but no KEK/,
      );
    });

    it("stores a bare JWK when no KEK is configured (cf-managed unchanged)", async () => {
      const jwk = await anEd25519PrivateJwk();
      const stored = await serialiseJwkForStorage(jwk, null);
      expect(isSealed(JSON.parse(stored))).toBe(false);
      expect(JSON.parse(stored).d).toBe(jwk.d);
    });
  });

  describe("domain separation from the cloister vault KEK", () => {
    // The vault derives with salt "notme-vault-kek-v1" / info
    // "credential-encryption". One operator secret may plausibly be reused
    // across both subsystems; if the parameters matched, the same secret would
    // yield the same KEK and a vault blob would unseal under the authority key.
    it("does not produce a KEK interchangeable with the vault's", async () => {
      const material = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(SECRET),
        "HKDF",
        false,
        ["deriveKey"],
      );
      const vaultKek = await crypto.subtle.deriveKey(
        {
          name: "HKDF",
          salt: new TextEncoder().encode("notme-vault-kek-v1"),
          info: new TextEncoder().encode("credential-encryption"),
          hash: "SHA-256",
        },
        material,
        { name: "AES-GCM", length: 256 },
        false,
        ["wrapKey", "unwrapKey"],
      );

      const sealed = await sealPrivateJwk(
        await anEd25519PrivateJwk(),
        await deriveKek(SECRET),
      );
      await expect(unsealPrivateJwk(sealed, vaultKek)).rejects.toThrow();
    });
  });
});
