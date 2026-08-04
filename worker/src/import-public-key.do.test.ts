/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * import-public-key.do.test.ts — `importPublicKey` must return a key usable
 * for the algorithm it actually is.
 *
 * This primitive had NO test. `grep -rn importPublicKey src/__tests__` was
 * empty, while three call sites depended on it — cert-exchange.ts,
 * cert-authority.ts, auth/derive-credentials.ts — each with coverage of its
 * own. The shared thing underneath had none, which is the usual shape: tests
 * cluster at the level people think about, and the primitive everyone assumes
 * is fine goes unexercised.
 *
 * The bug it hid: "try Ed25519, fall back to ECDSA on throw" never fell back,
 * because workerd's Ed25519 import ACCEPTS a P-256 SPKI instead of rejecting
 * it. Every key came back as {name:"Ed25519"}, so the P-256
 * proof-of-possession check on every cert-issuing path threw
 * "Requested algorithm ECDSA does not match this CryptoKey's algorithm
 * Ed25519" and answered 401.
 *
 * Runs in the workers pool deliberately: this is about what workerd's WebCrypto
 * does, and a Node-shimmed crypto would not reproduce it.
 */

import { describe, expect, it } from "vitest";
import { importPublicKey } from "./cert-authority";

function toPem(spki: ArrayBuffer): string {
  const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
  return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
}

describe("importPublicKey dispatches on the key's own algorithm", () => {
  it("imports a P-256 key as ECDSA, not Ed25519", async () => {
    const kp = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const spki = (await crypto.subtle.exportKey(
      "spki",
      kp.publicKey,
    )) as ArrayBuffer;

    const imported = await importPublicKey(toPem(spki));
    expect((imported.algorithm as { name: string }).name).toBe("ECDSA");
  });

  it("verifies a real P-256 signature — the check every cert route makes", async () => {
    // The end-to-end property. Before the OID dispatch this THREW rather than
    // returning false, and every /cert* route caught it as a 401 that read as
    // "your proof is bad" when the proof was fine.
    const kp = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const spki = (await crypto.subtle.exportKey(
      "spki",
      kp.publicKey,
    )) as ArrayBuffer;
    const msg = new TextEncoder().encode("binding payload");
    const sig = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      kp.privateKey,
      msg,
    );

    const imported = await importPublicKey(toPem(spki));
    expect(
      await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        imported,
        sig,
        msg,
      ),
    ).toBe(true);
  });

  it("imports an Ed25519 key as Ed25519 and verifies", async () => {
    const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const spki = (await crypto.subtle.exportKey(
      "spki",
      kp.publicKey,
    )) as ArrayBuffer;
    const msg = new TextEncoder().encode("binding payload");
    const sig = await crypto.subtle.sign(
      { name: "Ed25519" },
      kp.privateKey,
      msg,
    );

    const imported = await importPublicKey(toPem(spki));
    expect((imported.algorithm as { name: string }).name).toBe("Ed25519");
    expect(
      await crypto.subtle.verify({ name: "Ed25519" }, imported, sig, msg),
    ).toBe(true);
  });

  it("round-trips SPKI bytes unchanged for both curves", async () => {
    // Guards the direction that stayed correct even while the algorithm was
    // wrong: the minted cert embedded the right key bytes, which is why this
    // failed at PoP rather than producing a visibly broken certificate.
    for (const alg of [
      { name: "ECDSA", namedCurve: "P-256" },
      { name: "Ed25519" },
    ] as const) {
      const kp = (await crypto.subtle.generateKey(alg as any, true, [
        "sign",
        "verify",
      ])) as CryptoKeyPair;
      const spki = (await crypto.subtle.exportKey(
        "spki",
        kp.publicKey,
      )) as ArrayBuffer;
      const back = (await crypto.subtle.exportKey(
        "spki",
        await importPublicKey(toPem(spki)),
      )) as ArrayBuffer;
      expect(Array.from(new Uint8Array(back))).toEqual(
        Array.from(new Uint8Array(spki)),
      );
    }
  });
});
