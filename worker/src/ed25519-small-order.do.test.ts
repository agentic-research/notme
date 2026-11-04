/// <reference types="@cloudflare/vitest-plugin/types" />
/**
 * ed25519-small-order.do.test.ts — what workerd does with small-order Ed25519
 * public keys, and that every caller-supplied key path refuses them
 * (notme-48226d).
 *
 * Runs in the workers pool deliberately: the question is what workerd's
 * WebCrypto does, and Node's would answer a different question.
 *
 * THE 8 POINTS are the full order-8 torsion subgroup of edwards25519, in their
 * canonical RFC 8032 encodings. Source: the small-order test vectors of
 * Chalkias, Garillot and Nikolaenko, "Taming the many EdDSAs" (SSR 2020),
 * github.com/novifinancial/ed25519-speccheck; the same y-coordinates are the
 * rows of libsodium's `has_small_order` blocklist (crypto_core/ed25519/ref10/
 * ref10.c). Checked independently before use: each decodes, [8]P is the
 * identity, and the 8 are distinct (orders 1, 2, 4, 4, 8, 8, 8, 8).
 *
 * THE FORGERY needs no private key: R = a small-order point, S = 0. The
 * cofactorless check [S]B = R + [k]A then holds whenever [k]A = -R, so
 * trying the 8 R values over a few messages finds one for every key, and for
 * the identity key R = identity works for EVERY message.
 */
import { describe, expect, it } from "vitest";
import { AuthSession } from "./auth/auth-session";
import { verifyEd25519PopProof, verifyPopProofs } from "./auth/pop";
import { importPublicKey } from "./cert-authority";
import { isSmallOrderEd25519, isSmallOrderEd25519Key, verifyEd25519 } from "./ed25519-small-order";

const SMALL_ORDER = [
  "0100000000000000000000000000000000000000000000000000000000000000", // order 1
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 2
  "0000000000000000000000000000000000000000000000000000000000000080", // order 4
  "0000000000000000000000000000000000000000000000000000000000000000", // order 4
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8
];
/** Non-canonical aliases of small-order points: y ≥ p, or x = 0 with the sign bit set. */
const NON_CANONICAL = [
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p ≡ 0
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p+1 ≡ 1
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // y = p-1, x = 0, sign set
  "0100000000000000000000000000000000000000000000000000000000000080", // identity, sign set
];
const IDENTITY = SMALL_ORDER[0]!;

const hex = (h: string) => Uint8Array.from(h.match(/../g)!, (b) => parseInt(b, 16));
const enc = (s: string) => new TextEncoder().encode(s);
const b64u = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/** Import WITHOUT importPublicKey, so the verify-side guard is tested on its own. */
const rawKey = (h: string) => crypto.subtle.importKey("raw", hex(h), { name: "Ed25519" }, true, ["verify"]);

/** The forged signature R || 0 for small-order point R. */
const forged = (r: string) => {
  const sig = new Uint8Array(64);
  sig.set(hex(r), 0);
  return sig;
};

/** A forgery that the RAW runtime accepts for `key`, found by search: the first (R, message) that verifies. */
async function findForgery(key: CryptoKey): Promise<{ sig: Uint8Array; msg: Uint8Array } | null> {
  for (let m = 0; m < 32; m++) {
    const msg = enc(`notme small-order probe ${m}`);
    for (const r of SMALL_ORDER) {
      const sig = forged(r);
      if (await crypto.subtle.verify({ name: "Ed25519" }, key, sig, msg)) return { sig, msg };
    }
  }
  return null;
}

async function spkiPem(raw: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, true, ["verify"]);
  const spki = new Uint8Array((await crypto.subtle.exportKey("spki", key)) as ArrayBuffer);
  return `-----BEGIN PUBLIC KEY-----\n${btoa(String.fromCharCode(...spki))}\n-----END PUBLIC KEY-----`;
}

describe("workerd's Ed25519 accepts small-order public keys (the measured runtime behaviour)", () => {
  // If this block ever goes red, workerd started rejecting them itself. The
  // guards below stay — they are cheap and the runtime is not ours — but the
  // reasoning in ed25519-small-order.ts should be updated to say so.
  it.each(SMALL_ORDER)("imports %s and verifies a keyless forgery under it", async (a) => {
    const key = await rawKey(a);
    expect(await findForgery(key)).not.toBeNull();
  });

  it("the identity key verifies R = identity, S = 0 over EVERY message", async () => {
    const key = await rawKey(IDENTITY);
    for (const msg of ["", "a", "any message at all", "notme"]) {
      expect(await crypto.subtle.verify({ name: "Ed25519" }, key, forged(IDENTITY), enc(msg))).toBe(true);
    }
  });
});

describe("isSmallOrderEd25519", () => {
  it.each([...SMALL_ORDER, ...NON_CANONICAL])("flags %s", (a) => {
    expect(isSmallOrderEd25519(hex(a))).toBe(true);
  });

  it("does not flag real keys", async () => {
    for (let i = 0; i < 16; i++) {
      const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
      const raw = new Uint8Array((await crypto.subtle.exportKey("raw", kp.publicKey)) as ArrayBuffer);
      expect(isSmallOrderEd25519(raw)).toBe(false);
    }
  });

  it("fails closed on a key whose bytes cannot be read", async () => {
    const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    // A private key has no raw export: the guard must refuse, not wave it through.
    expect(await isSmallOrderEd25519Key(kp.privateKey)).toBe(true);
  });
});

describe("verifyEd25519 refuses keyless forgeries", () => {
  it.each(SMALL_ORDER)("refuses the forgery the runtime accepts under %s", async (a) => {
    const key = await rawKey(a);
    const f = (await findForgery(key))!;
    expect(await verifyEd25519(key, f.sig, f.msg)).toBe(false);
  });

  it("still verifies a genuine signature", async () => {
    const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const sig = await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, enc("hello"));
    expect(await verifyEd25519(kp.publicKey, sig, enc("hello"))).toBe(true);
    expect(await verifyEd25519(kp.publicKey, sig, enc("hellO"))).toBe(false);
  });
});

describe("every caller-supplied key path refuses a small-order key", () => {
  it("importPublicKey refuses a small-order Ed25519 SPKI (/cert, /cert/gha, authenticate(), tier enrolment and renewal)", async () => {
    for (const a of [...SMALL_ORDER, ...NON_CANONICAL.slice(0, 2)]) {
      await expect(importPublicKey(await spkiPem(hex(a)))).rejects.toThrow(/small-order/);
    }
  });

  it("importPublicKey still imports a real Ed25519 key", async () => {
    const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const raw = new Uint8Array((await crypto.subtle.exportKey("raw", kp.publicKey)) as ArrayBuffer);
    const key = await importPublicKey(await spkiPem(raw));
    expect(key.algorithm.name).toBe("Ed25519");
  });

  it("verifyEd25519PopProof (issuing-CA enrolment and tier renewal) refuses the forgery", async () => {
    const key = await rawKey(IDENTITY);
    const binding = enc("any binding the attacker likes");
    // The raw runtime would accept this proof:
    expect(await crypto.subtle.verify({ name: "Ed25519" }, key, forged(IDENTITY), binding)).toBe(true);
    expect(await verifyEd25519PopProof(binding, key, b64u(forged(IDENTITY)))).toBe(false);
  });

  it("verifyPopProofs (/cert, /cert/gha, authenticate()) refuses the Ed25519 half", async () => {
    const binding = enc("any binding the attacker likes");
    const ec = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const mtlsSig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, ec.privateKey, binding));
    const result = await verifyPopProofs(binding, ec.publicKey, await rawKey(IDENTITY), {
      mtls: b64u(mtlsSig),
      signing: b64u(forged(IDENTITY)),
    });
    expect(result).toEqual({ ok: false, algorithm: "Ed25519" });
  });

  it("AuthSession.sign() refuses a signer's output that verifies only because the key is small-order", async () => {
    const session = new AuthSession(
      {
        mtlsCert: "",
        signingCert: "",
        signingPublicKey: await rawKey(IDENTITY),
        identity: "wimse://notme.test/small-order",
        scopes: ["sign:git"],
        expiresAt: Math.floor(Date.now() / 1000) + 600,
        epoch: 1,
      },
      { env: {}, authorityState: async () => ({ epoch: 1 }) },
    );
    await expect(session.sign(enc("payload"), "raw", () => forged(IDENTITY))).rejects.toThrow(/does not verify/);
  });
});
