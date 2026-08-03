/**
 * routes-dpop.test.ts — JWKS response shape.
 *
 * This file used to also cover `handleToken`, a DO-free orchestrator that
 * duplicated the /token flow but was never wired into the route. Both were
 * deleted in notme-e73c64 — see the header of src/auth/dpop-handler.ts for
 * why a parallel implementation was worse than no implementation.
 *
 * The real /token flow is covered end-to-end, against a real Durable Object,
 * in src/dpop-nonce.do.test.ts (`pnpm test:do`).
 */

import { describe, expect, it } from "vitest";
import { encodeBase64urlNoPadding } from "@oslojs/encoding";

function b64url(buf: ArrayBuffer): string {
  return encodeBase64urlNoPadding(new Uint8Array(buf));
}

async function generateEd25519Keypair(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
}

describe("buildJwksResponse", () => {
  it("returns a valid JWKS with one key", async () => {
    const { buildJwksResponse } = await import("../auth/dpop-handler");
    const kp = await generateEd25519Keypair();
    const raw = (await crypto.subtle.exportKey(
      "raw",
      kp.publicKey,
    )) as ArrayBuffer;
    const x = b64url(raw);

    const jwks = buildJwksResponse({
      kty: "OKP",
      crv: "Ed25519",
      x,
      kid: "k1",
      use: "sig",
      alg: "EdDSA",
    });

    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0].kty).toBe("OKP");
    expect(jwks.keys[0].crv).toBe("Ed25519");
    expect(jwks.keys[0].kid).toBe("k1");
    expect(jwks.keys[0].use).toBe("sig");
    expect(jwks.keys[0].alg).toBe("EdDSA");
    expect(jwks.keys[0].x).toBe(x);
  });
});
