/**
 * dpop.test.ts — DPoP proof validation + JWK Thumbprint tests (RFC 9449 / RFC 7638).
 * Maps to docs/design/006-dpop-tokens.md
 *
 * TDD: tests written first, implementation follows.
 * Uses Web Crypto to generate real P-256 keypairs and sign real JWTs.
 */

import { describe, expect, it } from "vitest";

// ── Helpers: build real DPoP proofs with Web Crypto ──────────────────────────

/** Base64url encode a Uint8Array (no padding). */
function b64url(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

/** Base64url encode a UTF-8 string. */
function b64urlStr(s: string): string {
  return b64url(new TextEncoder().encode(s));
}

/** Generate a P-256 keypair and export the public JWK. */
async function generateP256(): Promise<{
  keyPair: CryptoKeyPair;
  jwk: JsonWebKey;
}> {
  const keyPair = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", keyPair.publicKey)) as JsonWebKey;
  return { keyPair, jwk };
}

/** Build and sign a DPoP proof JWT. */
async function buildDpopProof(opts: {
  keyPair: CryptoKeyPair;
  jwk: JsonWebKey;
  headerOverrides?: Record<string, unknown>;
  payloadOverrides?: Record<string, unknown>;
  skipSign?: boolean;
  tamperPayload?: boolean;
}): Promise<string> {
  const header = {
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: opts.jwk,
    ...opts.headerOverrides,
  };
  const payload = {
    jti: crypto.randomUUID(),
    htm: "POST",
    htu: "https://auth.notme.bot/token",
    iat: Math.floor(Date.now() / 1000),
    ...opts.payloadOverrides,
  };

  const headerB64 = b64urlStr(JSON.stringify(header));
  const payloadB64 = b64urlStr(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;

  const sigBytes = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    opts.keyPair.privateKey,
    new TextEncoder().encode(signingInput),
  );
  const sigB64 = b64url(sigBytes);

  if (opts.tamperPayload) {
    // Change the payload AFTER signing to break the signature
    const tamperedPayload = { ...payload, htm: "DELETE" };
    const tamperedPayloadB64 = b64urlStr(JSON.stringify(tamperedPayload));
    return `${headerB64}.${tamperedPayloadB64}.${sigB64}`;
  }

  return `${headerB64}.${payloadB64}.${sigB64}`;
}

// ── JWK Thumbprint (RFC 7638) ────────────────────────────────────────────────

describe("computeJwkThumbprint", () => {
  it("computes correct SHA-256 thumbprint for a known EC key", async () => {
    const { computeJwkThumbprint } = await import("../../../gen/ts/dpop");

    // RFC 7638 Section 3.1 uses an RSA key, but the algorithm is the same.
    // We use a deterministic EC key (fixed x, y) and verify the computation.
    const ecJwk: JsonWebKey = {
      kty: "EC",
      crv: "P-256",
      x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    };

    // Expected: SHA-256 of '{"crv":"P-256","kty":"EC","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}'
    // Canonical JSON: members sorted alphabetically: crv, kty, x, y
    const canonicalJson =
      '{"crv":"P-256","kty":"EC","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}';
    const hash = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(canonicalJson),
    );
    const expected = b64url(hash);

    const thumbprint = await computeJwkThumbprint(ecJwk);
    expect(thumbprint).toBe(expected);
  });

  it("excludes non-required members (alg, kid, use)", async () => {
    const { computeJwkThumbprint } = await import("../../../gen/ts/dpop");

    const bareJwk: JsonWebKey = {
      kty: "EC",
      crv: "P-256",
      x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    };

    const jwkWithExtras = {
      kty: "EC",
      crv: "P-256",
      x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      alg: "ES256",
      kid: "key-1",
      use: "sig",
      key_ops: ["verify"],
    } as JsonWebKey;

    const t1 = await computeJwkThumbprint(bareJwk);
    const t2 = await computeJwkThumbprint(jwkWithExtras);
    expect(t1).toBe(t2);
  });

  it("is deterministic (same key = same thumbprint)", async () => {
    const { computeJwkThumbprint } = await import("../../../gen/ts/dpop");

    const jwk: JsonWebKey = {
      kty: "EC",
      crv: "P-256",
      x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    };

    const t1 = await computeJwkThumbprint(jwk);
    const t2 = await computeJwkThumbprint(jwk);
    expect(t1).toBe(t2);
    // Thumbprints are base64url SHA-256 → 43 chars
    expect(t1.length).toBe(43);
  });
});

// ── DPoP Proof Validation (RFC 9449) ─────────────────────────────────────────

describe("validateDpopProof", () => {
  it("accepts a valid proof", async () => {
    const { validateDpopProof } = await import("../auth/dpop");
    const { keyPair, jwk } = await generateP256();

    const proof = await buildDpopProof({ keyPair, jwk });
    const result = await validateDpopProof(proof, {
      htm: "POST",
      htu: "https://auth.notme.bot/token",
    });

    expect(result.jwk).toBeDefined();
    expect(result.jti).toBeDefined();
    expect(typeof result.jti).toBe("string");
    expect(result.thumbprint).toBeDefined();
    expect(typeof result.thumbprint).toBe("string");
  });

  it("rejects wrong typ header", async () => {
    const { validateDpopProof } = await import("../auth/dpop");
    const { keyPair, jwk } = await generateP256();

    const proof = await buildDpopProof({
      keyPair,
      jwk,
      headerOverrides: { typ: "JWT" },
    });

    await expect(
      validateDpopProof(proof, {
        htm: "POST",
        htu: "https://auth.notme.bot/token",
      }),
    ).rejects.toThrow(/typ/i);
  });

  it("rejects wrong alg", async () => {
    const { validateDpopProof } = await import("../auth/dpop");
    const { keyPair, jwk } = await generateP256();

    const proof = await buildDpopProof({
      keyPair,
      jwk,
      headerOverrides: { alg: "RS256" },
    });

    await expect(
      validateDpopProof(proof, {
        htm: "POST",
        htu: "https://auth.notme.bot/token",
      }),
    ).rejects.toThrow(/alg/i);
  });

  it("rejects invalid signature (tampered payload)", async () => {
    const { validateDpopProof } = await import("../auth/dpop");
    const { keyPair, jwk } = await generateP256();

    const proof = await buildDpopProof({
      keyPair,
      jwk,
      tamperPayload: true,
    });

    await expect(
      validateDpopProof(proof, {
        htm: "DELETE",
        htu: "https://auth.notme.bot/token",
      }),
    ).rejects.toThrow(/signature/i);
  });

  it("rejects expired iat (>60s old)", async () => {
    const { validateDpopProof } = await import("../auth/dpop");
    const { keyPair, jwk } = await generateP256();

    const proof = await buildDpopProof({
      keyPair,
      jwk,
      payloadOverrides: { iat: Math.floor(Date.now() / 1000) - 120 },
    });

    await expect(
      validateDpopProof(proof, {
        htm: "POST",
        htu: "https://auth.notme.bot/token",
      }),
    ).rejects.toThrow(/iat|expired|old/i);
  });

  it("rejects htm mismatch", async () => {
    const { validateDpopProof } = await import("../auth/dpop");
    const { keyPair, jwk } = await generateP256();

    const proof = await buildDpopProof({
      keyPair,
      jwk,
      payloadOverrides: { htm: "GET" },
    });

    await expect(
      validateDpopProof(proof, {
        htm: "POST",
        htu: "https://auth.notme.bot/token",
      }),
    ).rejects.toThrow(/htm/i);
  });

  it("rejects htu mismatch", async () => {
    const { validateDpopProof } = await import("../auth/dpop");
    const { keyPair, jwk } = await generateP256();

    const proof = await buildDpopProof({
      keyPair,
      jwk,
      payloadOverrides: { htu: "https://evil.com/token" },
    });

    await expect(
      validateDpopProof(proof, {
        htm: "POST",
        htu: "https://auth.notme.bot/token",
      }),
    ).rejects.toThrow(/htu/i);
  });

  it("rejects missing jti", async () => {
    const { validateDpopProof } = await import("../auth/dpop");
    const { keyPair, jwk } = await generateP256();

    const proof = await buildDpopProof({
      keyPair,
      jwk,
      payloadOverrides: { jti: undefined },
    });

    await expect(
      validateDpopProof(proof, {
        htm: "POST",
        htu: "https://auth.notme.bot/token",
      }),
    ).rejects.toThrow(/jti/i);
  });

  it("validates nonce when provided", async () => {
    const { validateDpopProof } = await import("../auth/dpop");
    const { keyPair, jwk } = await generateP256();

    // Proof with correct nonce
    const goodProof = await buildDpopProof({
      keyPair,
      jwk,
      payloadOverrides: { nonce: "server-nonce-123" },
    });

    const result = await validateDpopProof(goodProof, {
      htm: "POST",
      htu: "https://auth.notme.bot/token",
      nonce: "server-nonce-123",
    });
    expect(result.jwk).toBeDefined();

    // Proof with wrong nonce
    const badProof = await buildDpopProof({
      keyPair,
      jwk,
      payloadOverrides: { nonce: "wrong-nonce" },
    });

    await expect(
      validateDpopProof(badProof, {
        htm: "POST",
        htu: "https://auth.notme.bot/token",
        nonce: "server-nonce-123",
      }),
    ).rejects.toThrow(/nonce/i);
  });

  it("validates ath when provided", async () => {
    const { validateDpopProof } = await import("../auth/dpop");
    const { keyPair, jwk } = await generateP256();

    // Compute ath = base64url(SHA-256(access_token))
    const accessToken = "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCJ9.test.sig";
    const athHash = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(accessToken),
    );
    const ath = b64url(athHash);

    // Proof with correct ath
    const goodProof = await buildDpopProof({
      keyPair,
      jwk,
      payloadOverrides: { ath },
    });

    const result = await validateDpopProof(goodProof, {
      htm: "POST",
      htu: "https://auth.notme.bot/token",
      accessTokenHash: ath,
    });
    expect(result.jwk).toBeDefined();

    // Proof with wrong ath
    const badProof = await buildDpopProof({
      keyPair,
      jwk,
      payloadOverrides: { ath: "wrong-hash" },
    });

    await expect(
      validateDpopProof(badProof, {
        htm: "POST",
        htu: "https://auth.notme.bot/token",
        accessTokenHash: ath,
      }),
    ).rejects.toThrow(/ath/i);
  });

  it("returned thumbprint matches computeJwkThumbprint", async () => {
    const { validateDpopProof } = await import("../auth/dpop");
    const { computeJwkThumbprint } = await import("../../../gen/ts/dpop");
    const { keyPair, jwk } = await generateP256();

    const proof = await buildDpopProof({ keyPair, jwk });
    const result = await validateDpopProof(proof, {
      htm: "POST",
      htu: "https://auth.notme.bot/token",
    });

    const expectedThumbprint = await computeJwkThumbprint(jwk);
    expect(result.thumbprint).toBe(expectedThumbprint);
  });
});
