/**
 * token.test.ts — JWT access token minting and verification tests.
 *
 * TDD: these tests are written FIRST, before implementation.
 * Tests use raw CryptoKey objects (no Durable Object needed).
 */

import { describe, expect, it, beforeAll } from "vitest";
import { encodeBase64urlNoPadding, decodeBase64urlIgnorePadding } from "@oslojs/encoding";

// Import the functions under test (will fail until implemented)
import { mintAccessToken, verifyAccessToken } from "../auth/token";

// Helper: generate an Ed25519 keypair for testing
async function generateEd25519Keypair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: "Ed25519" } as any,
    true,
    ["sign", "verify"],
  ) as Promise<CryptoKeyPair>;
}

// Helper: decode a JWT part from base64url
function decodeJwtPart(part: string): any {
  const bytes = decodeBase64urlIgnorePadding(part);
  return JSON.parse(new TextDecoder().decode(bytes));
}

describe("mintAccessToken", () => {
  let signingKey: CryptoKey;
  let verifyKey: CryptoKey;
  const keyId = "test-kid-01";
  const defaultParams = {
    sub: "principal:alice",
    scope: "bridgeCert authorityManage",
    audience: "https://rosary.bot",
    jkt: "abc123thumbprint",
  };

  beforeAll(async () => {
    const kp = await generateEd25519Keypair();
    signingKey = kp.privateKey;
    verifyKey = kp.publicKey;
  });

  it("produces valid 3-part JWT", async () => {
    const token = await mintAccessToken({
      ...defaultParams,
      signingKey,
      keyId,
    });

    const parts = token.split(".");
    expect(parts).toHaveLength(3);

    // Each part should be non-empty base64url
    for (const part of parts) {
      expect(part.length).toBeGreaterThan(0);
      // Base64url: only [A-Za-z0-9_-] (no padding = in JWT)
      expect(part).toMatch(/^[A-Za-z0-9_-]+$/);
    }
  });

  it("header has correct typ, alg, kid", async () => {
    const token = await mintAccessToken({
      ...defaultParams,
      signingKey,
      keyId,
    });

    const header = decodeJwtPart(token.split(".")[0]);
    expect(header.typ).toBe("at+jwt");
    expect(header.alg).toBe("EdDSA");
    expect(header.kid).toBe(keyId);
  });

  it("payload has all required claims", async () => {
    const token = await mintAccessToken({
      ...defaultParams,
      signingKey,
      keyId,
    });

    const payload = decodeJwtPart(token.split(".")[1]);
    expect(payload).toHaveProperty("sub");
    expect(payload).toHaveProperty("iss");
    expect(payload).toHaveProperty("aud");
    expect(payload).toHaveProperty("iat");
    expect(payload).toHaveProperty("nbf");
    expect(payload).toHaveProperty("exp");
    expect(payload).toHaveProperty("jti");
    expect(payload).toHaveProperty("scope");
    expect(payload).toHaveProperty("cnf");
    expect(payload.cnf).toHaveProperty("jkt");
  });

  it("exp is iat + 300", async () => {
    const token = await mintAccessToken({
      ...defaultParams,
      signingKey,
      keyId,
    });

    const payload = decodeJwtPart(token.split(".")[1]);
    expect(payload.exp).toBe(payload.iat + 300);
  });

  it("cnf.jkt matches provided thumbprint", async () => {
    const thumbprint = "my-custom-thumbprint-value";
    const token = await mintAccessToken({
      ...defaultParams,
      jkt: thumbprint,
      signingKey,
      keyId,
    });

    const payload = decodeJwtPart(token.split(".")[1]);
    expect(payload.cnf.jkt).toBe(thumbprint);
  });

  it("scope is space-separated string", async () => {
    const token = await mintAccessToken({
      ...defaultParams,
      scope: "bridgeCert authorityManage certMint",
      signingKey,
      keyId,
    });

    const payload = decodeJwtPart(token.split(".")[1]);
    expect(typeof payload.scope).toBe("string");
    expect(payload.scope).toBe("bridgeCert authorityManage certMint");
    // Verify it splits correctly
    const scopes = payload.scope.split(" ");
    expect(scopes).toEqual(["bridgeCert", "authorityManage", "certMint"]);
  });

  it("sub matches provided principalId", async () => {
    const token = await mintAccessToken({
      ...defaultParams,
      sub: "principal:bob",
      signingKey,
      keyId,
    });

    const payload = decodeJwtPart(token.split(".")[1]);
    expect(payload.sub).toBe("principal:bob");
  });

  it("iss is https://auth.notme.bot", async () => {
    const token = await mintAccessToken({
      ...defaultParams,
      signingKey,
      keyId,
    });

    const payload = decodeJwtPart(token.split(".")[1]);
    expect(payload.iss).toBe("https://auth.notme.bot");
  });

  it("aud matches provided audience", async () => {
    const token = await mintAccessToken({
      ...defaultParams,
      audience: "https://mcp.rosary.bot",
      signingKey,
      keyId,
    });

    const payload = decodeJwtPart(token.split(".")[1]);
    expect(payload.aud).toBe("https://mcp.rosary.bot");
  });

  it("nbf equals iat", async () => {
    const token = await mintAccessToken({
      ...defaultParams,
      signingKey,
      keyId,
    });

    const payload = decodeJwtPart(token.split(".")[1]);
    expect(payload.nbf).toBe(payload.iat);
  });

  it("jti is a valid UUID", async () => {
    const token = await mintAccessToken({
      ...defaultParams,
      signingKey,
      keyId,
    });

    const payload = decodeJwtPart(token.split(".")[1]);
    // UUID format: 8-4-4-4-12 hex chars
    expect(payload.jti).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });
});

describe("verifyAccessToken", () => {
  let signingKey: CryptoKey;
  let verifyKey: CryptoKey;
  const keyId = "test-kid-verify";
  const defaultParams = {
    sub: "principal:alice",
    scope: "bridgeCert",
    audience: "https://rosary.bot",
    jkt: "thumbprint-abc",
  };

  beforeAll(async () => {
    const kp = await generateEd25519Keypair();
    signingKey = kp.privateKey;
    verifyKey = kp.publicKey;
  });

  it("accepts valid token", async () => {
    const token = await mintAccessToken({
      ...defaultParams,
      signingKey,
      keyId,
    });

    const claims = await verifyAccessToken(token, verifyKey);
    expect(claims.sub).toBe("principal:alice");
    expect(claims.scope).toBe("bridgeCert");
    expect(claims.aud).toBe("https://rosary.bot");
    expect(claims.cnf.jkt).toBe("thumbprint-abc");
    expect(typeof claims.exp).toBe("number");
    expect(typeof claims.jti).toBe("string");
  });

  it("rejects expired token", async () => {
    // Mint a token, then tamper its exp to be in the past.
    // We need to re-sign it or forge it. Instead, let's use a helper approach:
    // Build a token with exp in the past by constructing it manually.
    const header = { typ: "at+jwt", alg: "EdDSA", kid: keyId };
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      sub: "principal:alice",
      iss: "https://auth.notme.bot",
      aud: "https://rosary.bot",
      iat: now - 600,
      nbf: now - 600,
      exp: now - 300, // expired 5 minutes ago
      jti: crypto.randomUUID(),
      scope: "bridgeCert",
      cnf: { jkt: "thumbprint-abc" },
    };

    const headerB64 = encodeBase64urlNoPadding(
      new TextEncoder().encode(JSON.stringify(header)),
    );
    const payloadB64 = encodeBase64urlNoPadding(
      new TextEncoder().encode(JSON.stringify(payload)),
    );
    const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const sig = new Uint8Array(
      await crypto.subtle.sign("Ed25519" as any, signingKey, signingInput),
    );
    const sigB64 = encodeBase64urlNoPadding(sig);
    const token = `${headerB64}.${payloadB64}.${sigB64}`;

    await expect(verifyAccessToken(token, verifyKey)).rejects.toThrow(/expired/i);
  });

  it("rejects tampered payload", async () => {
    const token = await mintAccessToken({
      ...defaultParams,
      signingKey,
      keyId,
    });

    // Tamper with the payload by changing the sub claim
    const parts = token.split(".");
    const payload = decodeJwtPart(parts[1]);
    payload.sub = "principal:evil";
    const tamperedPayloadB64 = encodeBase64urlNoPadding(
      new TextEncoder().encode(JSON.stringify(payload)),
    );
    const tamperedToken = `${parts[0]}.${tamperedPayloadB64}.${parts[2]}`;

    await expect(verifyAccessToken(tamperedToken, verifyKey)).rejects.toThrow(
      /signature/i,
    );
  });

  it("rejects wrong signing key", async () => {
    const token = await mintAccessToken({
      ...defaultParams,
      signingKey,
      keyId,
    });

    // Generate a different keypair
    const otherKp = await generateEd25519Keypair();

    await expect(verifyAccessToken(token, otherKp.publicKey)).rejects.toThrow(
      /signature/i,
    );
  });
});

describe("mintAccessToken + verifyAccessToken roundtrip", () => {
  it("mint then verify succeeds with matching keypair", async () => {
    const kp = await generateEd25519Keypair();
    const token = await mintAccessToken({
      sub: "principal:roundtrip",
      scope: "bridgeCert authorityManage",
      audience: "https://mcp.rosary.bot",
      jkt: "roundtrip-jkt-value",
      signingKey: kp.privateKey,
      keyId: "roundtrip-kid",
    });

    const claims = await verifyAccessToken(token, kp.publicKey);
    expect(claims.sub).toBe("principal:roundtrip");
    expect(claims.scope).toBe("bridgeCert authorityManage");
    expect(claims.aud).toBe("https://mcp.rosary.bot");
    expect(claims.cnf.jkt).toBe("roundtrip-jkt-value");
    expect(claims.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(claims.jti).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });
});
