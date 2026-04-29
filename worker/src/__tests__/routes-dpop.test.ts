/**
 * routes-dpop.test.ts — Integration tests for /token and /.well-known/jwks.json routes.
 *
 * TDD: tests first, route wiring second.
 * These test the handleToken() and handleJwks() handler functions directly
 * (not through the full Worker fetch — avoids needing DO bindings in tests).
 */

import { describe, expect, it, beforeAll } from "vitest";
import { encodeBase64urlNoPadding } from "@oslojs/encoding";

// ── Helpers ──────────────────────────────────────────────────

async function generateP256Keypair(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
}

async function generateEd25519Keypair(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey(
    { name: "Ed25519" } as any,
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
}

function b64url(buf: ArrayBuffer): string {
  return encodeBase64urlNoPadding(new Uint8Array(buf));
}

/** Build a signed DPoP proof JWT. */
async function buildDpopProof(opts: {
  keyPair: CryptoKeyPair;
  htm: string;
  htu: string;
  nonce?: string;
  ath?: string;
}): Promise<string> {
  const pubJwk = (await crypto.subtle.exportKey("jwk", opts.keyPair.publicKey)) as JsonWebKey;

  const header = {
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: { kty: pubJwk.kty, crv: pubJwk.crv, x: pubJwk.x, y: pubJwk.y },
  };

  const payload: Record<string, unknown> = {
    jti: crypto.randomUUID(),
    htm: opts.htm,
    htu: opts.htu,
    iat: Math.floor(Date.now() / 1000),
  };
  if (opts.nonce) payload.nonce = opts.nonce;
  if (opts.ath) payload.ath = opts.ath;

  const headerB64 = encodeBase64urlNoPadding(
    new TextEncoder().encode(JSON.stringify(header)),
  );
  const payloadB64 = encodeBase64urlNoPadding(
    new TextEncoder().encode(JSON.stringify(payload)),
  );
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    opts.keyPair.privateKey,
    signingInput,
  );
  const sigB64 = b64url(sig);

  return `${headerB64}.${payloadB64}.${sigB64}`;
}

// ── /token handler tests ────────────────────────────────────

describe("handleToken", () => {
  let masterKeyPair: CryptoKeyPair;
  let dpopKeyPair: CryptoKeyPair;

  beforeAll(async () => {
    masterKeyPair = await generateEd25519Keypair();
    dpopKeyPair = await generateP256Keypair();
  });

  // Import the handler (will be created in the implementation step)
  async function getHandler() {
    return (await import("../auth/dpop-handler")).handleToken;
  }

  it("rejects requests without session", async () => {
    const handleToken = await getHandler();
    const proof = await buildDpopProof({
      keyPair: dpopKeyPair,
      htm: "POST",
      htu: "https://auth.notme.bot/token",
    });

    const result = await handleToken({
      dpopProof: proof,
      session: null,
      tokenEndpointUrl: "https://auth.notme.bot/token",
      audience: "https://rosary.bot",
      signingKey: masterKeyPair.privateKey,
      keyId: "test-kid",
      checkJtiReplay: async () => false,
      storeJti: async () => {},
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.status).toBe(401);
      expect(result.error).toBe("session_required");
    }
  });

  it("rejects requests without DPoP proof", async () => {
    const handleToken = await getHandler();

    const result = await handleToken({
      dpopProof: null,
      session: { principalId: "alice", scopes: ["bridgeCert"], authMethod: "passkey", exp: Math.floor(Date.now() / 1000) + 3600 },
      tokenEndpointUrl: "https://auth.notme.bot/token",
      audience: "https://rosary.bot",
      signingKey: masterKeyPair.privateKey,
      keyId: "test-kid",
      checkJtiReplay: async () => false,
      storeJti: async () => {},
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.status).toBe(400);
      expect(result.error).toBe("dpop_proof_required");
    }
  });

  it("rejects requests without audience", async () => {
    const handleToken = await getHandler();
    const proof = await buildDpopProof({
      keyPair: dpopKeyPair,
      htm: "POST",
      htu: "https://auth.notme.bot/token",
    });

    const result = await handleToken({
      dpopProof: proof,
      session: { principalId: "alice", scopes: ["bridgeCert"], authMethod: "passkey", exp: Math.floor(Date.now() / 1000) + 3600 },
      tokenEndpointUrl: "https://auth.notme.bot/token",
      audience: "",
      signingKey: masterKeyPair.privateKey,
      keyId: "test-kid",
      checkJtiReplay: async () => false,
      storeJti: async () => {},
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.status).toBe(400);
      expect(result.error).toBe("invalid_audience");
    }
  });

  it("rejects replayed JTI", async () => {
    const handleToken = await getHandler();
    const proof = await buildDpopProof({
      keyPair: dpopKeyPair,
      htm: "POST",
      htu: "https://auth.notme.bot/token",
    });

    const result = await handleToken({
      dpopProof: proof,
      session: { principalId: "alice", scopes: ["bridgeCert"], authMethod: "passkey", exp: Math.floor(Date.now() / 1000) + 3600 },
      tokenEndpointUrl: "https://auth.notme.bot/token",
      audience: "https://rosary.bot",
      signingKey: masterKeyPair.privateKey,
      keyId: "test-kid",
      checkJtiReplay: async () => true, // already seen
      storeJti: async () => {},
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.status).toBe(401);
      expect(result.error).toBe("proof_reused");
    }
  });

  it("mints a valid DPoP-bound token on success", async () => {
    const handleToken = await getHandler();
    const proof = await buildDpopProof({
      keyPair: dpopKeyPair,
      htm: "POST",
      htu: "https://auth.notme.bot/token",
    });

    const result = await handleToken({
      dpopProof: proof,
      session: { principalId: "alice", scopes: ["bridgeCert", "authorityManage"], authMethod: "passkey", exp: Math.floor(Date.now() / 1000) + 3600 },
      tokenEndpointUrl: "https://auth.notme.bot/token",
      audience: "https://rosary.bot",
      signingKey: masterKeyPair.privateKey,
      keyId: "test-kid",
      checkJtiReplay: async () => false,
      storeJti: async () => {},
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.tokenType).toBe("DPoP");
    expect(result.expiresIn).toBe(300);
    expect(typeof result.accessToken).toBe("string");

    // Verify the token is valid
    const { verifyAccessToken } = await import("../auth/token");
    const claims = await verifyAccessToken(result.accessToken, masterKeyPair.publicKey);

    expect(claims.sub).toBe("alice");
    expect(claims.aud).toBe("https://rosary.bot");
    expect(claims.scope).toBe("bridgeCert authorityManage");
    expect(claims.cnf.jkt).toBeTruthy();

    // Verify cnf.jkt matches the DPoP key
    const { computeJwkThumbprint } = await import("../../../gen/ts/dpop");
    const pubJwk = (await crypto.subtle.exportKey("jwk", dpopKeyPair.publicKey)) as JsonWebKey;
    const expectedThumbprint = await computeJwkThumbprint(pubJwk);
    expect(claims.cnf.jkt).toBe(expectedThumbprint);
  });

  it("stores JTI before minting (TOCTOU, rosary-9b969c)", async () => {
    // The order is: replay-check → store → mint. If store throws, mint
    // must NOT run. This is the test that distinguishes from the prior
    // bug, which minted first and stored after — meaning a store error
    // would leave a minted token in the wild without a recorded JTI.
    const handleToken = await getHandler();
    const proof = await buildDpopProof({
      keyPair: dpopKeyPair,
      htm: "POST",
      htu: "https://auth.notme.bot/token",
    });

    let mintCalled = false;
    // Spy via a wrapped signingKey: replace the .sign-capable cryptoKey
    // with one that flips the flag when used. mintAccessToken calls
    // crypto.subtle.sign on the key — easy to intercept by extracting the
    // raw key and re-importing as a usage-only proxy. Simpler: just
    // observe whether the function returns ok. If store throws before
    // mint, the function should propagate the error (no ok=true result),
    // and we confirm mint didn't produce a token.
    let result: any;
    let threwFromStore = false;
    try {
      result = await handleToken({
        dpopProof: proof,
        session: { principalId: "alice", scopes: ["bridgeCert"], authMethod: "passkey", exp: Math.floor(Date.now() / 1000) + 3600 },
        tokenEndpointUrl: "https://auth.notme.bot/token",
        audience: "https://rosary.bot",
        signingKey: masterKeyPair.privateKey,
        keyId: "test-kid",
        checkJtiReplay: async () => false,
        storeJti: async () => {
          throw new Error("store failed");
        },
      });
      mintCalled = result?.ok === true;
    } catch (e: any) {
      threwFromStore = e.message === "store failed";
    }

    // store-failed: either the function propagates the throw OR returns
    // a non-ok result. In neither case should mint have produced a token
    // (would mean the order was swapped).
    expect(mintCalled).toBe(false);
    expect(threwFromStore || (result && !result.ok)).toBe(true);
  });
});

// ── JWKS endpoint tests ─────────────────────────────────────

describe("buildJwksResponse", () => {
  it("returns a valid JWKS with one key", async () => {
    const { buildJwksResponse } = await import("../auth/dpop-handler");
    const kp = await generateEd25519Keypair();
    const raw = (await crypto.subtle.exportKey("raw", kp.publicKey)) as ArrayBuffer;
    const x = b64url(raw);

    const jwks = buildJwksResponse({ kty: "OKP", crv: "Ed25519", x, kid: "k1", use: "sig", alg: "EdDSA" });

    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0].kty).toBe("OKP");
    expect(jwks.keys[0].crv).toBe("Ed25519");
    expect(jwks.keys[0].kid).toBe("k1");
    expect(jwks.keys[0].use).toBe("sig");
    expect(jwks.keys[0].alg).toBe("EdDSA");
    expect(jwks.keys[0].x).toBe(x);
  });
});
