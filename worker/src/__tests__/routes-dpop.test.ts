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
    // True ordering test: instrument BOTH callbacks so we observe the
    // call sequence. The earlier "throw from storeJti and check no token
    // returned" test couldn't distinguish bug from fix — under either
    // order the throw propagates and result.ok is false. Code-reviewer
    // sub-agent caught this (HIGH).
    //
    // Strategy: wrap the signingKey with a Proxy that intercepts the
    // .sign() that mintAccessToken eventually calls (via crypto.subtle.
    // sign). When that fires, we record "mint-sign". storeJti records
    // "store". Asserting events[0] === "store" means store ran first.
    const handleToken = await getHandler();
    const proof = await buildDpopProof({
      keyPair: dpopKeyPair,
      htm: "POST",
      htu: "https://auth.notme.bot/token",
    });

    const events: string[] = [];

    // crypto.subtle.sign is global; monkey-patch for the duration of
    // this test, restore after. We only want to record the sign call
    // that mintAccessToken makes — DPoP proof verification uses
    // crypto.subtle.verify, not sign, so no false hit.
    const origSign = crypto.subtle.sign.bind(crypto.subtle);
    (crypto.subtle as any).sign = (...args: unknown[]) => {
      events.push("mint-sign");
      return origSign(...(args as Parameters<typeof origSign>));
    };

    try {
      const result = await handleToken({
        dpopProof: proof,
        session: { principalId: "alice", scopes: ["bridgeCert"], authMethod: "passkey", exp: Math.floor(Date.now() / 1000) + 3600 },
        tokenEndpointUrl: "https://auth.notme.bot/token",
        audience: "https://rosary.bot",
        signingKey: masterKeyPair.privateKey,
        keyId: "test-kid",
        checkJtiReplay: async () => false,
        storeJti: async () => {
          events.push("store");
        },
      });
      expect(result.ok).toBe(true);
    } finally {
      (crypto.subtle as any).sign = origSign;
    }

    // The fix order: replay-check, store, mint. The buggy order was
    // store after mint. If "mint-sign" appears before "store", the bug
    // is back.
    const storeIdx = events.indexOf("store");
    const mintIdx = events.indexOf("mint-sign");
    expect(storeIdx).toBeGreaterThanOrEqual(0);
    expect(mintIdx).toBeGreaterThan(storeIdx);
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
