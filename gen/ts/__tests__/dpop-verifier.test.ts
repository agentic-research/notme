/**
 * dpop-verifier.test.ts — Tests for verifyDPoPToken() SDK.
 *
 * Uses real Web Crypto keys — no mocks. The publicKey option bypasses JWKS
 * fetching so tests run without network access.
 */

import { describe, expect, it, beforeAll } from "vitest";
import {
  computeJwkThumbprint,
  verifyDPoPToken,
  verifyAccessToken,
  type KVLike,
} from "../dpop";

// ── Helpers ─────────────────────────────────────────────────────────────────

/** Base64url encode bytes (no padding). */
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

/** Generate an Ed25519 keypair for signing access tokens. */
async function generateEd25519(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: "Ed25519" } as any,
    true,
    ["sign", "verify"],
  ) as Promise<CryptoKeyPair>;
}

/** Generate a P-256 keypair for DPoP proofs. */
async function generateP256(): Promise<{
  keyPair: CryptoKeyPair;
  jwk: JsonWebKey;
}> {
  const keyPair = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  return { keyPair, jwk };
}

/**
 * Mint an EdDSA access token with cnf.jkt binding.
 * Mirrors worker/src/auth/token.ts mintAccessToken but is self-contained.
 */
async function mintToken(opts: {
  signingKey: CryptoKey;
  sub: string;
  jkt: string;
  scope?: string;
  audience?: string;
  expOverride?: number;
  iatOverride?: number;
}): Promise<string> {
  const header = { typ: "at+jwt", alg: "EdDSA", kid: "test-kid" };
  const iat = opts.iatOverride ?? Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    sub: opts.sub,
    iss: "https://auth.notme.bot",
    aud: opts.audience ?? "https://example.com",
    iat,
    nbf: iat,
    exp: opts.expOverride ?? iat + 300,
    jti: crypto.randomUUID(),
    scope: opts.scope ?? "read",
    cnf: { jkt: opts.jkt },
  };

  const headerB64 = b64urlStr(JSON.stringify(header));
  const payloadB64 = b64urlStr(JSON.stringify(payload));
  const sigInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const sig = new Uint8Array(
    await crypto.subtle.sign("Ed25519" as any, opts.signingKey, sigInput),
  );
  return `${headerB64}.${payloadB64}.${b64url(sig)}`;
}

/** Mint an EdDSA access token WITHOUT cnf binding (for Bearer/redirect flows). */
async function mintUnboundToken(opts: {
  signingKey: CryptoKey;
  sub: string;
  scope?: string;
  audience?: string;
  expOverride?: number;
  iatOverride?: number;
}): Promise<string> {
  const header = { typ: "at+jwt", alg: "EdDSA", kid: "test-kid" };
  const iat = opts.iatOverride ?? Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    sub: opts.sub,
    iss: "https://auth.notme.bot",
    aud: opts.audience ?? "https://example.com",
    iat,
    nbf: iat,
    exp: opts.expOverride ?? iat + 300,
    jti: crypto.randomUUID(),
    scope: opts.scope ?? "read",
    // No cnf — this is a Bearer/redirect token, not DPoP-bound
  };

  const headerB64 = b64urlStr(JSON.stringify(header));
  const payloadB64 = b64urlStr(JSON.stringify(payload));
  const sigInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const sig = new Uint8Array(
    await crypto.subtle.sign("Ed25519" as any, opts.signingKey, sigInput),
  );
  return `${headerB64}.${payloadB64}.${b64url(sig)}`;
}

/** Build and sign a DPoP proof JWT (ES256). */
async function buildProof(opts: {
  keyPair: CryptoKeyPair;
  jwk: JsonWebKey;
  htm: string;
  htu: string;
  payloadOverrides?: Record<string, unknown>;
}): Promise<string> {
  const header = {
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: opts.jwk,
  };
  const payload = {
    jti: crypto.randomUUID(),
    htm: opts.htm,
    htu: opts.htu,
    iat: Math.floor(Date.now() / 1000),
    ...opts.payloadOverrides,
  };

  const headerB64 = b64urlStr(JSON.stringify(header));
  const payloadB64 = b64urlStr(JSON.stringify(payload));
  const sigInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    opts.keyPair.privateKey,
    sigInput,
  );
  return `${headerB64}.${payloadB64}.${b64url(sig)}`;
}

// ── Tests ───────────────────────────────────────────────────────────────────

describe("verifyDPoPToken", () => {
  let edKp: CryptoKeyPair;
  let ecKp: CryptoKeyPair;
  let ecJwk: JsonWebKey;
  let jkt: string;

  const METHOD = "GET";
  const URL = "https://api.example.com/resource";
  const JWKS_URL = "https://auth.notme.bot/.well-known/jwks.json";

  beforeAll(async () => {
    edKp = await generateEd25519();
    const ec = await generateP256();
    ecKp = ec.keyPair;
    ecJwk = ec.jwk;
    jkt = await computeJwkThumbprint(ecJwk);
  });

  // ── Happy path ──────────────────────────────────────────────────────────

  it("verifies a valid token+proof and returns claims", async () => {
    const token = await mintToken({
      signingKey: edKp.privateKey,
      sub: "principal:alice",
      jkt,
      scope: "read write",
      audience: "https://api.example.com",
    });
    const proof = await buildProof({
      keyPair: ecKp,
      jwk: ecJwk,
      htm: METHOD,
      htu: URL,
    });

    const claims = await verifyDPoPToken({
      token,
      proof,
      method: METHOD,
      url: URL,
      jwksUrl: JWKS_URL,
      publicKey: edKp.publicKey,
    });

    expect(claims.sub).toBe("principal:alice");
    expect(claims.scope).toBe("read write");
    expect(claims.aud).toBe("https://api.example.com");
    expect(typeof claims.exp).toBe("number");
    expect(claims.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(claims.jti).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });

  // ── Expired token ───────────────────────────────────────────────────────

  it("rejects an expired access token", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await mintToken({
      signingKey: edKp.privateKey,
      sub: "principal:alice",
      jkt,
      iatOverride: now - 600,
      expOverride: now - 300,
    });
    const proof = await buildProof({
      keyPair: ecKp,
      jwk: ecJwk,
      htm: METHOD,
      htu: URL,
    });

    await expect(
      verifyDPoPToken({
        token,
        proof,
        method: METHOD,
        url: URL,
        jwksUrl: JWKS_URL,
        publicKey: edKp.publicKey,
      }),
    ).rejects.toThrow(/expired/i);
  });

  // ── Invalid token signature ─────────────────────────────────────────────

  it("rejects a token signed by a different key", async () => {
    const otherKp = await generateEd25519();
    const token = await mintToken({
      signingKey: otherKp.privateKey, // signed by wrong key
      sub: "principal:alice",
      jkt,
    });
    const proof = await buildProof({
      keyPair: ecKp,
      jwk: ecJwk,
      htm: METHOD,
      htu: URL,
    });

    await expect(
      verifyDPoPToken({
        token,
        proof,
        method: METHOD,
        url: URL,
        jwksUrl: JWKS_URL,
        publicKey: edKp.publicKey, // verifying with the "correct" key
      }),
    ).rejects.toThrow(/signature/i);
  });

  // ── DPoP proof binding mismatch (wrong key) ────────────────────────────

  it("rejects when proof key does not match cnf.jkt", async () => {
    // Token is bound to ecKp's thumbprint
    const token = await mintToken({
      signingKey: edKp.privateKey,
      sub: "principal:alice",
      jkt, // bound to ecKp
    });

    // But proof is signed by a DIFFERENT EC key
    const otherEc = await generateP256();
    const proof = await buildProof({
      keyPair: otherEc.keyPair,
      jwk: otherEc.jwk,
      htm: METHOD,
      htu: URL,
    });

    await expect(
      verifyDPoPToken({
        token,
        proof,
        method: METHOD,
        url: URL,
        jwksUrl: JWKS_URL,
        publicKey: edKp.publicKey,
      }),
    ).rejects.toThrow(/binding|mismatch|thumbprint/i);
  });

  // ── htm mismatch ────────────────────────────────────────────────────────

  it("rejects when proof htm does not match request method", async () => {
    const token = await mintToken({
      signingKey: edKp.privateKey,
      sub: "principal:alice",
      jkt,
    });
    const proof = await buildProof({
      keyPair: ecKp,
      jwk: ecJwk,
      htm: "POST", // proof says POST
      htu: URL,
    });

    await expect(
      verifyDPoPToken({
        token,
        proof,
        method: "GET", // but request is GET
        url: URL,
        jwksUrl: JWKS_URL,
        publicKey: edKp.publicKey,
      }),
    ).rejects.toThrow(/htm/i);
  });

  // ── htu mismatch ────────────────────────────────────────────────────────

  it("rejects when proof htu does not match request URL", async () => {
    const token = await mintToken({
      signingKey: edKp.privateKey,
      sub: "principal:alice",
      jkt,
    });
    const proof = await buildProof({
      keyPair: ecKp,
      jwk: ecJwk,
      htm: METHOD,
      htu: "https://evil.com/steal", // wrong URL
    });

    await expect(
      verifyDPoPToken({
        token,
        proof,
        method: METHOD,
        url: URL,
        jwksUrl: JWKS_URL,
        publicKey: edKp.publicKey,
      }),
    ).rejects.toThrow(/htu/i);
  });

  // ── Strict htu matching (no prefix match) ──────────────────────────────

  it("rejects htu prefix match (strict exact match per RFC 9449)", async () => {
    const token = await mintToken({
      signingKey: edKp.privateKey,
      sub: "principal:alice",
      jkt,
    });
    // Proof htu is a prefix of the actual URL but not exact
    const proof = await buildProof({
      keyPair: ecKp,
      jwk: ecJwk,
      htm: METHOD,
      htu: "https://api.example.com", // prefix of full URL
    });

    await expect(
      verifyDPoPToken({
        token,
        proof,
        method: METHOD,
        url: "https://api.example.com/resource",
        jwksUrl: JWKS_URL,
        publicKey: edKp.publicKey,
      }),
    ).rejects.toThrow(/htu/i);
  });

  // ── Malformed inputs ──────────────────────────────────────────────────

  it("rejects malformed access token (not 3 parts)", async () => {
    const proof = await buildProof({
      keyPair: ecKp,
      jwk: ecJwk,
      htm: METHOD,
      htu: URL,
    });

    await expect(
      verifyDPoPToken({
        token: "not.a.valid.jwt.here",
        proof,
        method: METHOD,
        url: URL,
        jwksUrl: JWKS_URL,
        publicKey: edKp.publicKey,
      }),
    ).rejects.toThrow(/malformed|parts/i);
  });

  it("rejects malformed DPoP proof (not 3 parts)", async () => {
    const token = await mintToken({
      signingKey: edKp.privateKey,
      sub: "principal:alice",
      jkt,
    });

    await expect(
      verifyDPoPToken({
        token,
        proof: "only.two",
        method: METHOD,
        url: URL,
        jwksUrl: JWKS_URL,
        publicKey: edKp.publicKey,
      }),
    ).rejects.toThrow(/malformed|parts/i);
  });

  it("rejects DPoP proof with wrong typ", async () => {
    // Build a proof with typ: "JWT" instead of "dpop+jwt"
    const header = { typ: "JWT", alg: "ES256", jwk: ecJwk };
    const payload = {
      jti: crypto.randomUUID(),
      htm: METHOD,
      htu: URL,
      iat: Math.floor(Date.now() / 1000),
    };
    const headerB64 = b64urlStr(JSON.stringify(header));
    const payloadB64 = b64urlStr(JSON.stringify(payload));
    const sigInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const sig = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      ecKp.privateKey,
      sigInput,
    );
    const badProof = `${headerB64}.${payloadB64}.${b64url(sig)}`;

    const token = await mintToken({
      signingKey: edKp.privateKey,
      sub: "principal:alice",
      jkt,
    });

    await expect(
      verifyDPoPToken({
        token,
        proof: badProof,
        method: METHOD,
        url: URL,
        jwksUrl: JWKS_URL,
        publicKey: edKp.publicKey,
      }),
    ).rejects.toThrow(/typ/i);
  });

  it("rejects token missing cnf.jkt", async () => {
    // Build a token without cnf.jkt
    const header = { typ: "at+jwt", alg: "EdDSA", kid: "test-kid" };
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      sub: "principal:alice",
      iss: "https://auth.notme.bot",
      aud: "https://example.com",
      iat: now,
      nbf: now,
      exp: now + 300,
      jti: crypto.randomUUID(),
      scope: "read",
      // no cnf!
    };
    const headerB64 = b64urlStr(JSON.stringify(header));
    const payloadB64 = b64urlStr(JSON.stringify(payload));
    const sigInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const sig = new Uint8Array(
      await crypto.subtle.sign("Ed25519" as any, edKp.privateKey, sigInput),
    );
    const token = `${headerB64}.${payloadB64}.${b64url(sig)}`;

    const proof = await buildProof({
      keyPair: ecKp,
      jwk: ecJwk,
      htm: METHOD,
      htu: URL,
    });

    await expect(
      verifyDPoPToken({
        token,
        proof,
        method: METHOD,
        url: URL,
        jwksUrl: JWKS_URL,
        publicKey: edKp.publicKey,
      }),
    ).rejects.toThrow(/cnf|jkt/i);
  });

  // ── KV caching ────────────────────────────────────────────────────────

  it("works without KV (publicKey path)", async () => {
    const token = await mintToken({
      signingKey: edKp.privateKey,
      sub: "principal:bob",
      jkt,
    });
    const proof = await buildProof({
      keyPair: ecKp,
      jwk: ecJwk,
      htm: METHOD,
      htu: URL,
    });

    // No kv, using publicKey directly
    const claims = await verifyDPoPToken({
      token,
      proof,
      method: METHOD,
      url: URL,
      jwksUrl: JWKS_URL,
      publicKey: edKp.publicKey,
    });

    expect(claims.sub).toBe("principal:bob");
  });

  // ── Invalid DPoP proof signature (tampered) ─────────────────────────────

  it("rejects a DPoP proof with tampered payload", async () => {
    const token = await mintToken({
      signingKey: edKp.privateKey,
      sub: "principal:alice",
      jkt,
    });

    // Build a valid proof then tamper the payload
    const header = { typ: "dpop+jwt", alg: "ES256", jwk: ecJwk };
    const payload = {
      jti: crypto.randomUUID(),
      htm: METHOD,
      htu: URL,
      iat: Math.floor(Date.now() / 1000),
    };
    const headerB64 = b64urlStr(JSON.stringify(header));
    const payloadB64 = b64urlStr(JSON.stringify(payload));
    const sigInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const sig = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      ecKp.privateKey,
      sigInput,
    );

    // Tamper the payload after signing
    const tamperedPayload = { ...payload, htm: "DELETE" };
    const tamperedPayloadB64 = b64urlStr(JSON.stringify(tamperedPayload));
    const tamperedProof = `${headerB64}.${tamperedPayloadB64}.${b64url(sig)}`;

    await expect(
      verifyDPoPToken({
        token,
        proof: tamperedProof,
        method: "DELETE",
        url: URL,
        jwksUrl: JWKS_URL,
        publicKey: edKp.publicKey,
      }),
    ).rejects.toThrow(/signature/i);
  });

  // ── HIGH: Proof replay (missing iat/jti validation) ───────────────────

  it("HIGH: rejects DPoP proof with missing iat claim", async () => {
    const token = await mintToken({
      signingKey: edKp.privateKey,
      sub: "principal:alice",
      jkt,
    });
    // Proof without iat — enables indefinite replay
    const proof = await buildProof({
      keyPair: ecKp,
      jwk: ecJwk,
      htm: METHOD,
      htu: URL,
      payloadOverrides: { iat: undefined },
    });

    await expect(
      verifyDPoPToken({
        token, proof, method: METHOD, url: URL,
        jwksUrl: JWKS_URL, publicKey: edKp.publicKey,
      }),
    ).rejects.toThrow(/iat/i);
  });

  it("HIGH: rejects DPoP proof with stale iat (>60s old)", async () => {
    const token = await mintToken({
      signingKey: edKp.privateKey,
      sub: "principal:alice",
      jkt,
    });
    const proof = await buildProof({
      keyPair: ecKp,
      jwk: ecJwk,
      htm: METHOD,
      htu: URL,
      payloadOverrides: { iat: Math.floor(Date.now() / 1000) - 120 },
    });

    await expect(
      verifyDPoPToken({
        token, proof, method: METHOD, url: URL,
        jwksUrl: JWKS_URL, publicKey: edKp.publicKey,
      }),
    ).rejects.toThrow(/iat|old|expired|future/i);
  });

  it("HIGH: rejects DPoP proof with future iat", async () => {
    const token = await mintToken({
      signingKey: edKp.privateKey,
      sub: "principal:alice",
      jkt,
    });
    const proof = await buildProof({
      keyPair: ecKp,
      jwk: ecJwk,
      htm: METHOD,
      htu: URL,
      payloadOverrides: { iat: Math.floor(Date.now() / 1000) + 120 },
    });

    await expect(
      verifyDPoPToken({
        token, proof, method: METHOD, url: URL,
        jwksUrl: JWKS_URL, publicKey: edKp.publicKey,
      }),
    ).rejects.toThrow(/iat|old|expired|future/i);
  });

  it("HIGH: rejects DPoP proof with missing jti claim", async () => {
    const token = await mintToken({
      signingKey: edKp.privateKey,
      sub: "principal:alice",
      jkt,
    });
    const proof = await buildProof({
      keyPair: ecKp,
      jwk: ecJwk,
      htm: METHOD,
      htu: URL,
      payloadOverrides: { jti: undefined },
    });

    await expect(
      verifyDPoPToken({
        token, proof, method: METHOD, url: URL,
        jwksUrl: JWKS_URL, publicKey: edKp.publicKey,
      }),
    ).rejects.toThrow(/jti/i);
  });
});

// ── verifyAccessToken (redirect flow, no DPoP proof) ──────────────────────

describe("verifyAccessToken", () => {
  let edKp: CryptoKeyPair;
  let jkt: string;

  const JWKS_URL = "https://auth.notme.bot/.well-known/jwks.json";

  beforeAll(async () => {
    edKp = await generateEd25519();
    const ec = await generateP256();
    jkt = await computeJwkThumbprint(ec.jwk);
  });

  it("verifies a valid unbound token", async () => {
    const token = await mintUnboundToken({
      signingKey: edKp.privateKey,
      sub: "principal:alice",
      scope: "bridgeCert authorityManage",
      audience: "https://rosary.bot",
    });

    const claims = await verifyAccessToken({
      token,
      jwksUrl: JWKS_URL,
      publicKey: edKp.publicKey,
    });

    expect(claims.sub).toBe("principal:alice");
    expect(claims.scope).toBe("bridgeCert authorityManage");
    expect(claims.aud).toBe("https://rosary.bot");
    expect(claims.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it("rejects an expired token", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await mintUnboundToken({
      signingKey: edKp.privateKey,
      sub: "principal:alice",
      iatOverride: now - 600,
      expOverride: now - 300,
    });

    await expect(
      verifyAccessToken({ token, jwksUrl: JWKS_URL, publicKey: edKp.publicKey }),
    ).rejects.toThrow(/expired/i);
  });

  it("rejects a token signed by a different key", async () => {
    const otherKp = await generateEd25519();
    const token = await mintUnboundToken({
      signingKey: otherKp.privateKey,
      sub: "principal:alice",
    });

    await expect(
      verifyAccessToken({ token, jwksUrl: JWKS_URL, publicKey: edKp.publicKey }),
    ).rejects.toThrow(/signature/i);
  });

  it("rejects malformed token", async () => {
    await expect(
      verifyAccessToken({ token: "bad", jwksUrl: JWKS_URL, publicKey: edKp.publicKey }),
    ).rejects.toThrow(/malformed|parts/i);
  });

  it("CRITICAL: rejects DPoP-bound token used as Bearer (downgrade attack)", async () => {
    // RFC 9449 Section 3: a DPoP-bound token (has cnf.jkt) MUST NOT be accepted
    // as a plain Bearer token. An attacker who steals the token from logs can
    // strip the DPoP header and replay as Bearer.
    const token = await mintToken({
      signingKey: edKp.privateKey,
      sub: "principal:alice",
      jkt,  // <-- this token is DPoP-bound (has cnf.jkt)
      scope: "read",
    });

    // verifyAccessToken (Bearer path) must reject tokens with cnf claim
    await expect(
      verifyAccessToken({ token, jwksUrl: JWKS_URL, publicKey: edKp.publicKey }),
    ).rejects.toThrow(/dpop.bound|cnf|bearer/i);
  });
});
