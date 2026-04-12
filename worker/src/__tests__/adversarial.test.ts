import { describe, it, expect } from "vitest";
import { validateGHAToken } from "../gha-oidc";
import { mintAccessToken, verifyAccessToken } from "../auth/token";
import { timingSafeEqual } from "../auth/timing-safe";

/**
 * adversarial.test.ts — Verify key extraction invariants + adversarial token invariants.
 *
 * Maps to THREAT_MODEL.md: signing.key.isolation (invariant #4),
 *   forgery.alg-none (#1), expiry (#2), scope-escalation (#5), key-leak (#6)
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
    expect((spki as ArrayBuffer).byteLength).toBeGreaterThan(0);
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

// ── Token forgery (invariants #1, #2) ────────────────────────────────────────

describe("adversarial: token forgery", () => {
  it("rejects JWT with alg: none (invariant #1)", async () => {
    // Build a well-formed JWT with alg:none — no signature.
    // validateGHAToken checks header.alg === "RS256" before touching the network.
    const header = btoa(JSON.stringify({ alg: "none", typ: "JWT" }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
    const payload = btoa(
      JSON.stringify({
        iss: "https://token.actions.githubusercontent.com",
        sub: "repo:evil/repo:ref:refs/heads/main",
        aud: "notme.bot",
        exp: Math.floor(Date.now() / 1000) + 300,
        iat: Math.floor(Date.now() / 1000),
      }),
    )
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
    const fakeJwt = `${header}.${payload}.`;

    // Must throw (caller converts to 401) — must not silently accept
    await expect(validateGHAToken(fakeJwt, "notme.bot")).rejects.toThrow(
      /unsupported alg/i,
    );
  });

  it("rejects expired token (invariant #2)", async () => {
    // Build an RS256-claimed JWT with exp in the past.
    // validateGHAToken checks exp < now before fetching JWKS — fast-fail path.
    const header = btoa(JSON.stringify({ alg: "RS256", kid: "test-kid" }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
    const payload = btoa(
      JSON.stringify({
        iss: "https://token.actions.githubusercontent.com",
        aud: "notme.bot",
        exp: Math.floor(Date.now() / 1000) - 600, // expired 10 min ago
        iat: Math.floor(Date.now() / 1000) - 900,
      }),
    )
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");

    await expect(
      validateGHAToken(`${header}.${payload}.AAAA`, "notme.bot"),
    ).rejects.toThrow(/expired/i);
  });

  it("rejects malformed JWT (wrong part count)", async () => {
    await expect(validateGHAToken("not.a.valid.jwt", "notme.bot")).rejects.toThrow(
      /malformed/i,
    );
  });

  it("rejects wrong issuer", async () => {
    const header = btoa(JSON.stringify({ alg: "RS256", kid: "test-kid" }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
    const payload = btoa(
      JSON.stringify({
        iss: "https://evil.example.com", // wrong issuer
        aud: "notme.bot",
        exp: Math.floor(Date.now() / 1000) + 300,
        iat: Math.floor(Date.now() / 1000),
      }),
    )
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");

    await expect(
      validateGHAToken(`${header}.${payload}.AAAA`, "notme.bot"),
    ).rejects.toThrow(/issuer/i);
  });
});

// ── Scope escalation (invariant #5) ──────────────────────────────────────────

describe("adversarial: scope escalation", () => {
  it("bootstrap code single-use: second call returns false (invariant #5)", async () => {
    // Simulate the consumeBootstrapCode one-time-use invariant without a real DO.
    // The logic: a code is stored with used=0; first consume marks used=1; second fails.
    //
    // We can't instantiate SigningAuthority outside Workerd, so we verify the
    // underlying timing-safe comparison + used-flag logic directly.

    let used = false;
    const storedCode = crypto.randomUUID();

    // consumeBootstrapCode equivalent — first call
    async function consumeCode(attempt: string): Promise<boolean> {
      if (used) return false;
      const match = await timingSafeEqual(storedCode, attempt);
      if (!match) return false;
      used = true; // mark consumed
      return true;
    }

    // First use: must succeed
    const first = await consumeCode(storedCode);
    expect(first).toBe(true);

    // Second use: same code, must fail (used flag is set)
    const second = await consumeCode(storedCode);
    expect(second).toBe(false);
  });

  it("bootstrap code: wrong code is rejected", async () => {
    let used = false;
    const storedCode = crypto.randomUUID();

    async function consumeCode(attempt: string): Promise<boolean> {
      if (used) return false;
      const match = await timingSafeEqual(storedCode, attempt);
      if (!match) return false;
      used = true;
      return true;
    }

    const result = await consumeCode("totally-wrong-code");
    expect(result).toBe(false);
    // used must still be false — code was not burned
    expect(used).toBe(false);
  });

  it("timingSafeEqual is constant-time safe: equal strings return true", async () => {
    const a = "secure-bootstrap-code-example";
    expect(await timingSafeEqual(a, a)).toBe(true);
  });

  it("timingSafeEqual: different strings return false", async () => {
    expect(await timingSafeEqual("code-a", "code-b")).toBe(false);
  });
});

// ── Error message leak (invariant #6) ────────────────────────────────────────

describe("adversarial: error message leak", () => {
  it("mintAccessToken output contains no Ed25519 private 'd' field", async () => {
    // The minted JWT is a public document. It must NEVER contain the private key
    // 'd' field (the JWK private scalar) or PEM private key headers.
    const kp = (await crypto.subtle.generateKey(
      { name: "Ed25519" } as any,
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;

    const privateJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
    // Re-import as non-extractable (mirrors SigningAuthority behavior)
    const signingKey = await crypto.subtle.importKey(
      "jwk",
      privateJwk,
      { name: "Ed25519" } as any,
      false,
      ["sign"],
    );

    const token = await mintAccessToken({
      sub: "principal:test",
      scope: "bridgeCert",
      audience: "https://rosary.bot",
      jkt: "test-thumbprint",
      signingKey,
      keyId: "test-kid",
    });

    // JWT is three base64url segments — none should contain private key material
    expect(token).not.toMatch(/"d"\s*:\s*"[A-Za-z0-9_-]+"/);
    expect(token).not.toContain("BEGIN PRIVATE KEY");

    // Decode header and payload, confirm no 'd' field leaks through
    const [headerB64, payloadB64] = token.split(".");
    const header = JSON.parse(atob(headerB64!.replace(/-/g, "+").replace(/_/g, "/")));
    const payload = JSON.parse(atob(payloadB64!.replace(/-/g, "+").replace(/_/g, "/")));

    expect(header).not.toHaveProperty("d");
    expect(payload).not.toHaveProperty("d");
  });

  it("verifyAccessToken error messages do not leak key material", async () => {
    // Verify that errors thrown by verifyAccessToken (tampered signature, etc.)
    // do not contain key material such as the JWK 'd' scalar.
    const kp = (await crypto.subtle.generateKey(
      { name: "Ed25519" } as any,
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;

    const privateJwk = (await crypto.subtle.exportKey("jwk", kp.privateKey)) as JsonWebKey;
    const signingKey = await crypto.subtle.importKey(
      "jwk",
      privateJwk,
      { name: "Ed25519" } as any,
      false,
      ["sign"],
    );

    const token = await mintAccessToken({
      sub: "principal:test",
      scope: "bridgeCert",
      audience: "https://rosary.bot",
      signingKey,
      keyId: "test-kid",
    });

    // Tamper the signature
    const parts = token.split(".");
    const tampered = `${parts[0]}.${parts[1]}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;

    let errorMessage = "";
    try {
      await verifyAccessToken(tampered, kp.publicKey);
    } catch (e) {
      errorMessage = (e as Error).message;
    }

    // Error must exist (tampered token must fail)
    expect(errorMessage).not.toBe("");
    // Error must not contain any private key material
    expect(errorMessage).not.toMatch(/"d"\s*:\s*"[A-Za-z0-9_-]+"/);
    expect(errorMessage).not.toContain("BEGIN PRIVATE KEY");
    // The private JWK 'd' value itself must not appear
    expect(errorMessage).not.toContain(privateJwk.d);
  });

  it("validateGHAToken error for alg:none does not leak private key", async () => {
    const header = btoa(JSON.stringify({ alg: "none", typ: "JWT" }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
    const payload = btoa(
      JSON.stringify({
        iss: "https://token.actions.githubusercontent.com",
        aud: "notme.bot",
        exp: Math.floor(Date.now() / 1000) + 300,
        iat: Math.floor(Date.now() / 1000),
      }),
    )
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");

    let errorMessage = "";
    try {
      await validateGHAToken(`${header}.${payload}.`, "notme.bot");
    } catch (e) {
      errorMessage = (e as Error).message;
    }

    expect(errorMessage).not.toBe("");
    expect(errorMessage).not.toMatch(/"d"\s*:\s*"[A-Za-z0-9_-]+"/);
    expect(errorMessage).not.toContain("BEGIN PRIVATE KEY");
  });
});
