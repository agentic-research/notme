/**
 * jwt-primitives.test.ts — TDD tests for shared JWT primitives.
 *
 * These primitives live in gen/ts/dpop.ts and are used by ALL JWT code.
 * One implementation, one place, one set of tests.
 *
 * Patterns adapted from jose (MIT, Copyright (c) 2018 Filip Skokan).
 */

import { describe, expect, it } from "vitest";

async function getSDK() {
  return import("../dpop");
}

// ── Base64url ──────────────────────────────────────────────────────────────

describe("base64urlDecode (exported)", () => {
  it("decodes valid base64url to bytes", async () => {
    const { base64urlDecode } = await getSDK();
    // "hello" in base64url = "aGVsbG8"
    const bytes = base64urlDecode("aGVsbG8");
    expect(new TextDecoder().decode(bytes)).toBe("hello");
  });

  it("handles padding characters in input", async () => {
    const { base64urlDecode } = await getSDK();
    // Some implementations include padding — should still work
    const bytes = base64urlDecode("aGVsbG8=");
    expect(new TextDecoder().decode(bytes)).toBe("hello");
  });

  it("handles standard base64 chars (+/) in input", async () => {
    const { base64urlDecode } = await getSDK();
    // Should handle both standard and URL-safe variants
    const bytes = base64urlDecode("ab+c/d==");
    const bytes2 = base64urlDecode("ab-c_d");
    expect(bytes).toEqual(bytes2);
  });

  it("throws labeled error on malformed input", async () => {
    const { base64urlDecode } = await getSDK();
    expect(() => base64urlDecode("!!!invalid!!!")).toThrow();
  });

  it("returns empty Uint8Array for empty string", async () => {
    const { base64urlDecode } = await getSDK();
    const bytes = base64urlDecode("");
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(0);
  });
});

describe("base64urlEncode (exported)", () => {
  it("encodes bytes to base64url (no padding)", async () => {
    const { base64urlEncode } = await getSDK();
    const bytes = new TextEncoder().encode("hello");
    const encoded = base64urlEncode(bytes);
    expect(encoded).toBe("aGVsbG8");
    // Must not contain +, /, or =
    expect(encoded).not.toMatch(/[+/=]/);
  });

  it("roundtrips with decode", async () => {
    const { base64urlEncode, base64urlDecode } = await getSDK();
    const original = new Uint8Array([0, 1, 2, 255, 254, 253, 128, 64]);
    const encoded = base64urlEncode(original);
    const decoded = base64urlDecode(encoded);
    expect(decoded).toEqual(original);
  });

  it("handles large payloads without stack overflow", async () => {
    const { base64urlEncode, base64urlDecode } = await getSDK();
    // 100KB payload — would overflow if using String.fromCharCode.apply without chunking
    const large = new Uint8Array(100_000);
    for (let i = 0; i < large.length; i++) large[i] = i % 256;
    const encoded = base64urlEncode(large);
    const decoded = base64urlDecode(encoded);
    expect(decoded).toEqual(large);
  });
});

// ── JSON parse with label ──────────────────────────────────────────────────

describe("jsonParseSafe", () => {
  it("parses valid JSON", async () => {
    const { jsonParseSafe } = await getSDK();
    const obj = jsonParseSafe('{"sub":"alice","exp":123}', "test payload");
    expect(obj.sub).toBe("alice");
    expect(obj.exp).toBe(123);
  });

  it("throws labeled error on invalid JSON", async () => {
    const { jsonParseSafe } = await getSDK();
    expect(() => jsonParseSafe("not json", "JWT header")).toThrow(/JWT header/);
  });

  it("rejects non-object JSON (arrays, strings, numbers)", async () => {
    const { jsonParseSafe } = await getSDK();
    expect(() => jsonParseSafe("[1,2,3]", "payload")).toThrow(/object/i);
    expect(() => jsonParseSafe('"string"', "payload")).toThrow(/object/i);
    expect(() => jsonParseSafe("42", "payload")).toThrow(/object/i);
    expect(() => jsonParseSafe("null", "payload")).toThrow(/object/i);
  });
});

// ── Claim validation (jose-inspired) ───────────────────────────────────────

describe("validateClaims", () => {
  const now = Math.floor(Date.now() / 1000);

  it("accepts valid claims with all fields", async () => {
    const { validateClaims } = await getSDK();
    const payload = {
      sub: "alice",
      iss: "https://auth.notme.bot",
      aud: "https://rosary.bot",
      iat: now,
      nbf: now,
      exp: now + 300,
      jti: "unique-id",
    };
    // Should not throw
    validateClaims(payload, {
      issuer: "https://auth.notme.bot",
      audience: "https://rosary.bot",
    });
  });

  // ── exp ──

  it("rejects expired token (exp <= now)", async () => {
    const { validateClaims } = await getSDK();
    expect(() => validateClaims({ exp: now - 1 }, {})).toThrow(/exp/i);
  });

  it("rejects exp that is not a number", async () => {
    const { validateClaims } = await getSDK();
    expect(() => validateClaims({ exp: "not a number" }, {})).toThrow(/exp.*number/i);
  });

  it("accepts exp at boundary with tolerance", async () => {
    const { validateClaims } = await getSDK();
    // Expired 5s ago, but tolerance is 10s — should pass
    validateClaims({ exp: now - 5 }, { clockTolerance: 10 });
  });

  // ── nbf ──

  it("rejects token not yet valid (nbf > now)", async () => {
    const { validateClaims } = await getSDK();
    expect(() => validateClaims({
      exp: now + 300,
      nbf: now + 60,
    }, {})).toThrow(/nbf/i);
  });

  it("accepts nbf at boundary with tolerance", async () => {
    const { validateClaims } = await getSDK();
    // Not valid for 5 more seconds, but tolerance is 10s — should pass
    validateClaims({ exp: now + 300, nbf: now + 5 }, { clockTolerance: 10 });
  });

  it("rejects nbf that is not a number", async () => {
    const { validateClaims } = await getSDK();
    expect(() => validateClaims({ exp: now + 300, nbf: "bad" }, {})).toThrow(/nbf.*number/i);
  });

  it("ignores nbf when not present", async () => {
    const { validateClaims } = await getSDK();
    // No nbf — should not throw
    validateClaims({ exp: now + 300 }, {});
  });

  // ── iat ──

  it("rejects iat that is not a number when present", async () => {
    const { validateClaims } = await getSDK();
    expect(() => validateClaims({ exp: now + 300, iat: "bad" }, {})).toThrow(/iat.*number/i);
  });

  it("rejects iat in the far future", async () => {
    const { validateClaims } = await getSDK();
    expect(() => validateClaims({
      exp: now + 600,
      iat: now + 120,
    }, {})).toThrow(/iat/i);
  });

  // ── iss ──

  it("validates issuer when expected", async () => {
    const { validateClaims } = await getSDK();
    expect(() => validateClaims(
      { exp: now + 300, iss: "https://evil.com" },
      { issuer: "https://auth.notme.bot" },
    )).toThrow(/iss/i);
  });

  it("accepts matching issuer", async () => {
    const { validateClaims } = await getSDK();
    validateClaims(
      { exp: now + 300, iss: "https://auth.notme.bot" },
      { issuer: "https://auth.notme.bot" },
    );
  });

  it("requires iss when issuer option is set", async () => {
    const { validateClaims } = await getSDK();
    expect(() => validateClaims(
      { exp: now + 300 },
      { issuer: "https://auth.notme.bot" },
    )).toThrow(/iss.*missing/i);
  });

  // ── aud ──

  it("validates audience (string)", async () => {
    const { validateClaims } = await getSDK();
    expect(() => validateClaims(
      { exp: now + 300, aud: "https://evil.com" },
      { audience: "https://rosary.bot" },
    )).toThrow(/aud/i);
  });

  it("validates audience (array in payload)", async () => {
    const { validateClaims } = await getSDK();
    validateClaims(
      { exp: now + 300, aud: ["https://rosary.bot", "https://other.com"] },
      { audience: "https://rosary.bot" },
    );
  });

  it("validates audience (array in option)", async () => {
    const { validateClaims } = await getSDK();
    validateClaims(
      { exp: now + 300, aud: "https://rosary.bot" },
      { audience: ["https://rosary.bot", "https://mache.rosary.bot"] },
    );
  });

  it("requires aud when audience option is set", async () => {
    const { validateClaims } = await getSDK();
    expect(() => validateClaims(
      { exp: now + 300 },
      { audience: "https://rosary.bot" },
    )).toThrow(/aud.*missing/i);
  });

  // ── sub ──

  it("validates sub when required", async () => {
    const { validateClaims } = await getSDK();
    expect(() => validateClaims(
      { exp: now + 300 },
      { requireSub: true },
    )).toThrow(/sub.*missing/i);
  });

  it("rejects sub that is not a string", async () => {
    const { validateClaims } = await getSDK();
    expect(() => validateClaims(
      { exp: now + 300, sub: 12345 },
      { requireSub: true },
    )).toThrow(/sub.*string/i);
  });
});
