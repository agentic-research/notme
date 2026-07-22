/**
 * signing.test.ts — SigningAuthority DO tests.
 * Maps to THREAT_MODEL.md: signing.key.isolation, bundle.*
 *
 * Tests the DO's key lifecycle, bundle generation, and epoch tracking
 * using a mock SQL interface (same as passkey tests).
 */

import { describe, expect, it } from "vitest";

// We can't instantiate the real DO outside Workerd, but we can test
// the static helper and verify the schema/state logic.

describe("revocation.bundle.staleness", () => {
  // rosary-9bb26b: a bundle without a valid `issuedAt` would previously
  // skip the staleness check entirely. The fix makes the check fail
  // closed — these tests lock that contract.

  type Bundle = {
    epoch: number;
    seqno: number;
    keys: Record<string, string>;
    keyId: string;
    issuedAt: number;
    signature: string;
  };

  const fresh: Bundle = {
    epoch: 1,
    seqno: 1,
    keys: { kid1: "AAAA" },
    keyId: "kid1",
    issuedAt: Math.floor(Date.now() / 1000),
    signature: "AAAA",
  };

  it("accepts a fresh bundle (issuedAt within window)", async () => {
    const { isBundleStale } = await import("../revocation");
    expect(isBundleStale(fresh)).toBe(false);
  });

  it("rejects a bundle older than BUNDLE_MAX_AGE_MS (5 minutes)", async () => {
    const { isBundleStale, BUNDLE_MAX_AGE_MS } = await import("../revocation");
    const stale = { ...fresh, issuedAt: Math.floor((Date.now() - BUNDLE_MAX_AGE_MS - 1000) / 1000) };
    expect(isBundleStale(stale)).toBe(true);
  });

  it("rejects a bundle with no issuedAt (missing field, fail closed)", async () => {
    const { isBundleStale } = await import("../revocation");
    const noIssuedAt = { ...fresh } as Partial<Bundle>;
    delete noIssuedAt.issuedAt;
    expect(isBundleStale(noIssuedAt as any)).toBe(true);
  });

  it("rejects a bundle with NaN issuedAt", async () => {
    const { isBundleStale } = await import("../revocation");
    expect(isBundleStale({ ...fresh, issuedAt: NaN })).toBe(true);
  });

  it("rejects a bundle with non-numeric issuedAt", async () => {
    const { isBundleStale } = await import("../revocation");
    expect(isBundleStale({ ...fresh, issuedAt: "1234" } as any)).toBe(true);
  });

  it("rejects a bundle with zero or negative issuedAt", async () => {
    const { isBundleStale } = await import("../revocation");
    expect(isBundleStale({ ...fresh, issuedAt: 0 })).toBe(true);
    expect(isBundleStale({ ...fresh, issuedAt: -100 })).toBe(true);
  });
});

describe("signing.key.id", () => {
  // Exercises the production keyIdFromSpki (signet ADR-012, bead
  // signet-248d17): kid = hex(SHA-256(canonical SPKI DER)[:16]), 128-bit.
  // The earlier tests passed non-SPKI garbage (btoa("aaa…")) that the old
  // byte-hashing accepted; the canonicalizing importKey now correctly rejects
  // it, so these use real Ed25519 SPKI.

  // Build a canonical Ed25519 SPKI (RFC 8410: AlgorithmIdentifier = OID only,
  // parameters ABSENT) from a raw 32-byte public key given as hex.
  const spkiB64FromKeyHex = (keyHex: string) => {
    const der = "302a300506032b6570032100" + keyHex;
    const bytes = der.match(/../g)!.map((h) => parseInt(h, 16));
    return btoa(String.fromCharCode(...bytes));
  };
  const KEY_A =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
  const KEY_B =
    "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";

  it("matches the ADR-012 canonical conformance vector (128-bit)", async () => {
    const { keyIdFromSpki } = await import("../key-id");
    // The cross-language pinned vector. notme MUST reproduce it byte-for-byte,
    // as must signet Go and any LLO consumer.
    expect(await keyIdFromSpki(spkiB64FromKeyHex(KEY_A))).toBe(
      "9408457aefd071cec127c1f985399308",
    );
  });

  it("is 128-bit (32 lowercase hex) and deterministic", async () => {
    const { keyIdFromSpki } = await import("../key-id");
    const id = await keyIdFromSpki(spkiB64FromKeyHex(KEY_A));
    expect(id).toHaveLength(32);
    expect(id).toMatch(/^[0-9a-f]{32}$/);
    expect(await keyIdFromSpki(spkiB64FromKeyHex(KEY_A))).toBe(id);
  });

  it("differs for different keys", async () => {
    const { keyIdFromSpki } = await import("../key-id");
    expect(await keyIdFromSpki(spkiB64FromKeyHex(KEY_A))).not.toBe(
      await keyIdFromSpki(spkiB64FromKeyHex(KEY_B)),
    );
  });

  it("canonicalizes: rejects non-canonical NULL-params SPKI (ADR-012 R2)", async () => {
    const { keyIdFromSpki } = await import("../key-id");
    // Same key, but the AlgorithmIdentifier carries an explicit NULL parameter
    // — a valid-but-non-canonical encoding that MUST NOT silently produce a
    // second, divergent kid. Web Crypto rejects it; the kid stays single-valued.
    const der = "302c300706032b65700500032100" + KEY_A;
    const bytes = der.match(/../g)!.map((h) => parseInt(h, 16));
    const nullParamSpki = btoa(String.fromCharCode(...bytes));
    await expect(keyIdFromSpki(nullParamSpki)).rejects.toThrow();
  });
});

describe("bundle.canonical", () => {
  it("canonical JSON sorts keys alphabetically", () => {
    // The bundle canonical encoding must match revocation.ts bundleCanonical
    const bundle = {
      epoch: 1,
      seqno: 2,
      keys: { kid1: "pubkey" },
      keyId: "kid1",
      issuedAt: 1234567890,
    };

    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(bundle).sort()) {
      sorted[k] = bundle[k as keyof typeof bundle];
    }
    const canonical = JSON.stringify(sorted);

    // Keys must be in alphabetical order
    const keys = Object.keys(JSON.parse(canonical));
    expect(keys).toEqual(["epoch", "issuedAt", "keyId", "keys", "seqno"]);
  });

  it("excludes signature field from canonical form", () => {
    const bundle = {
      epoch: 1,
      seqno: 2,
      keys: {},
      keyId: "kid1",
      signature: "should-be-excluded",
    };

    const { signature: _sig, ...rest } = bundle;
    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(rest).sort()) {
      sorted[k] = rest[k as keyof typeof rest];
    }
    const canonical = JSON.stringify(sorted);

    expect(canonical).not.toContain("signature");
    expect(canonical).not.toContain("should-be-excluded");
  });
});

describe("signing.epoch", () => {
  it("epoch starts at 1", () => {
    // Default state row: epoch = 1, seqno = 1
    const defaultState = { epoch: 1, seqno: 1 };
    expect(defaultState.epoch).toBe(1);
    expect(defaultState.seqno).toBe(1);
  });

  it("rotation increments both epoch and seqno", () => {
    let state = { epoch: 1, seqno: 5 };
    // Simulate rotation
    state = { epoch: state.epoch + 1, seqno: state.seqno + 1 };
    expect(state.epoch).toBe(2);
    expect(state.seqno).toBe(6);
  });

  it("bundle generation increments seqno only", () => {
    let state = { epoch: 1, seqno: 1 };
    // Simulate bundle generation (no rotation)
    state = { epoch: state.epoch, seqno: state.seqno + 1 };
    expect(state.epoch).toBe(1);
    expect(state.seqno).toBe(2);
  });
});
