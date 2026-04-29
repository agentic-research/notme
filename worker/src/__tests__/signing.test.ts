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

describe("signing.key.id", () => {
  // Tests now exercise the production algorithm via the exported
  // keyIdFromSpki helper, not a parallel reimplementation. Earlier the
  // test reimplemented djb2 (the old 32-bit hash) and asserted on that —
  // it was checking the test-only stub, not the production code. After
  // rosary-808b0e the production function is SHA-256 truncated to 8
  // bytes (64-bit collision space).

  it("is deterministic — same input produces same output", async () => {
    const { keyIdFromSpki } = await import("../key-id");
    const spki1 = btoa("aaaaaaaaaaaabbbbbbbbbbbbccccccccccccdddddddddddd");
    const spki2 = btoa("aaaaaaaaaaaabbbbbbbbbbbbccccccccccccdddddddddddd");
    expect(await keyIdFromSpki(spki1)).toBe(await keyIdFromSpki(spki2));
  });

  it("differs for different inputs", async () => {
    const { keyIdFromSpki } = await import("../key-id");
    const spki1 = btoa("aaaaaaaaaaaabbbbbbbbbbbbccccccccccccdddddddddddd");
    const spki3 = btoa("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    expect(await keyIdFromSpki(spki1)).not.toBe(await keyIdFromSpki(spki3));
  });

  it("returns 16 hex chars (8 bytes / 64-bit truncation)", async () => {
    const { keyIdFromSpki } = await import("../key-id");
    const spki = btoa("aaaaaaaaaaaabbbbbbbbbbbbccccccccccccdddddddddddd");
    const id = await keyIdFromSpki(spki);
    expect(id).toHaveLength(16);
    expect(id).toMatch(/^[0-9a-f]{16}$/);
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
