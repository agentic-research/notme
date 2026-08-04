import { describe, it, expect } from "vitest";
import { detectKeyStorage, validateKeyStorageConfig } from "../platform";

describe("platform detection", () => {
  describe("detectKeyStorage", () => {
    it("defaults to cf-managed when no env vars set", () => {
      expect(detectKeyStorage({} as any)).toBe("cf-managed");
    });

    it("auto-detects encrypted when KEK secret present", () => {
      expect(
        detectKeyStorage({ NOTME_KEK_SECRET: "a".repeat(32) } as any),
      ).toBe("encrypted");
    });

    it("respects explicit NOTME_KEY_STORAGE=ephemeral", () => {
      expect(
        detectKeyStorage({ NOTME_KEY_STORAGE: "ephemeral" } as any),
      ).toBe("ephemeral");
    });

    it("respects explicit NOTME_KEY_STORAGE=encrypted", () => {
      expect(
        detectKeyStorage({
          NOTME_KEY_STORAGE: "encrypted",
          NOTME_KEK_SECRET: "ab".repeat(16),
        } as any),
      ).toBe("encrypted");
    });

    it("respects explicit NOTME_KEY_STORAGE=cf-managed", () => {
      expect(
        detectKeyStorage({ NOTME_KEY_STORAGE: "cf-managed" } as any),
      ).toBe("cf-managed");
    });
  });

  describe("validateKeyStorageConfig (fail closed)", () => {
    // These two asserted "encrypted always throws — not yet implemented".
    // notme-41d0d3 implemented it (src/key-encryption.ts), so the contract
    // inverted: encrypted mode is now valid WITH a secret and fail-closed
    // WITHOUT one. Rewritten rather than deleted — the fail-closed half is
    // the security-relevant assertion and must not be lost with the feature
    // flag it used to ride on.
    it("accepts encrypted mode when a KEK secret is present", () => {
      expect(() =>
        validateKeyStorageConfig("encrypted", "ab".repeat(16)),
      ).not.toThrow();
    });

    it("throws on encrypted mode without a KEK secret", () => {
      // Proceeding would persist the CA private key in cleartext while the
      // operator believes it is sealed.
      expect(() =>
        validateKeyStorageConfig("encrypted", undefined),
      ).toThrow(/NOTME_KEK_SECRET is unset/);
    });

    it("does not throw for ephemeral mode", () => {
      expect(() =>
        validateKeyStorageConfig("ephemeral", undefined),
      ).not.toThrow();
    });

    it("does not throw for cf-managed mode", () => {
      expect(() =>
        validateKeyStorageConfig("cf-managed", undefined),
      ).not.toThrow();
    });
  });
});
