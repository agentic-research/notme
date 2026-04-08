import { describe, it, expect } from "vitest";
import { detectKeyStorage, validateKeyStorageConfig } from "../platform";

describe("platform detection", () => {
  describe("detectKeyStorage", () => {
    it("defaults to ephemeral when no env vars set", () => {
      expect(detectKeyStorage({} as any)).toBe("ephemeral");
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

    it("respects explicit NOTME_KEY_STORAGE=encrypted with valid KEK", () => {
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
    it("throws when encrypted mode has no KEK secret", () => {
      expect(() =>
        validateKeyStorageConfig("encrypted", undefined),
      ).toThrow("NOTME_KEK_SECRET");
    });

    it("throws when KEK secret is too short", () => {
      expect(() =>
        validateKeyStorageConfig("encrypted", "tooshort"),
      ).toThrow("128 bits");
    });

    it("accepts valid KEK secret (32+ hex chars)", () => {
      expect(() =>
        validateKeyStorageConfig("encrypted", "ab".repeat(16)),
      ).not.toThrow();
    });

    it("does not throw for ephemeral mode regardless of KEK", () => {
      expect(() =>
        validateKeyStorageConfig("ephemeral", undefined),
      ).not.toThrow();
    });
  });
});
