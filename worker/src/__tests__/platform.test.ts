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
    it("throws on encrypted mode — not yet implemented", () => {
      expect(() =>
        validateKeyStorageConfig("encrypted", "ab".repeat(16)),
      ).toThrow("not yet implemented");
    });

    it("throws on encrypted mode even without KEK", () => {
      expect(() =>
        validateKeyStorageConfig("encrypted", undefined),
      ).toThrow("not yet implemented");
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
