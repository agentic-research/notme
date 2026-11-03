/**
 * no-network-guard.test.ts — the plain suite's network guard is installed and
 * draws the line where it claims to (notme-3fc74b).
 *
 * The guard is a setup file; if vitest.config.ts stopped loading it, every
 * other test would still pass and the suite would quietly be allowed to reach
 * production again. So pin that it is live, and pin its host classification.
 */
import { describe, expect, it } from "vitest";
import { isExternal, NETWORK_GUARD } from "./setup/no-network";

describe("plain-suite network guard", () => {
  it("is installed: global fetch is the guard, not the platform's", () => {
    expect(
      (globalThis.fetch as unknown as Record<symbol, unknown>)[NETWORK_GUARD],
    ).toBe(true);
  });

  it("refuses production and any other non-loopback host", () => {
    for (const u of [
      "https://auth.notme.bot/.well-known/jwks",
      "https://token.actions.githubusercontent.com/.well-known/openid-configuration",
      "http://example.com/",
      "https://10.0.0.1/",
    ]) {
      expect(isExternal(new URL(u)), u).toBe(true);
    }
  });

  it("allows loopback and non-network schemes", () => {
    for (const u of [
      "http://localhost:8788/x",
      "http://127.0.0.1/",
      "http://[::1]:9/",
      "http://auth.localhost/",
      "data:,x",
    ]) {
      expect(isExternal(new URL(u)), u).toBe(false);
    }
  });
});
