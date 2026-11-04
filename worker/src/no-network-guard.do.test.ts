/**
 * no-network-guard.do.test.ts — the Durable Object suite is hermetic, and the
 * guard that makes it so is actually installed in the pool (notme-73202e).
 *
 * The guard is a setup file named in vitest.workers*.mts. If a config stopped
 * loading it, every other DO test would still pass and the suite would quietly
 * be allowed to reach production again (the notme-3fc74b failure class). So pin
 * that it is live in THIS isolate, that it refuses a real host, and that the
 * fixtures that wrap fetch fall through to it rather than past it.
 */
/// <reference types="@cloudflare/vitest-pool-workers/types" />
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { installGhaSigner } from "./__tests__/helpers/gha-token";

// Deliberately NOT imported from ./__tests__/setup/no-network: importing it
// would install the guard as a side effect and make "is it installed?" pass
// whatever the pool config says. Find the installed one through fetch instead.
const NETWORK_GUARD = Symbol.for("notme.plain-suite.no-network");
// Captured at load, before any fixture in this file wraps fetch (a wrapper has
// no marker of its own).
const installedGuard = (globalThis.fetch as unknown as Record<symbol, unknown>)[NETWORK_GUARD];
const takeAttempts = (): string[] => (installedGuard as () => string[])();

describe("DO-suite network guard", () => {
  it("is installed: global fetch is the guard, not the platform's", () => {
    expect(typeof installedGuard).toBe("function");
  });

  it("refuses a real host, and the refusal names the URL", async () => {
    await expect(fetch("https://auth.notme.bot/.well-known/jwks.json")).rejects.toThrow(
      /refused a real network request to https:\/\/auth\.notme\.bot\/\.well-known\/jwks\.json/,
    );
    // Recorded as an attempt: the afterEach hook fails the test that made it,
    // even if it swallowed the rejection. Take it here so THIS test, which
    // made the request on purpose, stays green.
    expect(takeAttempts()).toEqual(["https://auth.notme.bot/.well-known/jwks.json"]);
  });

  it("covers a fetch made from inside a Durable Object instance", async () => {
    const stub = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("no-network-guard"));
    const message = await runInDurableObject(stub, async () => {
      try {
        await fetch("https://token.actions.githubusercontent.com/.well-known/jwks");
        return "reached the network";
      } catch (e) {
        return (e as Error).message;
      }
    });
    expect(message).toMatch(/refused a real network request to https:\/\/token\.actions\.githubusercontent\.com/);
    expect(takeAttempts()).toEqual(["https://token.actions.githubusercontent.com/.well-known/jwks"]);
  });

  it("a fetch-wrapping fixture passes non-GHA URLs to the guard, not the network", async () => {
    const gha = await installGhaSigner({
      owner: "o",
      repo: "r",
      audience: "https://example.test",
    });
    try {
      await expect(fetch("https://example.com/")).rejects.toThrow(/refused a real network request/);
      expect(takeAttempts()).toEqual(["https://example.com/"]);
    } finally {
      gha.restore();
    }
  });
});
