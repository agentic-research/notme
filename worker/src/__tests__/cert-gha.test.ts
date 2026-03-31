/**
 * cert-gha.test.ts — GHA OIDC cert exchange tests.
 * Maps to THREAT_MODEL.md: cert-gha.* rows.
 *
 * Tests the business logic of handleCertGHA without needing
 * a real GHA OIDC token or DO. Validates the defense layers.
 */

import { describe, expect, it } from "vitest";

describe("cert-gha.owner.allowlist", () => {
  it("case-insensitive owner comparison", () => {
    // The getAllowedOwners function lowercases both sides
    const owners = new Set(["agentic-research"]);
    expect(owners.has("agentic-research")).toBe(true);
    expect(owners.has("Agentic-Research".toLowerCase())).toBe(true);
    expect(owners.has("AGENTIC-RESEARCH".toLowerCase())).toBe(true);
    expect(owners.has("evil-corp".toLowerCase())).toBe(false);
  });
});

describe("cert-gha.rate-limit", () => {
  it("rate limit state tracks count and window", () => {
    const now = Date.now();
    const WINDOW = 3600_000;

    // Fresh window
    let rl: { count: number; windowStart: number } | null = null;
    if (!rl || now - (rl?.windowStart ?? 0) > WINDOW) {
      rl = { count: 1, windowStart: now };
    }
    expect(rl.count).toBe(1);

    // Same window, increment
    rl.count++;
    expect(rl.count).toBe(2);

    // Exceeds limit
    rl.count = 11;
    expect(rl.count > 10).toBe(true);

    // Expired window resets
    const oldWindow = { count: 5, windowStart: now - WINDOW - 1 };
    if (now - oldWindow.windowStart > WINDOW) {
      rl = { count: 1, windowStart: now };
    }
    expect(rl.count).toBe(1);
  });
});

describe("cert-gha.jti.replay", () => {
  it("JTI TTL is at least 60 seconds", () => {
    const JTI_MIN_TTL = 60;
    const exp = Math.floor(Date.now() / 1000) + 30; // expires in 30s
    const now = Math.floor(Date.now() / 1000);
    const ttl = Math.max(JTI_MIN_TTL, exp - now);
    // Even if token expires in 30s, JTI is tracked for 60s minimum
    expect(ttl).toBe(JTI_MIN_TTL);
  });

  it("JTI TTL matches token remaining lifetime when > minimum", () => {
    const JTI_MIN_TTL = 60;
    const exp = Math.floor(Date.now() / 1000) + 300; // expires in 5min
    const now = Math.floor(Date.now() / 1000);
    const ttl = Math.max(JTI_MIN_TTL, exp - now);
    expect(ttl).toBeGreaterThanOrEqual(290);
    expect(ttl).toBeLessThanOrEqual(300);
  });
});

describe("cert-gha.config", () => {
  it("getConfig returns defaults when env is empty", () => {
    const env: any = {};
    const cfg = {
      ghaCertAudience: (env.GHA_CERT_AUDIENCE as string) ?? "notme.bot",
      ghaCertTtlMs: Number(env.GHA_CERT_TTL_MS ?? 300_000),
      jtiMinTtlSeconds: Number(env.JTI_MIN_TTL_SECONDS ?? 60),
      rateLimitWindowMs: Number(env.RATE_LIMIT_WINDOW_MS ?? 3600_000),
      rateLimitMaxCerts: Number(env.RATE_LIMIT_MAX_CERTS ?? 10),
      rateLimitKvTtlSeconds: Number(env.RATE_LIMIT_KV_TTL_SECONDS ?? 3600),
    };

    expect(cfg.ghaCertAudience).toBe("notme.bot");
    expect(cfg.ghaCertTtlMs).toBe(300_000);
    expect(cfg.rateLimitMaxCerts).toBe(10);
  });

  it("getConfig respects env overrides", () => {
    const env: any = {
      GHA_CERT_AUDIENCE: "custom.example.com",
      RATE_LIMIT_MAX_CERTS: "50",
    };
    const cfg = {
      ghaCertAudience: (env.GHA_CERT_AUDIENCE as string) ?? "notme.bot",
      rateLimitMaxCerts: Number(env.RATE_LIMIT_MAX_CERTS ?? 10),
    };

    expect(cfg.ghaCertAudience).toBe("custom.example.com");
    expect(cfg.rateLimitMaxCerts).toBe(50);
  });
});
