/**
 * redirect-uri.test.ts — open-redirect defenses on the /authorize flow.
 *
 * Maps to THREAT_MODEL.md row `authorize.redirect.allowlist` and the
 * https-required + parse-or-fail rules in section 5.
 *
 * The validator is pure — no fetch, no env, no clock. Each test pins
 * one row of the validation matrix.
 */

import { describe, expect, it } from "vitest";
import {
  validateRedirectUri,
  ALLOWED_REDIRECT_HOSTS,
} from "../auth/redirect-uri";

describe("authorize.redirect.allowlist", () => {
  it("rejects an empty redirect_uri (status 400)", () => {
    const r = validateRedirectUri("");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.status).toBe(400);
      expect(r.reason).toMatch(/required/);
    }
  });

  it("rejects a malformed url (status 400)", () => {
    const r = validateRedirectUri("not-a-url");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.status).toBe(400);
      expect(r.reason).toMatch(/invalid/);
    }
  });

  it("accepts https on an allowlisted host", () => {
    const r = validateRedirectUri("https://rosary.bot/callback");
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.url.hostname).toBe("rosary.bot");
  });

  it("accepts every host in ALLOWED_REDIRECT_HOSTS", () => {
    for (const host of ALLOWED_REDIRECT_HOSTS) {
      const proto = host === "localhost" || host === "127.0.0.1" ? "http" : "https";
      const r = validateRedirectUri(`${proto}://${host}/cb`);
      expect(r.ok, `${host} should be allowed`).toBe(true);
    }
  });

  it("rejects a host not in the allowlist (status 403)", () => {
    const r = validateRedirectUri("https://attacker.example/cb");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.status).toBe(403);
      expect(r.reason).toMatch(/not on allowed/);
    }
  });

  it("rejects a wildcard subdomain attempt (e.g. evil.rosary.bot.attacker.example)", () => {
    // The allowlist is exact-match — a hostname that just contains
    // 'rosary.bot' as a substring must not pass.
    const r = validateRedirectUri("https://rosary.bot.attacker.example/cb");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.status).toBe(403);
  });

  it("rejects a subdomain not in the allowlist (e.g. evil.rosary.bot)", () => {
    // Exact match means evil.rosary.bot is NOT covered by 'rosary.bot'
    // alone — the allowlist must list each exact subdomain explicitly.
    const r = validateRedirectUri("https://evil.rosary.bot/cb");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.status).toBe(403);
  });

  it("rejects http on a non-localhost allowlisted host (status 400)", () => {
    // rosary.bot is on the allowlist but must be https — http on the
    // public internet leaks the access token in URL query params.
    const r = validateRedirectUri("http://rosary.bot/cb");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.status).toBe(400);
      expect(r.reason).toMatch(/must be https/);
    }
  });

  it("accepts http://localhost for dev", () => {
    const r = validateRedirectUri("http://localhost:8788/cb");
    expect(r.ok).toBe(true);
  });

  it("accepts https://localhost too (dev workflows that terminate TLS locally)", () => {
    const r = validateRedirectUri("https://localhost:8788/cb");
    expect(r.ok).toBe(true);
  });

  it("rejects file:// even on localhost", () => {
    const r = validateRedirectUri("file:///etc/passwd");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.status).toBe(400);
  });

  it("rejects javascript: scheme", () => {
    // The URL parser actually accepts `javascript:alert(1)`, so the
    // protocol gate is what stops it. The hostname for javascript: is
    // empty, which is also not in the allowlist — both layers fire.
    const r = validateRedirectUri("javascript:alert(1)");
    expect(r.ok).toBe(false);
  });

  it("rejects data: URIs", () => {
    const r = validateRedirectUri("data:text/html,<script>alert(1)</script>");
    expect(r.ok).toBe(false);
  });

  it("rejects redirect_uri with userinfo (https://user:pass@host)", () => {
    // URL parses user:pass@host correctly; we still want to allow only
    // the bare allowlisted host. userinfo isn't checked separately —
    // the hostname comparison alone catches the abuse case where
    // attacker.example has user:pass@rosary.bot prefix because the URL
    // parser puts attacker.example as hostname.
    const r = validateRedirectUri("https://rosary.bot@attacker.example/cb");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.status).toBe(403);
  });

  it("rejects 127.0.0.1 with non-http(s) scheme", () => {
    const r = validateRedirectUri("ftp://127.0.0.1/cb");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.status).toBe(400);
  });

  it("returns the parsed URL on success for callers that need it", () => {
    const r = validateRedirectUri("https://auth.notme.bot/cb?state=x");
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.url.pathname).toBe("/cb");
      expect(r.url.searchParams.get("state")).toBe("x");
    }
  });
});
