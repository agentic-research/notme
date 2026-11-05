/**
 * client-metadata.test.ts — Client ID Metadata Documents (ADR-022 D1, D3).
 *
 * The validators are pure. The fetcher takes `fetch` as a parameter so the
 * outbound-request limits (no redirects, size, content type, timeout) are
 * pinned here without a network.
 */

import { describe, expect, it } from "vitest";
import {
  CLIENT_METADATA_MAX_BYTES,
  cacheTtlSeconds,
  clientTier,
  fetchClientMetadata,
  matchRedirectUri,
  validateClientIdUrl,
  validateClientMetadata,
} from "../auth/client-metadata";

const ISSUER = "https://auth.notme.bot";
const CLIENT_ID = "https://claude.ai/oauth/client-metadata.json";

describe("validateClientIdUrl", () => {
  it("accepts an https URL with a path on another origin", () => {
    const r = validateClientIdUrl(CLIENT_ID, ISSUER);
    expect(r.ok).toBe(true);
  });

  it.each([
    ["not a url", "not-a-url"],
    ["http", "http://claude.ai/oauth/client.json"],
    ["no path", "https://claude.ai"],
    ["root path only", "https://claude.ai/"],
    ["fragment", "https://claude.ai/client.json#x"],
    ["userinfo", "https://user:pw@claude.ai/client.json"],
    ["dot segment", "https://claude.ai/a/../client.json"],
    ["single-dot segment", "https://claude.ai/./client.json"],
    ["encoded dot segment", "https://claude.ai/a/%2e%2e/client.json"],
    ["IPv4 literal", "https://203.0.113.7/client.json"],
    ["IPv6 literal", "https://[2001:db8::1]/client.json"],
  ])("rejects %s", (_label, url) => {
    expect(validateClientIdUrl(url, ISSUER).ok).toBe(false);
  });

  it("rejects notme's own origin (reserved for DCR-derived documents)", () => {
    const r = validateClientIdUrl(`${ISSUER}/clients/abc`, ISSUER);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/issuer/);
  });
});

describe("validateClientMetadata", () => {
  const good = {
    client_id: CLIENT_ID,
    client_name: "Claude",
    redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
  };

  it("accepts a minimal public client and defaults auth method to none", () => {
    const r = validateClientMetadata(good, CLIENT_ID);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.metadata.token_endpoint_auth_method).toBe("none");
      expect(r.metadata.redirect_uris).toEqual(good.redirect_uris);
    }
  });

  it("requires client_id to equal the fetched URL byte for byte", () => {
    const r = validateClientMetadata(
      { ...good, client_id: `${CLIENT_ID}?` },
      CLIENT_ID,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/client_id/);
  });

  it.each([
    ["non-object", "nope"],
    ["null", null],
    ["array", [good]],
  ])("rejects a %s document", (_label, doc) => {
    expect(validateClientMetadata(doc, CLIENT_ID).ok).toBe(false);
  });

  it.each([
    ["missing redirect_uris", { ...good, redirect_uris: undefined }],
    ["empty redirect_uris", { ...good, redirect_uris: [] }],
    ["non-string redirect", { ...good, redirect_uris: [42] }],
    [
      "http redirect off loopback",
      { ...good, redirect_uris: ["http://claude.ai/cb"] },
    ],
    [
      "redirect with fragment",
      { ...good, redirect_uris: ["https://claude.ai/cb#f"] },
    ],
    [
      "javascript redirect",
      { ...good, redirect_uris: ["javascript:alert(1)"] },
    ],
  ])("rejects %s", (_label, doc) => {
    expect(validateClientMetadata(doc, CLIENT_ID).ok).toBe(false);
  });

  it("allows http redirects only on loopback (native clients)", () => {
    const r = validateClientMetadata(
      {
        ...good,
        redirect_uris: ["http://127.0.0.1:33418/cb", "http://localhost/cb"],
      },
      CLIENT_ID,
    );
    expect(r.ok).toBe(true);
  });

  it("rejects any client secret (ADR-022: no client secrets, ever)", () => {
    for (const doc of [
      { ...good, client_secret: "s" },
      { ...good, token_endpoint_auth_method: "client_secret_basic" },
      { ...good, token_endpoint_auth_method: "client_secret_post" },
    ]) {
      expect(validateClientMetadata(doc, CLIENT_ID).ok).toBe(false);
    }
  });

  it("private_key_jwt requires exactly one of jwks_uri / jwks", () => {
    const base = { ...good, token_endpoint_auth_method: "private_key_jwt" };
    expect(validateClientMetadata(base, CLIENT_ID).ok).toBe(false);
    expect(
      validateClientMetadata(
        { ...base, jwks_uri: "https://claude.ai/jwks.json" },
        CLIENT_ID,
      ).ok,
    ).toBe(true);
    expect(
      validateClientMetadata({ ...base, jwks: { keys: [] } }, CLIENT_ID).ok,
    ).toBe(true);
    expect(
      validateClientMetadata(
        {
          ...base,
          jwks_uri: "https://claude.ai/jwks.json",
          jwks: { keys: [] },
        },
        CLIENT_ID,
      ).ok,
    ).toBe(false);
  });

  it("rejects a non-https jwks_uri", () => {
    const r = validateClientMetadata(
      {
        ...good,
        token_endpoint_auth_method: "private_key_jwt",
        jwks_uri: "http://claude.ai/jwks.json",
      },
      CLIENT_ID,
    );
    expect(r.ok).toBe(false);
  });

  it("drops unknown fields rather than carrying them forward", () => {
    const r = validateClientMetadata(
      { ...good, scope_override: "admin" },
      CLIENT_ID,
    );
    expect(r.ok).toBe(true);
    if (r.ok) expect("scope_override" in r.metadata).toBe(false);
  });
});

describe("matchRedirectUri", () => {
  const meta = { redirect_uris: ["https://claude.ai/api/mcp/auth_callback"] };

  it("matches exactly", () => {
    expect(
      matchRedirectUri(meta, "https://claude.ai/api/mcp/auth_callback"),
    ).toBe(true);
  });

  it.each([
    "https://claude.ai/api/mcp/auth_callback/",
    "https://claude.ai/api/mcp/auth_callback?x=1",
    "https://CLAUDE.ai/api/mcp/auth_callback",
    "https://claude.ai/api/mcp/",
  ])("does not match a near-miss: %s", (uri) => {
    expect(matchRedirectUri(meta, uri)).toBe(false);
  });
});

describe("clientTier (ADR-022 D3)", () => {
  it("is cimd-verified on the client's own origin", () => {
    expect(clientTier(CLIENT_ID, ISSUER)).toBe("cimd-verified");
  });

  it("is dcr-derived under the issuer's /clients/ prefix", () => {
    expect(clientTier(`${ISSUER}/clients/abc`, ISSUER)).toBe("dcr-derived");
  });

  it("does not treat a look-alike prefix as notme-hosted", () => {
    expect(
      clientTier("https://auth.notme.bot.evil.example/clients/abc", ISSUER),
    ).toBe("cimd-verified");
  });
});

describe("cacheTtlSeconds", () => {
  it.each([
    [null, 300],
    ["no-store", 300],
    ["max-age=10", 300],
    ["public, max-age=3600", 3600],
    ["max-age=999999", 86400],
    ["max-age=garbage", 300],
  ])("%s → %d", (header, want) => {
    expect(cacheTtlSeconds(header)).toBe(want);
  });
});

describe("fetchClientMetadata", () => {
  const body = JSON.stringify({
    client_id: CLIENT_ID,
    redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
  });

  function fakeFetch(res: Response, seen?: { init?: RequestInit }) {
    return async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (seen) seen.init = init;
      return res;
    };
  }

  it("fetches, validates and returns metadata plus a clamped TTL", async () => {
    const seen: { init?: RequestInit } = {};
    const r = await fetchClientMetadata(
      CLIENT_ID,
      fakeFetch(
        new Response(body, {
          headers: {
            "content-type": "application/json",
            "cache-control": "max-age=600",
          },
        }),
        seen,
      ),
    );
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.ttlSeconds).toBe(600);
    expect(seen.init?.redirect).toBe("manual");
    expect(seen.init?.signal).toBeDefined();
  });

  it("refuses a redirect instead of following it", async () => {
    const r = await fetchClientMetadata(
      CLIENT_ID,
      fakeFetch(
        new Response(null, {
          status: 302,
          headers: { location: "https://evil.example/" },
        }),
      ),
    );
    expect(r.ok).toBe(false);
  });

  it("refuses a non-JSON content type", async () => {
    const r = await fetchClientMetadata(
      CLIENT_ID,
      fakeFetch(
        new Response(body, { headers: { "content-type": "text/html" } }),
      ),
    );
    expect(r.ok).toBe(false);
  });

  it("refuses a body over the size cap, even without content-length", async () => {
    const big = JSON.stringify({
      client_id: CLIENT_ID,
      pad: "x".repeat(CLIENT_METADATA_MAX_BYTES),
    });
    const r = await fetchClientMetadata(
      CLIENT_ID,
      fakeFetch(
        new Response(big, { headers: { "content-type": "application/json" } }),
      ),
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/large/);
  });

  it("refuses malformed JSON", async () => {
    const r = await fetchClientMetadata(
      CLIENT_ID,
      fakeFetch(
        new Response("{", { headers: { "content-type": "application/json" } }),
      ),
    );
    expect(r.ok).toBe(false);
  });

  it("turns a network error or timeout into a refusal, not a throw", async () => {
    const r = await fetchClientMetadata(CLIENT_ID, async () => {
      throw new DOMException("timed out", "TimeoutError");
    });
    expect(r.ok).toBe(false);
  });
});
