/**
 * cache-build-key.test.ts — a deploy is never answered from the previous
 * build's cache (notme-486e8a).
 *
 * Measured in production right after a deploy: /.well-known/oauth-authorization-server
 * served the new grant list while /.well-known/signet-authority.json — built
 * from the SAME constant — still served the old one, `cache-control:
 * public, max-age=86400`. The Cache API key was the bare request URL, so an
 * entry written by the previous Worker version answered for up to a day.
 * Every deploy that changed what discovery advertises was misreported for up
 * to 24 hours afterwards — "advertises but doesn't work", recurring by design.
 *
 * The cache comment already knew: verification appended query parameters "so
 * deployment verification can bypass entries created by an older Worker
 * version". The workaround reached the verifier and not the clients.
 */
import { describe, expect, it } from "vitest";
import { cacheKey, setCacheBuild } from "../cache-key";

const req = (url: string, accept?: string) =>
  new Request(url, accept ? { headers: { accept } } : undefined);

describe("the cache key carries the build", () => {
  it("two builds never share an entry for the same URL", () => {
    setCacheBuild({ BUILD_SHA: "a".repeat(40) });
    const before = cacheKey(req("https://auth.notme.bot/.well-known/signet-authority.json")).url;
    setCacheBuild({ BUILD_SHA: "b".repeat(40) });
    const after = cacheKey(req("https://auth.notme.bot/.well-known/signet-authority.json")).url;
    expect(before).not.toBe(after);
  });

  it("the same build shares its entry — the cache still caches", () => {
    setCacheBuild({ BUILD_SHA: "c".repeat(40) });
    const one = cacheKey(req("https://auth.notme.bot/.well-known/jwks.json")).url;
    const two = cacheKey(req("https://auth.notme.bot/.well-known/jwks.json")).url;
    expect(one).toBe(two);
  });

  it("content negotiation still separates JSON from HTML within one build", () => {
    setCacheBuild({ BUILD_SHA: "d".repeat(40) });
    const json = cacheKey(req("https://notme.bot/x", "application/json"), "Accept").url;
    const html = cacheKey(req("https://notme.bot/x", "text/html"), "Accept").url;
    expect(json).not.toBe(html);
  });
});
