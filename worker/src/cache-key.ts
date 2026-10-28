/**
 * Cache API keys for worker.ts (notme-486e8a). Pure, so it can be tested
 * without the Worker entry point.
 *
 * THE BUILD IS PART OF EVERY KEY. The key used to be the bare request URL,
 * and cached responses carry `max-age=86400` — so an entry written by the
 * PREVIOUS Worker version kept answering for up to a day after a deploy.
 * Measured in production on 2026-10-28: right after deploying, the OAuth
 * metadata served the new grant list while /.well-known/signet-authority.json,
 * built from the same constant, still served the old one. Every deploy that
 * changed what discovery advertises misreported it for up to 24 hours.
 *
 * worker.ts already appended query parameters "so deployment verification
 * can bypass entries created by an older Worker version" — the workaround
 * reached the verifier and never the clients. Keying by build fixes it for
 * everyone; an unstamped build (local dev) shares the "unstamped" key.
 */
import { buildInfo } from "./build-version";

let currentBuild = "unstamped";

/** Called once per request from worker.ts's fetch with that request's env. */
export function setCacheBuild(env: { BUILD_SHA?: string }): void {
  const b = buildInfo(env);
  currentBuild = b.stamped ? b.commit : "unstamped";
}

export function wantsJson(request: Request): boolean {
  const accept = request.headers.get("Accept") || "";
  // Explicitly request JSON, for API tools
  if (accept.includes("application/json") || accept.includes("application/schema+json")) {
    return true;
  }
  // For all other requests (including browsers), default to HTML
  return false;
}

export function cacheKey(request: Request, vary?: string): Request {
  const url = new URL(request.url);
  url.searchParams.set("_build", currentBuild);
  // For content-negotiated routes, include Accept in the cache key so JSON
  // and HTML responses are cached separately. `_cache=v2` invalidates the v1
  // keys, which dropped the query string and classified
  // application/schema+json as HTML.
  if (vary === "Accept") {
    url.searchParams.set("_accept", wantsJson(request) ? "json" : "html");
    url.searchParams.set("_cache", "v2");
  }
  return new Request(url.toString(), request);
}
