/**
 * no-network.ts — the plain suite is hermetic: no test may reach a real host
 * (notme-3fc74b).
 *
 * WHY. Two OIDC tests asserted that verification got PAST the issuer or
 * audience check, and past it the verifier fetches discovery and JWKS from the
 * issuer: live auth.notme.bot. A GitHub runner's network path to production
 * then decided a unit test's outcome (CI timed out on both, on a docs-only PR),
 * and every CI run sent requests to production. Worse, the tests caught the
 * network error and passed on it, so an outage read as green.
 *
 * HOW. Every fetch whose host is not loopback is refused AND recorded, and
 * afterEach fails the test that made it, naming the URL. Recording matters:
 * a test that swallows the rejection (as those two did) still fails.
 *
 * A test that needs an endpoint serves it: stub `fetch` (vi.stubGlobal, or a
 * fixture such as helpers/oidc-issuer.ts). A stub replaces this guard for as
 * long as it is installed, so a stubbed URL never reaches it, and anything
 * the stub passes through to "the real fetch" lands back here.
 */
import { afterEach, expect } from "vitest";

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

function urlOf(input: RequestInfo | URL): URL | null {
  try {
    return new URL(
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url,
    );
  } catch {
    return null; // a relative URL cannot leave the process
  }
}

/** True for a URL that would go out over the network to a non-loopback host. */
export function isExternal(url: URL): boolean {
  if (url.protocol !== "http:" && url.protocol !== "https:") return false;
  const host = url.hostname.toLowerCase();
  return !(LOOPBACK.has(host) || host.endsWith(".localhost"));
}

let attempted: string[] = [];
const loopbackFetch = globalThis.fetch;

/** Marks the guard, so a test can pin that this setup file is actually loaded. */
export const NETWORK_GUARD = Symbol.for("notme.plain-suite.no-network");

const guardedFetch = ((input: RequestInfo | URL, init?: RequestInit) => {
  const url = urlOf(input);
  if (url && isExternal(url)) {
    attempted.push(url.href);
    return Promise.reject(
      new Error(
        `hermetic plain suite (notme-3fc74b): refused a real network request to ${url.href}. ` +
          `Stub fetch or serve a fixture (see src/__tests__/helpers/oidc-issuer.ts).`,
      ),
    );
  }
  return loopbackFetch(input, init);
}) as typeof fetch;
Object.defineProperty(guardedFetch, NETWORK_GUARD, { value: true });
globalThis.fetch = guardedFetch;

afterEach(() => {
  const made = attempted;
  attempted = [];
  expect(
    made,
    "this test made a real network request; the plain suite must be hermetic (notme-3fc74b)",
  ).toEqual([]);
});
