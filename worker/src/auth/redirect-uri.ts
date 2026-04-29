/**
 * Redirect-URI validation for the OAuth-style /authorize flow.
 *
 * Defends against open-redirect: a malicious caller could otherwise send
 * a victim through /authorize with redirect_uri pointing at attacker.com
 * and exfiltrate the issued bearer token. Defenses (in order):
 *
 *   1. Required (no empty / missing).
 *   2. Parses as a URL.
 *   3. https-only on the public internet (localhost is exempt for dev).
 *   4. Exact-host allowlist — no wildcard subdomains.
 *
 * Extracted as a pure function so unit tests cover the matrix directly
 * without spinning up the worker. The /authorize route consumes the
 * result and maps each error variant to an HTTP response.
 */

export const ALLOWED_REDIRECT_HOSTS: ReadonlySet<string> = new Set([
  "localhost",
  "127.0.0.1",
  "rosary.bot",
  "auth.rosary.bot",
  "notme.bot",
  "auth.notme.bot",
]);

export type RedirectUriValidation =
  | { ok: true; url: URL }
  | { ok: false; status: 400 | 403; reason: string };

export function validateRedirectUri(redirectUri: string): RedirectUriValidation {
  if (!redirectUri) {
    return { ok: false, status: 400, reason: "redirect_uri required" };
  }

  let parsed: URL;
  try {
    parsed = new URL(redirectUri);
  } catch {
    return { ok: false, status: 400, reason: "invalid redirect_uri" };
  }

  const isLocalhost =
    parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";

  // https-only on the public internet. localhost gets http for dev, but
  // still has to be http or https — no file://, javascript:, data:, etc.
  if (!isLocalhost && parsed.protocol !== "https:") {
    return { ok: false, status: 400, reason: "redirect_uri must be https" };
  }
  if (isLocalhost && parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { ok: false, status: 400, reason: "redirect_uri must be http or https" };
  }

  // Exact-host allowlist — wildcard subdomains are NOT permitted (a
  // permissive `*.notme.bot` would let any subdomain XSS-via-image become
  // a redirect target).
  if (!ALLOWED_REDIRECT_HOSTS.has(parsed.hostname)) {
    return { ok: false, status: 403, reason: "redirect_uri not on allowed domain" };
  }

  return { ok: true, url: parsed };
}
