// api-docs.ts — render public/_api-docs.html for the environment serving it
// (notme-131c8e).
//
// The asset is a template. It names the authority host ONLY through
// AUTHORITY_HOST_TOKEN, and /api/docs fills the token on every environment,
// production included. Before this, the asset hardcoded the production host
// and worker.ts rewrote that literal on staging, so a domain change meant
// editing two files coupled through a string neither one showed.
//
// The site host (notme.bot links for styles, nav, the architecture page) is
// not templated: it is the marketing site, not the authority, and the page is
// served from the authority host with absolute links back to it.

/** The one placeholder _api-docs.html may use for the authority host. */
export const AUTHORITY_HOST_TOKEN = "{{AUTHORITY_HOST}}";

const HTML_ESCAPES: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

/**
 * Fill every AUTHORITY_HOST_TOKEN in `template` with `authorityHost`.
 *
 * Escaped although the host normally comes from SIGNET_AUTHORITY_URL, which
 * the operator sets: the route falls back to the request's Host when that var
 * does not parse, and a header must never be able to add markup to the page.
 */
export function renderApiDocs(template: string, authorityHost: string): string {
  const safe = authorityHost.replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]!);
  return template.replaceAll(AUTHORITY_HOST_TOKEN, safe);
}
