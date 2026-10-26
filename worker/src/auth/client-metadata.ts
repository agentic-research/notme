/**
 * Client ID Metadata Documents (CIMD) — ADR-022 D1 and D3.
 *
 * A third-party OAuth client's `client_id` is an https URL; the client's
 * metadata is whatever that URL serves. notme fetches it rather than storing
 * a registration the client pushed (derive-never-receive, notme-6ad276).
 *
 * Fetching an attacker-chosen URL is the new attack surface, so the limits
 * live here, next to the validation, and are pinned by
 * __tests__/client-metadata.test.ts:
 *   - https only, no redirects followed, 8 KiB body cap, 2 s timeout,
 *     application/json only, no IP-literal hosts;
 *   - cache lifetime clamped so a client can neither pin a stale document
 *     nor force a fetch per request.
 *
 * Not wired into /authorize yet. Rate limiting per client_id host and the
 * operator allowlist belong to the route, not to this module.
 */

import { validateRedirectUri } from "./redirect-uri";

export const CLIENT_METADATA_MAX_BYTES = 8 * 1024;
export const CLIENT_METADATA_TIMEOUT_MS = 2_000;
export const CLIENT_METADATA_MIN_TTL_S = 5 * 60;
export const CLIENT_METADATA_MAX_TTL_S = 24 * 60 * 60;

/** Path prefix under the issuer reserved for DCR-derived documents (ADR-022 D2). */
export const DCR_CLIENTS_PATH = "/clients/";

export type ClientTier = "cimd-verified" | "dcr-derived";

export type TokenEndpointAuthMethod = "none" | "private_key_jwt";

/** The fields notme acts on. Everything else in the document is dropped. */
export interface ClientMetadata {
  client_id: string;
  client_name?: string;
  client_uri?: string;
  logo_uri?: string;
  redirect_uris: string[];
  token_endpoint_auth_method: TokenEndpointAuthMethod;
  jwks_uri?: string;
  jwks?: { keys: unknown[] };
}

type Result<T> = ({ ok: true } & T) | { ok: false; reason: string };

// A path segment that is "." or "..", literally or percent-encoded. The URL
// parser resolves these away, so they must be caught on the raw string.
const DOT_SEGMENT = /(^|\/)(\.|%2e){1,2}(\/|\?|#|$)/i;

function isIpLiteral(hostname: string): boolean {
  return hostname.startsWith("[") || /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
}

function rawPath(input: string): string {
  const afterScheme = input.indexOf("://");
  if (afterScheme < 0) return "";
  const slash = input.indexOf("/", afterScheme + 3);
  return slash < 0 ? "" : input.slice(slash);
}

/**
 * Validate a `client_id` as a CIMD URL. notme's own origin is refused:
 * documents there are DCR-derived and must never be presented as a client
 * vouching for itself.
 */
export function validateClientIdUrl(
  clientId: string,
  issuer: string,
): Result<{ url: URL }> {
  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    return { ok: false, reason: "client_id is not a URL" };
  }
  if (url.protocol !== "https:") {
    return { ok: false, reason: "client_id must be https" };
  }
  if (url.username || url.password) {
    return { ok: false, reason: "client_id must not contain userinfo" };
  }
  if (url.hash || clientId.includes("#")) {
    return { ok: false, reason: "client_id must not contain a fragment" };
  }
  if (url.pathname === "" || url.pathname === "/") {
    return { ok: false, reason: "client_id must have a path" };
  }
  if (DOT_SEGMENT.test(rawPath(clientId))) {
    return { ok: false, reason: "client_id must not contain dot segments" };
  }
  if (isIpLiteral(url.hostname)) {
    return { ok: false, reason: "client_id host must be a DNS name" };
  }
  if (url.origin === new URL(issuer).origin) {
    return {
      ok: false,
      reason: "client_id must not be on the issuer's origin",
    };
  }
  return { ok: true, url };
}

function isHttpsUrl(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * Third-party redirect URIs: https anywhere, http only on loopback (native
 * clients), never a fragment. Reuses redirect-uri.ts's scheme rules but not
 * its host allowlist — for a third-party client the document is the
 * allowlist.
 */
function validateClientRedirectUri(value: unknown): boolean {
  if (typeof value !== "string" || value.includes("#")) return false;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (loopback) return validateRedirectUri(value).ok;
  return url.protocol === "https:";
}

/**
 * Validate a fetched metadata document against the URL it was fetched from.
 * Returns only the fields notme acts on.
 */
export function validateClientMetadata(
  doc: unknown,
  clientId: string,
): Result<{ metadata: ClientMetadata }> {
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
    return { ok: false, reason: "metadata must be a JSON object" };
  }
  const d = doc as Record<string, unknown>;

  if (d.client_id !== clientId) {
    return {
      ok: false,
      reason: "client_id in document does not match its URL",
    };
  }

  const redirects = d.redirect_uris;
  if (!Array.isArray(redirects) || redirects.length === 0) {
    return { ok: false, reason: "redirect_uris must be a non-empty array" };
  }
  if (!redirects.every(validateClientRedirectUri)) {
    return { ok: false, reason: "redirect_uris contains an invalid URI" };
  }

  if ("client_secret" in d) {
    return { ok: false, reason: "client secrets are not accepted" };
  }
  const method = d.token_endpoint_auth_method ?? "none";
  if (method !== "none" && method !== "private_key_jwt") {
    return {
      ok: false,
      reason: `unsupported token_endpoint_auth_method: ${String(method)}`,
    };
  }

  const metadata: ClientMetadata = {
    client_id: clientId,
    redirect_uris: redirects as string[],
    token_endpoint_auth_method: method,
  };

  if (method === "private_key_jwt") {
    const hasUri = d.jwks_uri !== undefined;
    const hasJwks = d.jwks !== undefined;
    if (hasUri === hasJwks) {
      return {
        ok: false,
        reason: "private_key_jwt requires exactly one of jwks_uri or jwks",
      };
    }
    if (hasUri) {
      if (!isHttpsUrl(d.jwks_uri)) {
        return { ok: false, reason: "jwks_uri must be https" };
      }
      metadata.jwks_uri = d.jwks_uri;
    } else {
      const jwks = d.jwks as { keys?: unknown };
      if (
        typeof jwks !== "object" ||
        jwks === null ||
        !Array.isArray(jwks.keys)
      ) {
        return {
          ok: false,
          reason: "jwks must be an object with a keys array",
        };
      }
      metadata.jwks = { keys: jwks.keys };
    }
  }

  if (typeof d.client_name === "string") metadata.client_name = d.client_name;
  if (isHttpsUrl(d.client_uri)) metadata.client_uri = d.client_uri;
  if (isHttpsUrl(d.logo_uri)) metadata.logo_uri = d.logo_uri;

  return { ok: true, metadata };
}

/** Exact string match only — no normalization, no prefix matching. */
export function matchRedirectUri(
  metadata: Pick<ClientMetadata, "redirect_uris">,
  redirectUri: string,
): boolean {
  return metadata.redirect_uris.includes(redirectUri);
}

/** ADR-022 D3: which trust tier a client_id belongs to. */
export function clientTier(clientId: string, issuer: string): ClientTier {
  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    return "cimd-verified";
  }
  const iss = new URL(issuer);
  return url.origin === iss.origin && url.pathname.startsWith(DCR_CLIENTS_PATH)
    ? "dcr-derived"
    : "cimd-verified";
}

/** Clamp a Cache-Control max-age into [MIN_TTL, MAX_TTL]. */
export function cacheTtlSeconds(cacheControl: string | null): number {
  const m = cacheControl?.match(/(?:^|,)\s*max-age=(\d+)\s*(?:,|$)/i);
  const requested = m ? Number(m[1]) : 0;
  return Math.min(
    CLIENT_METADATA_MAX_TTL_S,
    Math.max(CLIENT_METADATA_MIN_TTL_S, requested),
  );
}

async function readCapped(res: Response, max: number): Promise<string | null> {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder().decode(buf);
}

/**
 * Fetch and validate a client's metadata document. Never throws: every
 * failure, including a timeout, is a refusal. The caller is expected to have
 * run validateClientIdUrl first.
 */
export async function fetchClientMetadata(
  clientId: string,
  fetchFn: typeof fetch = fetch,
): Promise<Result<{ metadata: ClientMetadata; ttlSeconds: number }>> {
  let res: Response;
  try {
    res = await fetchFn(clientId, {
      method: "GET",
      redirect: "manual",
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(CLIENT_METADATA_TIMEOUT_MS),
    });
  } catch {
    return { ok: false, reason: "metadata fetch failed" };
  }

  if (res.status !== 200) {
    return { ok: false, reason: `metadata fetch returned ${res.status}` };
  }
  const type = res.headers.get("content-type") ?? "";
  if (!/^application\/json\s*(;|$)/i.test(type)) {
    return { ok: false, reason: "metadata must be application/json" };
  }

  let text: string | null;
  try {
    text = await readCapped(res, CLIENT_METADATA_MAX_BYTES);
  } catch {
    return { ok: false, reason: "metadata read failed" };
  }
  if (text === null) {
    return { ok: false, reason: "metadata document too large" };
  }

  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return { ok: false, reason: "metadata is not valid JSON" };
  }

  const v = validateClientMetadata(doc, clientId);
  if (!v.ok) return v;
  return {
    ok: true,
    metadata: v.metadata,
    ttlSeconds: cacheTtlSeconds(res.headers.get("cache-control")),
  };
}
