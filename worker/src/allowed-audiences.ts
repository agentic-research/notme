/**
 * Audience allowlist — every endpoint that mints an access token must
 * check the requested audience against this set.
 *
 * `DEFAULT_ALLOWED_AUDIENCES` is the production set baked into the
 * source. `getAllowedAudiences(env)` overrides via env.ALLOWED_AUDIENCES
 * (CSV) so staging or self-hosted deployments can pin different
 * resource servers without a code change. Empty/missing env → falls
 * back to the default. Env value fully REPLACES the default — operators
 * declare exactly what their deployment trusts.
 *
 * In its own file (no DO dependencies) so unit tests can import without
 * pulling in `cloudflare:workers` via the worker entry point.
 */

export const DEFAULT_ALLOWED_AUDIENCES: ReadonlyArray<string> = [
  "https://rosary.bot",
  "https://mcp.rosary.bot",
  "https://auth.notme.bot",
  "https://notme.bot",
  "https://mache.rosary.bot",
];

export function getAllowedAudiences(
  env: { ALLOWED_AUDIENCES?: string },
): Set<string> {
  const raw = (env.ALLOWED_AUDIENCES ?? "").trim();
  if (!raw) return new Set(DEFAULT_ALLOWED_AUDIENCES);
  return new Set(
    raw
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0),
  );
}
