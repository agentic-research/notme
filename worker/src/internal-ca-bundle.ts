import type { Platform } from "./platform";
import type { CABundle } from "./revocation";

const CURRENT_BUNDLE_CACHE_KEY = "bundle:current";

/**
 * How long a published bundle may be reused, in seconds.
 *
 * MUST stay below `BUNDLE_MAX_AGE_MS` (5 minutes) in revocation.ts — a cached
 * bundle that outlives the consumer's staleness window is worse than no cache,
 * because every consumer rejects it and the endpoint looks healthy.
 *
 * 60s: a quarter of the window, so a bundle is refreshed four times over
 * before any conformant verifier would call it stale.
 */
const BUNDLE_CACHE_TTL_SECONDS = 60;

type SigningAuthorityStub = {
  generateBundle(): Promise<CABundle>;
};

type EnvWithSigningAuthority = {
  SIGNING_AUTHORITY: {
    idFromName(name: string): unknown;
    get(id: unknown): SigningAuthorityStub;
  };
};

export async function ensureCurrentCABundle(
  env: EnvWithSigningAuthority,
  platform: Platform,
): Promise<CABundle> {
  const existingBundle = await platform.cache.get(CURRENT_BUNDLE_CACHE_KEY);
  if (existingBundle) {
    try {
      return JSON.parse(existingBundle) as CABundle;
    } catch {
      // Regenerate below; a malformed cache entry should not pin the endpoint down.
    }
  }

  const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
  const authority = env.SIGNING_AUTHORITY.get(authorityId);
  const bundle = await authority.generateBundle();
  // TTL SHORTER THAN THE STALENESS WINDOW, or the endpoint serves a fossil.
  //
  // This put carried no TTL, so the first bundle generated was pinned in KV
  // permanently. Production served a bundle issued 2026-03-29 — 130 days old —
  // against a `BUNDLE_MAX_AGE_MS` of FIVE MINUTES. Any consumer running
  // `isBundleStale()` rejects it, so revocation was broken end to end for
  // every downstream verifier (notme-77a024).
  //
  // Two independent failures had to line up: the DO alarm that republishes
  // every BUNDLE_REFRESH_MS stopped running (it has a circuit breaker that
  // requires `resetAlarmHealth()` to clear), AND this cache never expired.
  // Either one alone would have been survivable — a live alarm refreshes
  // despite no TTL, and a TTL forces regeneration despite a dead alarm.
  //
  // So the TTL is not a duplicate of the alarm; it is the reason a dead alarm
  // degrades into "slightly stale" instead of "four months stale".
  await platform.cache.put(CURRENT_BUNDLE_CACHE_KEY, JSON.stringify(bundle), {
    expirationTtl: BUNDLE_CACHE_TTL_SECONDS,
  });
  return bundle;
}

export async function handleInternalCABundle(
  request: Request,
  env: EnvWithSigningAuthority,
  platform: Platform,
): Promise<Response> {
  if (request.method !== "GET") {
    return Response.json({ error: "method not allowed" }, { status: 405 });
  }

  try {
    const bundle = await ensureCurrentCABundle(env, platform);
    return Response.json(bundle, {
      headers: { "Cache-Control": "no-store" },
    });
  } catch (e: any) {
    return Response.json(
      { error: `authority unavailable: ${e?.message ?? "unknown"}` },
      { status: 503 },
    );
  }
}
