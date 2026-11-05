import { opaqueError } from "./error-body";
import type { Platform } from "./platform";
import { isBundleStale } from "./revocation";
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
      const cached = JSON.parse(existingBundle) as CABundle;
      // Staleness is checked AT THE READ, not just assumed from the TTL.
      // The 130-day incident needed two failures to line up — a dead refresh
      // alarm and a TTL-less put — and both are fixed, and both could
      // regress. This gate is the third, independent safeguard: a bundle
      // that somehow survives past the staleness window is refused here and
      // regenerated, so the serving path cannot hand out a fossil whatever
      // the cache layer does (notme-8d3018).
      if (!isBundleStale(cached)) {
        return cached;
      }
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

// ── Serving /internal/ca-bundle without a stampede (notme-a34dad, review M1) ──
//
// The route is public — it is registered before host canonicalisation — and
// it used to read KV on EVERY request, and on a stale bundle every concurrent
// request ran its own generateBundle() on the singleton authority and its own
// KV put to one key (capped at 1 write/s). The most expensive unauthenticated
// path per request. Now, in order:
//
//  1. the edge cache (Cache API, per colo);
//  2. this isolate's last answer, if it is still inside its serve window;
//  3. ONE refresh per isolate at a time — ensureCurrentCABundle, which reads
//     KV and calls the DO only if that copy is stale. Every concurrent
//     request waits on the same promise.
//
// FRESHNESS IS UNCHANGED. Before, a bundle was served only while
// !isBundleStale(bundle), i.e. at most BUNDLE_MAX_AGE_MS (300 s) old at the
// moment it left the Worker, and the client was told no-store. Now a cached
// copy's window is min(SERVE_TTL_SECONDS, what is left of its 300 s), so a
// bundle still leaves the Worker at most 300 s old, and the client is still
// told no-store (the edge entry's max-age is not passed on, or a client
// holding it would add its own lifetime on top).
//
// What the short TTL DOES add is up to SERVE_TTL_SECONDS before a NEW bundle
// (a rotate() or revokeEpoch()) is seen by an isolate or colo that cached the
// old one — on top of KV's own propagation. The trust-anchor gates
// (release.yml, scripts/refresh-trust-anchor.ts) must see the live key right
// after a rotation (review F2, notme-ed6114), so a request that sends
// `Cache-Control: no-cache` skips steps 1 and 2. That bypass is the stampede
// shape again, so it is per-IP limited (CERT_LIMITER, `ca-bundle-ip:`), and it
// still shares step 3's single flight.

/** The longest an edge or isolate copy is reused. Short: see above. */
export const SERVE_TTL_SECONDS = 30;
/** How long a failed refresh's 503 is reused, per isolate and at the edge (M3). */
export const UNAVAILABLE_TTL_SECONDS = 5;

const BUNDLE_MAX_AGE_SECONDS = 300; // BUNDLE_MAX_AGE_MS in revocation.ts, in seconds

/** Seconds a copy of `bundle` may be reused from `nowMs`: within its 300 s, at most SERVE_TTL_SECONDS. */
export function serveWindowSeconds(bundle: CABundle, nowMs: number = Date.now()): number {
  if (isBundleStale(bundle, nowMs)) return 0;
  const left = Math.floor(bundle.issuedAt + BUNDLE_MAX_AGE_SECONDS - nowMs / 1000);
  return Math.max(0, Math.min(SERVE_TTL_SECONDS, left));
}

let memo: { bundle: CABundle; until: number } | null = null;
let unavailableUntil = 0;
let inflight: Promise<CABundle> | null = null;

/** Drop this isolate's copy — after a rotate or revocation this isolate made. */
export function invalidateCABundleMemo(): void {
  memo = null;
  unavailableUntil = 0;
}

/** For tests only: a cold isolate. */
export function __resetCABundleMemoForTests(): void {
  memo = null;
  unavailableUntil = 0;
  inflight = null;
}

function refreshOnce(env: EnvWithSigningAuthority, platform: Platform): Promise<CABundle> {
  if (inflight) return inflight;
  const p = ensureCurrentCABundle(env, platform).then(
    (bundle) => {
      const now = Date.now();
      memo = { bundle, until: now + serveWindowSeconds(bundle, now) * 1000 };
      unavailableUntil = 0;
      return bundle;
    },
    (e) => {
      unavailableUntil = Date.now() + UNAVAILABLE_TTL_SECONDS * 1000;
      throw e;
    },
  );
  inflight = p;
  p.then(
    () => { if (inflight === p) inflight = null; },
    () => { if (inflight === p) inflight = null; },
  );
  return p;
}

type EdgeCache = {
  match(key: Request): Promise<Response | undefined>;
  put(key: Request, value: Response): Promise<void>;
};

export type CABundleServeOptions = {
  /** The Worker's edge cache (worker.ts passes its backoff-wrapped Cache API). Absent: no edge step. */
  edge?: EdgeCache;
  /** The cache key for this request (worker.ts passes cacheKey(request)). */
  edgeKey?: Request;
  /** The bypass limiter: resolves false to refuse a `no-cache` request. Absent: no limit. */
  bypassAllowed?: () => Promise<boolean>;
};

const clientCopy = (body: BodyInit | null, status: number, headers: HeadersInit): Response => {
  const h = new Headers(headers);
  h.set("Cache-Control", "no-store");
  return new Response(body, { status, headers: h });
};

export async function handleInternalCABundle(
  request: Request,
  env: EnvWithSigningAuthority,
  platform: Platform,
  opts: CABundleServeOptions = {},
): Promise<Response> {
  if (request.method !== "GET") {
    return Response.json({ error: "method not allowed" }, { status: 405 });
  }

  const bypass = /\bno-cache\b/i.test(request.headers.get("cache-control") || "");
  if (bypass && opts.bypassAllowed && !(await opts.bypassAllowed())) {
    return Response.json({ error: "rate_limited" }, { status: 429, headers: { "Retry-After": "60" } });
  }

  const { edge, edgeKey } = opts;
  if (!bypass && edge && edgeKey) {
    const hit = await edge.match(edgeKey);
    if (hit) return clientCopy(hit.body, hit.status, hit.headers);
  }

  const now = Date.now();
  let bundle: CABundle | null = !bypass && memo && now < memo.until ? memo.bundle : null;
  if (!bundle) {
    if (!bypass && now < unavailableUntil) {
      return Response.json(
        { error: "authority unavailable" },
        { status: 503, headers: { "Cache-Control": "no-store", "Retry-After": String(UNAVAILABLE_TTL_SECONDS) } },
      );
    }
    try {
      bundle = await refreshOnce(env, platform);
    } catch (e: any) {
      // Constant body (notme-b567c9); the authority's error is logged.
      const res = opaqueError("internal-ca-bundle", "authority unavailable", 503, e);
      if (edge && edgeKey) {
        // Negatively cached for a few seconds (M3, src/edge-cache.ts
        // NEGATIVE_CACHE_SECONDS): an overloaded authority is not asked again
        // by every request in this colo.
        await edge.put(
          edgeKey,
          new Response(JSON.stringify({ error: "authority unavailable" }), {
            status: 503,
            headers: { "Content-Type": "application/json", "Cache-Control": `public, max-age=${UNAVAILABLE_TTL_SECONDS}` },
          }),
        );
      }
      return clientCopy(res.body, 503, { ...Object.fromEntries(res.headers), "Retry-After": String(UNAVAILABLE_TTL_SECONDS) });
    }
  }

  const body = JSON.stringify(bundle);
  const ttl = serveWindowSeconds(bundle);
  if (edge && edgeKey && ttl > 0) {
    await edge.put(
      edgeKey,
      new Response(body, {
        headers: { "Content-Type": "application/json", "Cache-Control": `public, max-age=${ttl}` },
      }),
    );
  }
  return clientCopy(body, 200, { "Content-Type": "application/json" });
}
