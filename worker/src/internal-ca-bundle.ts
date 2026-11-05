import { opaqueError } from "./error-body";
import type { Platform } from "./platform";
import { isBundleStale } from "./revocation";
import type { CABundle } from "./revocation";

const CURRENT_BUNDLE_CACHE_KEY = "bundle:current";

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
      // Staleness is checked AT THE READ. This is THE bound on a bundle's life,
      // not a backstop: bundle:current carries no KV TTL (see the put below),
      // because an expired key fails revocation open. The 130-day fossil
      // (notme-77a024) is refused here and regenerated, so the serving path
      // cannot hand out a fossil whatever the cache layer does (notme-8d3018).
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
  // NO expirationTtl, the same as the DO's #publishBundle. The bound on a
  // bundle's life is the READ-TIME staleness check (isBundleStale, here above
  // and in checkRevocation), which fails CLOSED. A KV TTL turns a stale bundle
  // into an ABSENT one, and checkRevocation fails OPEN on an absent bundle
  // (the bootstrap case). This put used to carry `expirationTtl: 60`, so with
  // the refresh alarm stopped the key expired a minute after the Worker last
  // wrote it, and every revoked certificate was accepted from then on
  // (bundle-no-ttl.test.ts).
  //
  // The 130-day fossil that the TTL was added for (notme-77a024) cannot
  // recur this way: a fossil is stale at every read, so this path regenerates
  // it and checkRevocation refuses it.
  await platform.cache.put(CURRENT_BUNDLE_CACHE_KEY, JSON.stringify(bundle));
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
