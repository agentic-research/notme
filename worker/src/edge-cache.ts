/**
 * The Cache API, with failures that RECOVER (notme-a34dad, overnight review M3).
 *
 * worker.ts used to set `cacheEnabled = false` "for remainder of isolate
 * lifetime" on any throw from `cache.put` or `cache.match`. One transient
 * error therefore sent every later .well-known request in that isolate to the
 * singleton SigningAuthority — during an overload, exactly when it could
 * least afford them, so the overload fed itself.
 *
 * Now a failure turns the cache off for a backoff that doubles per
 * consecutive failure (1 s, 2 s, 4 s … capped at 60 s) and resets on the
 * first success. A permanently broken cache costs one attempt a minute; a
 * blip costs a second.
 *
 * The one PERMANENT off switch is deliberate and separate: local workerd has
 * no Cache API, and worker.ts says so once per isolate (`disableForIsolate`).
 *
 * `match` awaits inside its try. The old helper returned `cache.match(...)`
 * unawaited, so a rejected match escaped the catch it was written for.
 */

export const BACKOFF_BASE_MS = 1_000;
export const BACKOFF_MAX_MS = 60_000;

type CacheLike = {
  match(key: Request): Promise<Response | undefined>;
  put(key: Request, value: Response): Promise<void>;
};

let failures = 0;
let disabledUntil = 0;
let offForIsolate = false;

function defaultCache(): CacheLike {
  // Throws (ReferenceError) where there is no Cache API; that is a failure
  // like any other and backs off.
  return (caches as unknown as { default: CacheLike }).default;
}

function usable(now: number): boolean {
  return !offForIsolate && now >= disabledUntil;
}

function failed(now: number): void {
  failures++;
  disabledUntil = now + Math.min(BACKOFF_BASE_MS * 2 ** (failures - 1), BACKOFF_MAX_MS);
}

function succeeded(): void {
  failures = 0;
  disabledUntil = 0;
}

/** Local workerd: no Cache API, for the life of this isolate. */
export function disableForIsolate(): void {
  offForIsolate = true;
}

export async function edgeMatch(
  key: Request,
  cache?: CacheLike,
  now = Date.now(),
): Promise<Response | undefined> {
  if (!usable(now)) return undefined;
  try {
    const hit = await (cache ?? defaultCache()).match(key);
    succeeded();
    return hit;
  } catch {
    failed(now);
    return undefined;
  }
}

export async function edgePut(
  key: Request,
  value: Response,
  cache?: CacheLike,
  now = Date.now(),
): Promise<void> {
  if (!usable(now)) return;
  try {
    await (cache ?? defaultCache()).put(key, value);
    succeeded();
  } catch {
    failed(now);
  }
}

/** For tests only. */
export function __edgeCacheStateForTests(): { failures: number; disabledUntil: number; offForIsolate: boolean } {
  return { failures, disabledUntil, offForIsolate };
}

/** For tests only. */
export function __resetEdgeCacheForTests(): void {
  failures = 0;
  disabledUntil = 0;
  offForIsolate = false;
}

/**
 * How long a DO-backed public document's 503 is cached at the edge (M3).
 *
 * DELIBERATE, and short. During a DO overload every uncached request for
 * jwks.json, epochs.json or ca-bundle.pem is one more call on the object that
 * is already refusing them, so not caching the 503 is what made an overload
 * sustain itself. Five seconds bounds that to one call per document per colo
 * per 5 s. Its cost — a transient one-off failure pinned for up to 5 s in one
 * colo — is small next to that: every consumer of these documents already
 * holds its own copy for up to 300 s (ROTATION_BOUND_CACHE_CONTROL), so a
 * 5 s gap is absorbed, and the bound is far below any rotation window. Only
 * 503 is cached negatively: it is the "authority unavailable" answer, and a
 * 4xx or 500 from these routes would be a bug worth seeing on every request.
 */
export const NEGATIVE_CACHE_SECONDS = 5;

// The 503 is ALSO remembered per isolate, and that is the part relied on:
// whether the Cache API stores a 503 at all is not something this code can
// count on (miniflare's cache, via http-cache-semantics, refuses to store a
// status it does not "understand", 503 among them; Cloudflare's own policy
// is not verified here). The edge put is attempted; this map always holds.
// Bounded: only the fixed set of serveCachedPublic routes write to it, keyed
// by their query-free cache key.
const unavailableUntil = new Map<string, number>();
const UNAVAILABLE_MAX_KEYS = 64;

export function noteUnavailable(key: Request, now = Date.now()): void {
  if (unavailableUntil.size >= UNAVAILABLE_MAX_KEYS) {
    for (const [k, t] of unavailableUntil) if (t <= now) unavailableUntil.delete(k);
    if (unavailableUntil.size >= UNAVAILABLE_MAX_KEYS) return;
  }
  unavailableUntil.set(key.url, now + NEGATIVE_CACHE_SECONDS * 1000);
}

/** Seconds left on a remembered 503 for this key, or 0. */
export function unavailableFor(key: Request, now = Date.now()): number {
  const t = unavailableUntil.get(key.url);
  if (t === undefined) return 0;
  if (t <= now) {
    unavailableUntil.delete(key.url);
    return 0;
  }
  return Math.ceil((t - now) / 1000);
}
