/**
 * The Cache API, with failures that RECOVER (notme-a34dad, overnight review M3).
 *
 * worker.ts used to set `cacheEnabled = false` "for remainder of isolate
 * lifetime" on any throw from `cache.put` or `cache.match`. One transient
 * error therefore sent every later .well-known request in that isolate to the
 * singleton SigningAuthority — during an overload, exactly when it could
 * least afford them, so the overload fed itself.
 *
 * Now a failure turns that route's cache operation off for a backoff that
 * doubles per consecutive failure (1 s, 2 s, 4 s … capped at 60 s) and
 * resets on the first success. A permanently broken cache costs one attempt a minute; a
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

/**
 * One circuit per (operation, route), not one per isolate (review L6). A
 * single shared circuit let ANY failure — a `put` that throws on some other
 * route's key, a match timeout — switch caching off for the DO-backed
 * `.well-known` documents too, which is M3's amplification again for up to
 * BACKOFF_MAX_MS. Now:
 *  - the family is the key's PATH (the query, which carries the build and
 *    whatever a caller appended, is not part of it), so jwks.json failing
 *    leaves epochs.json alone;
 *  - `match` and `put` have separate circuits, so a failing put never stops
 *    the matches that keep requests off the DO.
 * Bounded: past MAX_FAMILIES distinct paths (the host-canonicalisation
 * redirect caches arbitrary paths), new paths share one overflow circuit
 * rather than growing the map.
 */
type Circuit = { failures: number; disabledUntil: number };
type Op = "match" | "put";
const MAX_FAMILIES = 64;
const circuits = new Map<string, Circuit>();
const overflow: Record<Op, Circuit> = { match: { failures: 0, disabledUntil: 0 }, put: { failures: 0, disabledUntil: 0 } };
let offForIsolate = false;

function familyOf(key: Request): string {
  try {
    return new URL(key.url).pathname;
  } catch {
    return "";
  }
}

function circuit(op: Op, key: Request, create: boolean): Circuit | undefined {
  const id = `${op}:${familyOf(key)}`;
  let c = circuits.get(id);
  if (!c && create) {
    if (circuits.size >= 2 * MAX_FAMILIES) return overflow[op];
    c = { failures: 0, disabledUntil: 0 };
    circuits.set(id, c);
  }
  return c ?? (circuits.size >= 2 * MAX_FAMILIES ? overflow[op] : undefined);
}

function defaultCache(): CacheLike {
  // Throws (ReferenceError) where there is no Cache API; that is a failure
  // like any other and backs off.
  return (caches as unknown as { default: CacheLike }).default;
}

function usable(op: Op, key: Request, now: number): boolean {
  if (offForIsolate) return false;
  const c = circuit(op, key, false);
  return !c || now >= c.disabledUntil;
}

function failed(op: Op, key: Request, now: number): void {
  const c = circuit(op, key, true)!;
  c.failures++;
  c.disabledUntil = now + Math.min(BACKOFF_BASE_MS * 2 ** (c.failures - 1), BACKOFF_MAX_MS);
}

function succeeded(op: Op, key: Request): void {
  const c = circuit(op, key, false);
  if (c) {
    c.failures = 0;
    c.disabledUntil = 0;
  }
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
  if (!usable("match", key, now)) return undefined;
  try {
    const hit = await (cache ?? defaultCache()).match(key);
    succeeded("match", key);
    return hit;
  } catch {
    failed("match", key, now);
    return undefined;
  }
}

export async function edgePut(
  key: Request,
  value: Response,
  cache?: CacheLike,
  now = Date.now(),
): Promise<void> {
  if (!usable("put", key, now)) return;
  try {
    await (cache ?? defaultCache()).put(key, value);
    succeeded("put", key);
  } catch {
    failed("put", key, now);
  }
}

/** For tests only: one circuit's state. */
export function __edgeCacheStateForTests(
  key: Request,
  op: Op,
): { failures: number; disabledUntil: number; offForIsolate: boolean } {
  const c = circuit(op, key, false) ?? { failures: 0, disabledUntil: 0 };
  return { failures: c.failures, disabledUntil: c.disabledUntil, offForIsolate };
}

/** For tests only: how many circuits exist. */
export function __edgeCacheFamiliesForTests(): number {
  return circuits.size;
}

/** For tests only. */
export function __resetEdgeCacheForTests(): void {
  circuits.clear();
  for (const c of Object.values(overflow)) {
    c.failures = 0;
    c.disabledUntil = 0;
  }
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

