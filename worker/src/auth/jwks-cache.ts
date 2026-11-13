/**
 * jwks-cache.ts — the per-isolate JWKS cache every OIDC verifier shares
 * (notme-a36d10, overnight review M2).
 *
 * THE DEFECT. Both verifiers (gha-oidc.ts for GitHub, auth/verify-proof.ts
 * for the generic issuers) cached a JWKS for an hour and then:
 *  - on an UNKNOWN kid threw at once, with no refetch, so a GitHub key
 *    rotation failed /cert/gha, /token exchange and /bootstrap/claim for up
 *    to ~2 h (isolate cache plus the edge cache under the fetch);
 *  - on a FAILED fetch threw away keys that still verified, so an upstream
 *    JWKS outage took those routes down within the hour.
 *
 * THE RULES, per issuer, per isolate:
 *  - Fresh (younger than ttlMs) and the wanted key is there: no fetch.
 *  - Expired, or the wanted key is NOT there: fetch, at most once per
 *    minRefetchIntervalMs since the last attempt. An unknown-kid refetch
 *    asks the fetcher to bypass the edge cache, which would otherwise hand
 *    back the same pre-rotation document. A flood of tokens with invented
 *    kids therefore costs at most one upstream fetch per window.
 *  - Concurrent callers share one in-flight fetch (single-flight).
 *  - A failed fetch serves the cached keys while they are younger than
 *    maxStaleMs (a hard limit: past it the error surfaces), so an upstream
 *    outage does not drop keys that still verify.
 *  - A COLD issuer (nothing cached) always fetches (single-flight still
 *    applies): there is nothing to serve instead.
 *
 * Unknown kid after all that is still the CALLER's refusal; this only
 * decides which keys the caller gets to look in.
 */

export interface JwksCacheOptions {
  /** How long fetched keys are trusted without asking again. */
  ttlMs: number;
  /** The least time between two upstream attempts for one issuer. */
  minRefetchIntervalMs: number;
  /** How long after their fetch cached keys may still be served when the upstream fails. */
  maxStaleMs: number;
}

/** What the fetcher is told: bypass the edge cache (an unknown-kid refetch). */
export interface JwksFetchContext {
  bypassCache: boolean;
}

interface Entry<K> {
  keys: K[];
  fetchedAt: number;
  lastAttemptAt: number;
}

export class JwksCache<K> {
  readonly #fetcher: (issuer: string, ctx: JwksFetchContext) => Promise<K[]>;
  readonly #opts: JwksCacheOptions;
  readonly #now: () => number;
  readonly #entries = new Map<string, Entry<K>>();
  readonly #inflight = new Map<string, Promise<K[]>>();

  constructor(
    fetcher: (issuer: string, ctx: JwksFetchContext) => Promise<K[]>,
    opts: JwksCacheOptions,
    now: () => number = () => Date.now(),
  ) {
    this.#fetcher = fetcher;
    this.#opts = opts;
    this.#now = now;
  }

  /**
   * The keys to verify against. `has` says whether a key set contains the
   * key the caller needs; when it does not, the cache refetches (subject to
   * the rate limit) before answering.
   */
  async get(issuer: string, has: (keys: readonly K[]) => boolean = () => true): Promise<K[]> {
    const now = this.#now();
    const e = this.#entries.get(issuer);
    if (!e) return this.#refresh(issuer, false);
    const fresh = now - e.fetchedAt < this.#opts.ttlMs;
    const found = has(e.keys);
    if (fresh && found) return e.keys;
    if (now - e.lastAttemptAt < this.#opts.minRefetchIntervalMs) {
      // Rate-limited. Serve what is cached while it may be served at all.
      if (now - e.fetchedAt < this.#opts.maxStaleMs) return e.keys;
      throw new Error(`JWKS for ${issuer} is past its max-stale limit and refetch is rate-limited`);
    }
    // A fresh set missing the key: the upstream may have rotated, so look
    // past the edge cache, which would answer with the same document.
    return this.#refresh(issuer, fresh && !found);
  }

  #refresh(issuer: string, bypassCache: boolean): Promise<K[]> {
    const pending = this.#inflight.get(issuer);
    if (pending) return pending;
    const p = this.#doRefresh(issuer, bypassCache).finally(() => this.#inflight.delete(issuer));
    this.#inflight.set(issuer, p);
    return p;
  }

  async #doRefresh(issuer: string, bypassCache: boolean): Promise<K[]> {
    const startedAt = this.#now();
    const e = this.#entries.get(issuer);
    if (e) e.lastAttemptAt = startedAt;
    try {
      const keys = await this.#fetcher(issuer, { bypassCache });
      this.#entries.set(issuer, { keys, fetchedAt: startedAt, lastAttemptAt: startedAt });
      return keys;
    } catch (err) {
      if (e && startedAt - e.fetchedAt < this.#opts.maxStaleMs) {
        console.warn(
          JSON.stringify({
            event: "jwks.serve_stale",
            issuer,
            ageS: Math.floor((startedAt - e.fetchedAt) / 1000),
            error: String(err).slice(0, 200),
          }),
        );
        return e.keys;
      }
      throw err;
    }
  }
}

/** The shared policy: refetch at most once a minute, serve stale up to a day. */
export const JWKS_POLICY: JwksCacheOptions = {
  ttlMs: 60 * 60 * 1000,
  minRefetchIntervalMs: 60 * 1000,
  maxStaleMs: 24 * 60 * 60 * 1000,
};

/** Bound on each upstream JWKS request, so a hung issuer cannot hold a route. */
export const JWKS_FETCH_TIMEOUT_MS = 3000;
