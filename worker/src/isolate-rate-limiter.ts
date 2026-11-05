/**
 * A fixed-window rate limiter held in ISOLATE memory, shaped like a Workers
 * rate-limit binding (`limit({ key }) -> { success }`), for when no binding
 * is configured (notme-153f03).
 *
 * PER-ISOLATE, AND ONLY THAT. Its counts live in this isolate's heap: two
 * isolates (two Cloudflare locations, two workerd processes, a restart) each
 * count from zero. On a single self-hosted workerd process that is one
 * isolate, so it is a real bound there; on Cloudflare it is a floor under the
 * `[[ratelimits]]` binding, not a substitute for it.
 *
 * Memory is bounded: past `maxKeys` live keys, expired windows are swept, and
 * if every slot is still live a NEW key is refused rather than admitted, so a
 * key flood cannot grow the map or buy a fresh budget per key.
 */
export class IsolateRateLimiter {
  #windows = new Map<string, { start: number; count: number }>();
  #limit: number;
  #periodMs: number;
  #maxKeys: number;

  constructor(opts: { limit: number; periodSeconds: number; maxKeys?: number }) {
    this.#limit = opts.limit;
    this.#periodMs = opts.periodSeconds * 1000;
    this.#maxKeys = opts.maxKeys ?? 1024;
  }

  async limit({ key }: { key: string }): Promise<{ success: boolean }> {
    const now = Date.now();
    let w = this.#windows.get(key);
    // A window that started in the "future" (the clock stepped back) is stale
    // too: holding it would refuse the key until the clock caught up.
    if (w && (now - w.start >= this.#periodMs || now < w.start)) {
      this.#windows.delete(key);
      w = undefined;
    }
    if (!w) {
      if (this.#windows.size >= this.#maxKeys) {
        for (const [k, v] of this.#windows) {
          if (now - v.start >= this.#periodMs || now < v.start) this.#windows.delete(k);
        }
        if (this.#windows.size >= this.#maxKeys) return { success: false };
      }
      w = { start: now, count: 0 };
      this.#windows.set(key, w);
    }
    w.count++;
    return { success: w.count <= this.#limit };
  }
}
