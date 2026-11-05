/**
 * jti-kv.ts — the KV half of an OIDC token's one-spend rule (notme-a3804c,
 * overnight review L4).
 *
 * Since notme-b0d10f the authoritative spend is the SigningAuthority's
 * `oidc:<iss>#<jti>`, made atomically in the DO. The KV `jti:<jti>` key is
 * the cross-check, written AFTER that spend: an edge that sees it can refuse
 * a replay without a DO call. So a failed write loses only that shortcut —
 * the DO still refuses the replay — while letting the throw escape turned
 * the request into a 500 with the caller's token already burnt, the one
 * outcome a client cannot recover from. Hence: log it, and finish.
 */

export interface JtiKv {
  put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>;
}

/** Record `key` as spent in KV for `ttlSeconds`. Never throws. */
export async function markJtiSpentInKv(
  cache: JtiKv,
  key: string,
  ttlSeconds: number,
  route: string,
): Promise<void> {
  try {
    await cache.put(key, "1", { expirationTtl: ttlSeconds });
  } catch (err) {
    // The jti is not a secret, but the key is left out: the event is about
    // the KV write, and route + error are what an operator acts on.
    console.error({ event: "jti.kv_write_failed", route, error: String(err).slice(0, 200) });
  }
}
