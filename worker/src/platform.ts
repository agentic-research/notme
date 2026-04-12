// Platform abstraction — unified API across CF edge and local workerd.
//
// Detects runtime and provides:
// - CacheStore (KV on CF, SQLite locally)
// - Key storage mode (ephemeral / encrypted / cf-managed)
// - Rate limiting (CF binding or no-op)

export type KeyStorageMode = "ephemeral" | "encrypted" | "cf-managed";

// Ed25519 is not in the WebCrypto TypeScript types (@cloudflare/workers-types).
// Single declaration avoids scattered `as any` casts in security-critical code.
export const ED25519 = { name: "Ed25519" } as any;

export interface CacheStore {
  get(key: string): Promise<string | null>;
  put(
    key: string,
    value: string,
    opts?: { expirationTtl?: number },
  ): Promise<void>;
}

export interface Platform {
  readonly keyStorage: KeyStorageMode;
  readonly cache: CacheStore;
  rateLimit?(key: string): Promise<boolean>;
}

/** Detect key storage mode from environment. */
export function detectKeyStorage(env: Record<string, unknown>): KeyStorageMode {
  const explicit = env.NOTME_KEY_STORAGE as string | undefined;
  if (explicit === "ephemeral") return "ephemeral";
  if (explicit === "encrypted") return "encrypted";
  if (explicit === "cf-managed") return "cf-managed";

  // Auto-detect: KEK secret present -> encrypted, otherwise cf-managed.
  // cf-managed is the safe default — CF handles encryption at rest.
  // Local workerd sets NOTME_KEY_STORAGE=ephemeral in config.capnp.
  if (env.NOTME_KEK_SECRET) return "encrypted";
  return "cf-managed";
}

/** Validate config — fail closed on misconfiguration. */
export function validateKeyStorageConfig(
  mode: KeyStorageMode,
  _kekSecret?: string | undefined,
): void {
  if (mode === "encrypted") {
    // Encrypted mode is designed but not yet implemented (HKDF wrapping).
    // Fail hard so operators don't get a false sense of security.
    throw new Error(
      "FATAL: encrypted key storage is not yet implemented.\n" +
        "Use NOTME_KEY_STORAGE=ephemeral (local/CI) or cf-managed (production).\n" +
        "See docs/design/007-secretless-local-proxy.md for roadmap.",
    );
  }
}

/** In-memory cache with TTL — used in local workerd where KV is unavailable.
 *  Provides real JTI replay protection (not a no-op). Entries expire by TTL. */
export class MemoryCache implements CacheStore {
  private store = new Map<string, { value: string; expiresAt: number | null }>();
  private putCount = 0;
  private static readonly SWEEP_INTERVAL = 100; // evict expired entries every N puts

  async get(key: string): Promise<string | null> {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (entry.expiresAt !== null && entry.expiresAt <= Math.floor(Date.now() / 1000)) {
      this.store.delete(key);
      return null;
    }
    return entry.value;
  }

  async put(
    key: string,
    value: string,
    opts?: { expirationTtl?: number },
  ): Promise<void> {
    const expiresAt = opts?.expirationTtl
      ? Math.floor(Date.now() / 1000) + opts.expirationTtl
      : null;
    this.store.set(key, { value, expiresAt });

    // Periodic sweep — prevents unbounded growth from one-shot JTI entries
    if (++this.putCount % MemoryCache.SWEEP_INTERVAL === 0) {
      const now = Math.floor(Date.now() / 1000);
      for (const [k, v] of this.store) {
        if (v.expiresAt !== null && v.expiresAt <= now) this.store.delete(k);
      }
    }
  }
}

/** CF KV-backed cache. */
export class KVCache implements CacheStore {
  constructor(private kv: KVNamespace) {}

  async get(key: string): Promise<string | null> {
    return this.kv.get(key);
  }

  async put(
    key: string,
    value: string,
    opts?: { expirationTtl?: number },
  ): Promise<void> {
    await this.kv.put(key, value, opts);
  }
}

/** SQLite-backed cache — used in local workerd where KV is unavailable. */
export class SQLiteCache implements CacheStore {
  constructor(private sql: SqlStorage) {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS kv_cache (
        key        TEXT PRIMARY KEY,
        value      TEXT NOT NULL,
        expires_at INTEGER
      )
    `);
  }

  async get(key: string): Promise<string | null> {
    const now = Math.floor(Date.now() / 1000);
    const rows = this.sql
      .exec(
        "SELECT value FROM kv_cache WHERE key = ? AND (expires_at IS NULL OR expires_at > ?)",
        key,
        now,
      )
      .toArray() as Array<{ value: string }>;
    return rows[0]?.value ?? null;
  }

  async put(
    key: string,
    value: string,
    opts?: { expirationTtl?: number },
  ): Promise<void> {
    const expiresAt = opts?.expirationTtl
      ? Math.floor(Date.now() / 1000) + opts.expirationTtl
      : null;
    this.sql.exec(
      "INSERT OR REPLACE INTO kv_cache (key, value, expires_at) VALUES (?, ?, ?)",
      key,
      value,
      expiresAt,
    );
  }
}

/** Build a Platform from the Worker env object. */
export function createPlatform(
  env: Record<string, any>,
  sql?: SqlStorage,
): Platform {
  const keyStorage = detectKeyStorage(env);
  validateKeyStorageConfig(keyStorage, env.NOTME_KEK_SECRET);

  let cache: CacheStore;
  if (env.CA_BUNDLE_CACHE) {
    cache = new KVCache(env.CA_BUNDLE_CACHE);
  } else if (sql) {
    cache = new SQLiteCache(sql);
  } else {
    cache = new MemoryCache();
  }

  const platform: Platform = {
    keyStorage,
    cache,
  };

  if (env.CERT_LIMITER) {
    platform.rateLimit = async (key: string) => {
      const { success } = await env.CERT_LIMITER.limit({ key });
      return success;
    };
  }

  return platform;
}
