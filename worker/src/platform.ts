// Platform abstraction — unified API across CF edge and local workerd.
//
// Detects runtime and provides:
// - CacheStore (KV on CF, SQLite locally)
// - Key storage mode (ephemeral / encrypted / cf-managed)
// - Rate limiting (CF binding or no-op)

export type KeyStorageMode = "ephemeral" | "encrypted" | "cf-managed";

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

  // Auto-detect: KEK secret present -> encrypted, otherwise ephemeral
  if (env.NOTME_KEK_SECRET) return "encrypted";
  return "ephemeral";
}

/** Validate config — fail closed on misconfiguration. */
export function validateKeyStorageConfig(
  mode: KeyStorageMode,
  kekSecret: string | undefined,
): void {
  if (mode === "encrypted") {
    if (!kekSecret) {
      throw new Error(
        "FATAL: NOTME_KEY_STORAGE=encrypted requires NOTME_KEK_SECRET.\n" +
          "Generate with: openssl rand -hex 32",
      );
    }
    if (kekSecret.length < 32) {
      throw new Error(
        "FATAL: NOTME_KEK_SECRET must be at least 128 bits (32 hex chars).\n" +
          "Generate with: openssl rand -hex 32",
      );
    }
  }
}

/** In-memory cache with TTL — used in local workerd where KV is unavailable.
 *  Provides real JTI replay protection (not a no-op). Entries expire by TTL. */
export class MemoryCache implements CacheStore {
  private store = new Map<string, { value: string; expiresAt: number | null }>();

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
