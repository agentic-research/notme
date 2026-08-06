// Platform abstraction — unified API across CF edge and local workerd.
//
// Detects runtime and provides:
// - CacheStore (KV on CF, SQLite locally)
// - Key storage mode (ephemeral / encrypted / cf-managed)
// - Rate limiting (CF binding or no-op)

export type KeyStorageMode = "ephemeral" | "encrypted" | "cf-managed";

// Ed25519 algorithm identifier — single declaration so security-critical
// crypto call sites stay type-clean.
//
// CF Workers' WebCrypto runtime fully implements Ed25519 (BoringSSL); the
// TypeScript DOM lib's `SubtleCrypto.sign`/`verify` overloads, however, do
// not yet enumerate it as a valid AlgorithmIdentifier, and
// `@cloudflare/workers-types` doesn't extend the algorithm union for it.
// The `as any` here is a typing workaround, not a security bypass — the
// algorithm string is forwarded to the runtime verbatim.
//
// All production sign/verify call sites import this constant rather than
// inlining their own cast. When the lib types catch up (or workers-types
// adds the entry), drop the `as any` here and every call site gets fixed
// for free. Tests inline their own `"Ed25519" as any` casts because they
// often need to construct distinct algorithm objects (importKey vs sign);
// keeping this constant production-only avoids changing test plumbing.
//
// See SECURITY.md "Ed25519 typing workaround" for the audit note.
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

/**
 * Validate config — fail closed on misconfiguration.
 *
 * Encrypted mode is IMPLEMENTED as of notme-41d0d3 (`src/key-encryption.ts`).
 * Until then this threw unconditionally, which combined badly with
 * `detectKeyStorage` above: setting NOTME_KEK_SECRET auto-selects "encrypted",
 * so an operator following the ADR-007 roadmap and setting the secret bricked
 * the authority on boot. Both halves are live now.
 *
 * The remaining fail-closed case is the one that matters: mode says encrypted
 * but no secret is present. Continuing would write the CA private key in
 * cleartext while the operator believes it is sealed — the exact false sense
 * of security the previous throw existed to prevent.
 */
/**
 * Minimum KEK secret length, in characters — ADR-007 §169's "at least 32 hex
 * characters (128 bits of entropy)".
 *
 * The floor is on LENGTH, never on content. An entropy heuristic over an
 * operator's passphrase is a guess, and one that rejects a legitimate
 * high-entropy secret is worse than no check at all: the operator's fix is
 * then to choose a WORSE secret that happens to satisfy the heuristic.
 */
const MIN_KEK_SECRET_CHARS = 32;

export function validateKeyStorageConfig(
  mode: KeyStorageMode,
  kekSecret?: string | undefined,
): void {
  if (mode !== "encrypted") return;

  if (!kekSecret) {
    throw new Error(
      "FATAL: NOTME_KEY_STORAGE=encrypted but NOTME_KEK_SECRET is unset.\n" +
        "Set the secret, or use NOTME_KEY_STORAGE=ephemeral (local/CI) or " +
        "cf-managed (CF encryption at rest only, key stored as plaintext JWK).\n" +
        "See docs/design/007-secretless-local-proxy.md.",
    );
  }

  // ADR-007 §169 specified this check, and 007-secretless-plan.md §149
  // specified its test. Neither shipped — this is the one finding in the
  // documentation audit where the DOCUMENT was right and the implementation
  // regressed (notme-bed754).
  //
  // Why it is not a nicety: `deriveKek` refuses only an EMPTY secret, so
  // NOTME_KEK_SECRET=weak derives a perfectly usable AES-GCM key and the
  // authority boots reporting encrypted storage. The operator gets the
  // APPEARANCE of a sealed CA master key with none of the strength, and
  // PBKDF2 over a four-character input is brute-forceable offline by anyone
  // who obtains the ciphertext. A false sense of sealing is the specific
  // harm the unset-secret throw above already exists to prevent.
  //
  // Trimmed before measuring: `wrangler secret put` from a file or a shell
  // heredoc trivially carries a trailing newline, and letting an invisible
  // character satisfy an entropy floor is the least debuggable way to fail
  // this check.
  if (kekSecret.trim().length < MIN_KEK_SECRET_CHARS) {
    throw new Error(
      `FATAL: NOTME_KEK_SECRET must be at least 128 bits (${MIN_KEK_SECRET_CHARS} hex chars).\n` +
        "It seals the CA master key at rest; a short secret is brute-forceable " +
        "offline by anyone who obtains the ciphertext.\n" +
        "Generate one with: openssl rand -hex 32\n" +
        "See docs/design/007-secretless-local-proxy.md.",
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
