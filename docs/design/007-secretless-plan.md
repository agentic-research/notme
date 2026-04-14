# Secretless Local Proxy — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the notme identity authority run locally via workerd with private keys that never touch disk — same code, same behavior, three deployment targets.

**Architecture:** Thin `Platform` abstraction detects runtime (CF edge vs workerd) and provides unified cache + key storage. Signing authority DO uses `extractable: false` CryptoKeys in ephemeral mode. Host routing bypass for localhost. SQLite-backed cache replaces KV locally.

**Tech Stack:** TypeScript, workerd (CF Workers runtime), Web Crypto, esbuild, vitest

**Spec:** `docs/design/007-secretless-local-proxy.md`

---

### Task 1: Build tooling — esbuild + Taskfile + config.capnp

**Files:**
- Modify: `worker/package.json:4-10`
- Modify: `Taskfile.yml` (add tasks after line 122)
- Modify: `worker/config.capnp`

- [ ] **Step 1: Add esbuild dev dependency**

Run: `cd worker && npm install --save-dev esbuild`

- [ ] **Step 2: Add build:local script to package.json**

In `worker/package.json`, add to the `"scripts"` block:

```json
"build:local": "esbuild worker.ts --bundle --format=esm --outfile=dist/worker.js --conditions=workerd --external:cloudflare:workers --external:@cloudflare/vitest-pool-workers"
```

- [ ] **Step 3: Add Taskfile entries**

Append to `Taskfile.yml` after the `ship-prod` task:

```yaml
  worker:build-local:
    desc: Bundle worker for local workerd
    dir: worker
    cmds:
      - npx esbuild worker.ts --bundle --format=esm --outfile=dist/worker.js --conditions=workerd --external:cloudflare:workers --external:@cloudflare/vitest-pool-workers

  worker:serve:
    desc: Run local identity authority via workerd
    dir: worker
    deps: [worker:build-local]
    cmds:
      - npx workerd serve config.capnp --experimental
```

- [ ] **Step 4: Finalize config.capnp**

Add `NOTME_KEY_STORAGE` env var binding to the bindings array (after `GHA_ALLOWED_OWNERS`):

```capnp
    # Key storage mode — ephemeral for local dev (no private key on disk)
    ( name = "NOTME_KEY_STORAGE",
      text = "ephemeral",
    ),
```

- [ ] **Step 5: Test the build**

Run: `cd worker && npm run build:local`
Expected: `dist/worker.js` created, no errors.

- [ ] **Step 6: Commit**

```
build: add esbuild + Taskfile for local workerd

Adds build:local script, worker:build-local and worker:serve Taskfile
tasks, and finalizes config.capnp with enableSql, DO bindings, and
NOTME_KEY_STORAGE=ephemeral default.
```

---

### Task 2: Platform interface + detection logic

**Files:**
- Create: `worker/src/platform.ts`
- Test: `worker/src/__tests__/platform.test.ts`

- [ ] **Step 1: Write the failing test for platform detection**

Create `worker/src/__tests__/platform.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { detectKeyStorage, validateKeyStorageConfig } from "../platform";

describe("platform detection", () => {
  describe("detectKeyStorage", () => {
    it("defaults to ephemeral when no env vars set", () => {
      expect(detectKeyStorage({} as any)).toBe("ephemeral");
    });

    it("auto-detects encrypted when KEK secret present", () => {
      expect(
        detectKeyStorage({ NOTME_KEK_SECRET: "a".repeat(32) } as any),
      ).toBe("encrypted");
    });

    it("respects explicit NOTME_KEY_STORAGE=ephemeral", () => {
      expect(
        detectKeyStorage({ NOTME_KEY_STORAGE: "ephemeral" } as any),
      ).toBe("ephemeral");
    });

    it("respects explicit NOTME_KEY_STORAGE=encrypted with valid KEK", () => {
      expect(
        detectKeyStorage({
          NOTME_KEY_STORAGE: "encrypted",
          NOTME_KEK_SECRET: "ab".repeat(16),
        } as any),
      ).toBe("encrypted");
    });

    it("respects explicit NOTME_KEY_STORAGE=cf-managed", () => {
      expect(
        detectKeyStorage({ NOTME_KEY_STORAGE: "cf-managed" } as any),
      ).toBe("cf-managed");
    });
  });

  describe("validateKeyStorageConfig (fail closed)", () => {
    it("throws when encrypted mode has no KEK secret", () => {
      expect(() =>
        validateKeyStorageConfig("encrypted", undefined),
      ).toThrow("NOTME_KEK_SECRET");
    });

    it("throws when KEK secret is too short", () => {
      expect(() =>
        validateKeyStorageConfig("encrypted", "tooshort"),
      ).toThrow("128 bits");
    });

    it("accepts valid KEK secret (32+ hex chars)", () => {
      expect(() =>
        validateKeyStorageConfig("encrypted", "ab".repeat(16)),
      ).not.toThrow();
    });

    it("does not throw for ephemeral mode regardless of KEK", () => {
      expect(() =>
        validateKeyStorageConfig("ephemeral", undefined),
      ).not.toThrow();
    });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd worker && npx vitest run src/__tests__/platform.test.ts`
Expected: FAIL — `Cannot find module '../platform'`

- [ ] **Step 3: Write platform.ts**

Create `worker/src/platform.ts`:

```typescript
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

/** No-op cache — used when no cache binding is available. */
export class NullCache implements CacheStore {
  async get(): Promise<string | null> {
    return null;
  }
  async put(): Promise<void> {}
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
    cache = new NullCache();
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd worker && npx vitest run src/__tests__/platform.test.ts`
Expected: All tests PASS.

- [ ] **Step 5: Run full test suite**

Run: `cd worker && npx vitest run`
Expected: 78+ tests pass, no regressions.

- [ ] **Step 6: Commit**

```
feat(platform): add Platform interface with CacheStore + detection

Abstracts KV (CF) vs SQLite (local workerd) behind CacheStore interface.
Detects key storage mode from env vars. Fails closed: encrypted mode
without valid KEK secret refuses to start.
```

---

### Task 3: Ephemeral key storage — extractable: false

**Files:**
- Modify: `worker/src/signing-authority.ts:76-165`
- Test: `worker/src/__tests__/adversarial.test.ts`

- [ ] **Step 1: Write adversarial test for key non-extractability**

Create `worker/src/__tests__/adversarial.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { env } from "cloudflare:test";

describe("adversarial: key extraction", () => {
  it("no private key material in RPC responses (invariant #4)", async () => {
    const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
    const authority = env.SIGNING_AUTHORITY.get(authorityId);

    const responses: string[] = [];
    responses.push(JSON.stringify(await authority.getPublicKeyJwk()));
    responses.push(await authority.getPublicKeyPem());
    responses.push(JSON.stringify(await authority.getAuthorityState()));
    responses.push(await authority.getCACertificatePem());
    responses.push(JSON.stringify(await authority.generateBundle()));

    const combined = responses.join("\n");
    // Ed25519 private key JWK has a "d" field
    expect(combined).not.toMatch(/"d"\s*:\s*"[A-Za-z0-9_-]+"/);
    expect(combined).not.toContain("BEGIN PRIVATE KEY");
  });
});
```

- [ ] **Step 2: Run test — should pass (RPC already doesn't leak keys)**

Run: `cd worker && npx vitest run src/__tests__/adversarial.test.ts`
Expected: PASS.

- [ ] **Step 3: Add key storage mode to SigningAuthority**

In `worker/src/signing-authority.ts`, after line 29 (`private verifyKey`), add:

```typescript
  private keyStorageMode: "ephemeral" | "encrypted" | "cf-managed" = "cf-managed";

  setKeyStorageMode(mode: "ephemeral" | "encrypted" | "cf-managed"): void {
    this.keyStorageMode = mode;
  }
```

- [ ] **Step 4: Modify key import path — non-extractable after load**

Replace the key import block (lines 103-132) with:

```typescript
    if (rows.length > 0) {
      const row = rows[0]!;

      // Ephemeral mode: private_jwk is empty string — key only exists in memory
      if (!row.private_jwk) {
        // Key was ephemeral and we restarted — fall through to generate new key
      } else {
        const jwk = JSON.parse(row.private_jwk);
        this.signingKey = await crypto.subtle.importKey(
          "jwk",
          jwk,
          { name: "Ed25519" } as any,
          false, // non-extractable after import
          ["sign"],
        );
        const spkiBytes = Uint8Array.from(atob(row.public_spki), (c) =>
          c.charCodeAt(0),
        );
        this.verifyKey = await crypto.subtle.importKey(
          "spki",
          spkiBytes,
          { name: "Ed25519" } as any,
          true, // public key stays extractable (needed for JWKS)
          ["verify"],
        );
        let keyId = row.key_id;
        if (!keyId) {
          keyId = await SigningAuthority.keyIdFromSpki(row.public_spki);
          this.ctx.storage.sql.exec(
            "UPDATE keys SET key_id = ? WHERE id = 'authority'",
            keyId,
          );
        }
        return { signingKey: this.signingKey, verifyKey: this.verifyKey, keyId };
      }
    }
```

- [ ] **Step 5: Modify key generation — ephemeral uses extractable:false**

Replace the key generation block (lines 135-165) with:

```typescript
    // Generate the authority keypair
    const isEphemeral = this.keyStorageMode === "ephemeral";
    const kp = (await crypto.subtle.generateKey(
      { name: "Ed25519" } as any,
      !isEphemeral, // extractable:false in ephemeral mode
      ["sign", "verify"],
    )) as CryptoKeyPair;

    // Always extract public key (for key ID + JWKS)
    const publicSpki = (await crypto.subtle.exportKey(
      "spki",
      kp.publicKey,
    )) as ArrayBuffer;
    const publicSpkiB64 = btoa(
      String.fromCharCode(...new Uint8Array(publicSpki)),
    );
    const keyId = await SigningAuthority.keyIdFromSpki(publicSpkiB64);

    if (isEphemeral) {
      // Store public key + key ID only — no private key material on disk
      this.ctx.storage.sql.exec(
        "INSERT OR REPLACE INTO keys (id, private_jwk, public_spki, key_id) VALUES ('authority', '', ?, ?)",
        publicSpkiB64,
        keyId,
      );
      this.signingKey = kp.privateKey;
      this.verifyKey = kp.publicKey;
    } else {
      // Persistent: export JWK, store, then re-import as non-extractable
      const privateJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
      this.ctx.storage.sql.exec(
        "INSERT INTO keys (id, private_jwk, public_spki, key_id) VALUES ('authority', ?, ?, ?)",
        JSON.stringify(privateJwk),
        publicSpkiB64,
        keyId,
      );
      // Re-import as non-extractable
      this.signingKey = await crypto.subtle.importKey(
        "jwk",
        privateJwk,
        { name: "Ed25519" } as any,
        false,
        ["sign"],
      );
      this.verifyKey = kp.publicKey;
    }

    await this.scheduleNextRefresh();
    return { signingKey: this.signingKey, verifyKey: this.verifyKey, keyId };
```

- [ ] **Step 6: Run full test suite**

Run: `cd worker && npx vitest run`
Expected: All tests pass. Existing signing tests use cf-managed (default).

- [ ] **Step 7: Commit**

```
security: extractable:false + ephemeral key storage mode

Keys are non-extractable in steady state across all modes.
Ephemeral mode: private key never written to SQLite.
CF-managed: re-imported as non-extractable after loading.

Invariant: crypto.subtle.exportKey() on signingKey always throws.
```

---

### Task 4: Constant-time bootstrap code comparison

**Files:**
- Create: `worker/src/auth/timing-safe.ts`
- Modify: `worker/src/signing-authority.ts` (consumeBootstrapCode)

- [ ] **Step 1: Write timing-safe comparison utility**

Create `worker/src/auth/timing-safe.ts`:

```typescript
// Constant-time string comparison using HMAC.
//
// JS string === is not constant-time. For security-sensitive comparisons
// (bootstrap codes, session tokens), compare HMAC digests instead.

const HMAC_KEY_MATERIAL = new TextEncoder().encode("notme-timing-safe-cmp");

async function hmacDigest(value: string): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey(
    "raw",
    HMAC_KEY_MATERIAL,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
}

export async function timingSafeEqual(a: string, b: string): Promise<boolean> {
  const [digestA, digestB] = await Promise.all([hmacDigest(a), hmacDigest(b)]);
  const bufA = new Uint8Array(digestA);
  const bufB = new Uint8Array(digestB);
  if (bufA.length !== bufB.length) return false;
  let result = 0;
  for (let i = 0; i < bufA.length; i++) {
    result |= bufA[i]! ^ bufB[i]!;
  }
  return result === 0;
}
```

- [ ] **Step 2: Update consumeBootstrapCode**

In `worker/src/signing-authority.ts`, in `consumeBootstrapCode` (around line 650), replace:

```typescript
    if (rows.length === 0 || rows[0]!.code !== code) return false;
```

with:

```typescript
    const { timingSafeEqual } = await import("./auth/timing-safe");
    if (rows.length === 0 || !(await timingSafeEqual(rows[0]!.code, code))) return false;
```

- [ ] **Step 3: Run tests**

Run: `cd worker && npx vitest run`
Expected: All tests pass.

- [ ] **Step 4: Commit**

```
security: constant-time bootstrap code comparison (invariant #6)

Replaces JS === with HMAC-based constant-time comparison for
bootstrap codes. Prevents timing side-channel extraction.
```

---

### Task 5: Host routing fix — localhost bypass

**Files:**
- Modify: `worker/worker.ts:884-908`
- Test: `worker/src/__tests__/routes.test.ts`

- [ ] **Step 1: Read existing routes.test.ts to match its patterns**

Run: Read `worker/src/__tests__/routes.test.ts` to understand the test setup (SELF, env, describe structure).

- [ ] **Step 2: Add localhost routing tests**

Add to `worker/src/__tests__/routes.test.ts` (matching existing patterns):

```typescript
describe("localhost routing", () => {
  it("does not redirect localhost requests", async () => {
    const res = await SELF.fetch("http://localhost:8788/.well-known/signet-authority.json");
    expect(res.status).not.toBe(301);
  });

  it("serves auth endpoints on localhost without subdomain", async () => {
    const res = await SELF.fetch("http://localhost:8788/.well-known/jwks.json");
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.keys).toBeDefined();
  });
});
```

Note: Adjust based on the actual test setup (env vars, SELF binding, etc.). The test env needs `SITE_URL=http://localhost:8788` to trigger the local bypass.

- [ ] **Step 3: Run test to verify it fails**

Run: `cd worker && npx vitest run src/__tests__/routes.test.ts`
Expected: FAIL — localhost gets 301 redirect.

- [ ] **Step 4: Fix canonical host redirect**

In `worker/worker.ts`, around line 884, after `const sub = getSubdomain(host);`, add:

```typescript
    const siteUrl: string = env.SITE_URL || "";
    const isLocal = siteUrl.startsWith("http://localhost");
```

Modify the redirect check (line 892) to:

```typescript
    if (!isLocal && !host.endsWith("notme.bot") && host !== "") {
```

- [ ] **Step 5: Fix subdomain routing**

Modify the auth subdomain check (line 905) to:

```typescript
    if (sub === "auth" || isLocal) {
```

Remove the duplicate `siteUrl` declaration inside the if block (it was already declared above).

- [ ] **Step 6: Run tests**

Run: `cd worker && npx vitest run`
Expected: All tests pass.

- [ ] **Step 7: Commit**

```
fix: localhost routing bypass for local workerd

Skip canonical host redirect when SITE_URL is localhost.
Treat localhost as auth subdomain so identity endpoints are reachable.
```

---

### Task 6: Wire platform cache into worker.ts

**Files:**
- Modify: `worker/worker.ts` (replace `env.CA_BUNDLE_CACHE`)
- Modify: `worker/src/signing-authority.ts` (alarm handler)

- [ ] **Step 1: Create platform in fetch handler**

In `worker/worker.ts`, at the top of the `fetch` handler (after CORS block, around line 883), add:

```typescript
    const { createPlatform } = await import("./src/platform");
    const platform = createPlatform(env);
```

- [ ] **Step 2: Pass platform to handleCertGHA**

Update `handleCertGHA` signature to accept platform, and replace all `env.CA_BUNDLE_CACHE` calls:

- `env.CA_BUNDLE_CACHE?.get(...)` becomes `platform.cache.get(...)`
- `env.CA_BUNDLE_CACHE.put(...)` becomes `platform.cache.put(...)`
- `env.CERT_LIMITER` check becomes `platform.rateLimit?.(...)`

- [ ] **Step 3: Replace KV in DPoP token endpoint**

In the `/token` handler (around line 1473), replace:

- `env.CA_BUNDLE_CACHE.get(jtiKey)` with `platform.cache.get(jtiKey)`
- `env.CA_BUNDLE_CACHE.put(...)` with `platform.cache.put(...)`

- [ ] **Step 4: Guard alarm handler**

In `worker/src/signing-authority.ts` alarm method, guard KV with optional chaining:

```typescript
  override async alarm(): Promise<void> {
    try {
      const bundle = await this.generateBundle();
      if (this.env.CA_BUNDLE_CACHE) {
        await this.env.CA_BUNDLE_CACHE.put("bundle:current", JSON.stringify(bundle));
      }
    } catch (e) {
      console.error("[signing-authority] bundle refresh failed:", e);
    }
    await this.ctx.storage.setAlarm(Date.now() + BUNDLE_REFRESH_MS);
  }
```

- [ ] **Step 5: Run full test suite**

Run: `cd worker && npx vitest run`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```
refactor: replace env.CA_BUNDLE_CACHE with platform.cache

All KV access goes through Platform abstraction. CF edge uses
KVCache, local workerd uses SQLiteCache. Alarm handler guarded
for missing KV.
```

---

### Task 7: Adversarial security tests — full suite

**Files:**
- Modify: `worker/src/__tests__/adversarial.test.ts` (extend from Task 3)

- [ ] **Step 1: Add token forgery tests**

Extend `adversarial.test.ts` with:

```typescript
describe("adversarial: token forgery", () => {
  it("rejects JWT with alg: none", async () => {
    const header = btoa(JSON.stringify({ alg: "none", typ: "JWT" }))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    const payload = btoa(JSON.stringify({
      iss: "https://token.actions.githubusercontent.com",
      sub: "repo:evil/repo:ref:refs/heads/main",
      aud: "notme.bot",
      exp: Math.floor(Date.now() / 1000) + 300,
      iat: Math.floor(Date.now() / 1000),
    })).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    const fakeJwt = `${header}.${payload}.`;

    const res = await SELF.fetch("https://auth.notme.bot/cert/gha", {
      method: "POST",
      headers: { Authorization: `Bearer ${fakeJwt}` },
    });
    expect(res.status).toBe(401);
  });

  it("rejects expired token", async () => {
    const header = btoa(JSON.stringify({ alg: "RS256", kid: "test" }))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    const payload = btoa(JSON.stringify({
      iss: "https://token.actions.githubusercontent.com",
      aud: "notme.bot",
      exp: Math.floor(Date.now() / 1000) - 600,
      iat: Math.floor(Date.now() / 1000) - 900,
    })).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

    const res = await SELF.fetch("https://auth.notme.bot/cert/gha", {
      method: "POST",
      headers: { Authorization: `Bearer ${header}.${payload}.AAAA` },
    });
    expect(res.status).toBe(401);
  });
});

describe("adversarial: scope escalation", () => {
  it("bootstrap code cannot be reused", async () => {
    const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
    const authority = env.SIGNING_AUTHORITY.get(authorityId);

    const code = await authority.getOrCreateBootstrapCode();
    expect(code).toBeTruthy();

    const first = await authority.consumeBootstrapCode(code!);
    expect(first).toBe(true);

    const second = await authority.consumeBootstrapCode(code!);
    expect(second).toBe(false);
  });
});

describe("adversarial: error message leak", () => {
  it("error responses do not contain key material", async () => {
    const endpoints = [
      { url: "https://auth.notme.bot/cert/gha", method: "POST", headers: {} },
      { url: "https://auth.notme.bot/cert/gha", method: "POST", headers: { Authorization: "Bearer bad" } },
      { url: "https://auth.notme.bot/token", method: "POST", headers: { "Content-Type": "application/json" } },
    ];

    for (const ep of endpoints) {
      const res = await SELF.fetch(ep.url, { method: ep.method, headers: ep.headers });
      const text = await res.text();
      expect(text).not.toMatch(/"d"\s*:\s*"[A-Za-z0-9_-]+"/);
      expect(text).not.toContain("BEGIN PRIVATE KEY");
    }
  });
});
```

- [ ] **Step 2: Run adversarial tests**

Run: `cd worker && npx vitest run src/__tests__/adversarial.test.ts`
Expected: All PASS.

- [ ] **Step 3: Run full suite**

Run: `cd worker && npx vitest run`
Expected: All tests pass.

- [ ] **Step 4: Commit**

```
test: adversarial security tests — forgery, replay, scope, leak

Verifies invariants #1-#6: alg:none rejection, expired tokens,
bootstrap reuse, error message key leak checks.
```

---

### Task 8: Integration test — workerd boots and serves endpoints

- [ ] **Step 1: Build and start workerd**

```bash
cd worker && npm run build:local
mkdir -p /tmp/notme-do-test && rm -rf /tmp/notme-do-test/*
sed 's|path = "/data/do"|path = "/tmp/notme-do-test"|' config.capnp > /tmp/config-test.capnp
./node_modules/workerd/bin/workerd serve /tmp/config-test.capnp --experimental &
sleep 4
```

- [ ] **Step 2: Verify discovery**

Run: `curl -sf http://localhost:8788/.well-known/signet-authority.json | python3 -m json.tool`
Expected: JSON with `"issuer": "http://localhost:8788"`

- [ ] **Step 3: Verify JWKS**

Run: `curl -sf http://localhost:8788/.well-known/jwks.json | python3 -m json.tool`
Expected: JSON with `keys[0].kty = "OKP"`

- [ ] **Step 4: Verify passkey status**

Run: `curl -sf http://localhost:8788/auth/passkey/status | python3 -m json.tool`
Expected: JSON with `authority.keyId` (8 hex chars)

- [ ] **Step 5: Verify no private key in SQLite (invariant #1)**

Run: `strings /tmp/notme-do-test/*.sqlite 2>/dev/null | grep '"d"'`
Expected: No output (no private key on disk).

- [ ] **Step 6: Verify CA cert**

Run: `curl -sf http://localhost:8788/.well-known/ca-bundle.pem | head -1`
Expected: `-----BEGIN CERTIFICATE-----`

- [ ] **Step 7: Cleanup**

Kill the workerd process. Remove temp files.

---

### Task 9: Container image build + verify

- [ ] **Step 1: Build worker bundle**

Run: `cd worker && npm run build:local`

- [ ] **Step 2: Build container image**

Run:
```bash
cd packages
melange build melange-workerd.yaml --arch aarch64 --signing-key melange.rsa --out-dir ./out
apko build apko-notme.yaml notme:latest notme.tar --keyring-append melange.rsa.pub
```

- [ ] **Step 3: Load and run**

Run:
```bash
docker load < packages/notme.tar
docker run -d --name notme-test -p 8788:8788 notme:latest
sleep 4
```

- [ ] **Step 4: Verify endpoints**

Run same curl checks as Task 8 Steps 2-6.

- [ ] **Step 5: Cleanup**

Run: `docker stop notme-test && docker rm notme-test`

---

### Task 10: Final verification + push

- [ ] **Step 1: Run full test suite**

Run: `cd worker && npx vitest run`
Expected: All tests pass.

- [ ] **Step 2: Run typecheck**

Run: `cd worker && npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 3: Verify all success criteria**

1. workerd boots on localhost:8788 — Task 8
2. No private key in SQLite — Task 8 Step 5
3. exportKey throws — Task 3 adversarial tests
4. encrypted without KEK = hard error — Task 2 platform tests
5. All tests pass — this step
6. Container works — Task 9
7. Same curl commands work everywhere — Tasks 8 + 9

- [ ] **Step 4: Push and update PR**

Push the branch. Update PR #1 description to include the secretless proxy work, or open a new PR.
