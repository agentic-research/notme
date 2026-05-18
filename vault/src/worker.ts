// Credential vault Worker — the HTTP entrypoint.
//
// Wires together:
//   - Identity verification via notme shared SDK
//   - CredentialVault Durable Object for storage
//   - Handler for routing

import { handleRequest } from "./handler";
import { verifyAccessToken, verifyDPoPToken } from "../../gen/ts/dpop";
import type { SealedCredential as _SealedCredential } from "./crypto";
import { validateServiceName } from "./vault";

/**
 * Public RPC surface of the CredentialVault Durable Object.
 *
 * Extracted as a separate interface so `DurableObjectNamespace<T>` doesn't
 * recurse through the class's full type (which references Env, which
 * references VAULT, …). The class implements this interface; the binding
 * uses it as the type parameter.
 *
 * `Rpc.DurableObjectBranded` is the marker CF requires on the parameter
 * — it tags this as a DO RPC type, not a plain interface.
 */
export interface CredentialVaultRpc extends Rpc.DurableObjectBranded {
  getCredential(service: string): Promise<{
    upstream: string;
    headers: Record<string, string>;
    allowedSubs: string[];
  } | null>;
  putCredential(
    service: string,
    cred: { upstream: string; headers: Record<string, string>; allowedSubs: string[] },
  ): Promise<void>;
  deleteCredential(service: string): Promise<boolean>;
  listServices(): Promise<string[]>;
  checkAndStoreJti(jti: string): Promise<boolean>;
  proxyRequest(service: string, incomingRequest: Request): Promise<Response>;
  /**
   * Per-caller token-bucket gate (cloister-211b68 / dos-friend F1).
   * Returns `{ ok: true }` if the request fits the caller's budget,
   * else `{ ok: false, retryAfterSec }` with a conservative ceiling
   * derived from the bucket's refill rate.
   */
  consumeBudget(sub: string, costClass: "read" | "write" | "proxy"): Promise<
    { ok: true } | { ok: false; retryAfterSec: number }
  >;
}

export interface Env {
  VAULT: DurableObjectNamespace<CredentialVaultRpc>;
  ADMIN_SUB: string;
  /**
   * URL spec for the pluggable KEK source.
   *   env://NAME            — read the named env binding (plaintext)
   *   file:///path          — read via the KEK_DISK workerd disk service
   *   keychain://name       — macOS Keychain via the KEK_HELPER sidecar
   *   http(s)://host/...    — any HTTP backend via KEK_HELPER
   * See `src/kek-source.ts` for the resolver. If unset, vault falls
   * back to the legacy `VAULT_KEK_SECRET` env binding with a one-time
   * deprecation warning at boot — keeps existing deployments working
   * during the rollout.
   */
  VAULT_KEK_SOURCE?: string;
  /**
   * Legacy plaintext KEK secret. DEPRECATED — set `VAULT_KEK_SOURCE`
   * instead (e.g. `env://VAULT_KEK_SECRET` is a one-line equivalent).
   * Kept so the lift PR (#19) doesn't force every deployment to update
   * its wrangler config on the same day.
   */
  VAULT_KEK_SECRET?: string;
  /**
   * Vault's own URL — used as the expected `aud` claim on incoming
   * access tokens. Resource servers MUST validate audience to prevent
   * confused-deputy: a token minted for rosary.bot would otherwise be
   * accepted by vault since both share notme's signing key.
   */
  VAULT_AUDIENCE: string;
}

/**
 * Compile-time structural assertion that the runtime class
 * `CredentialVault` matches the RPC surface declared in
 * `CredentialVaultRpc`. We can't use `class … implements
 * CredentialVaultRpc` because the interface extends
 * `Rpc.DurableObjectBranded` whose private brand symbol is only
 * assigned by the runtime DurableObject base class. So this assertion
 * picks ONLY the named methods (no brand) on both sides and checks
 * structural equality both ways: one direction catches "RPC has a
 * method the class missed" (would break callers); the reverse catches
 * "class has a method whose signature is wider/narrower than the RPC"
 * (would let drift compile silently). If either direction fails, tsc
 * fails.
 *
 * Closes notme-aed3a0 (M4 from session code review).
 */
type _RpcMethodNames =
  | "getCredential"
  | "putCredential"
  | "deleteCredential"
  | "listServices"
  | "checkAndStoreJti"
  | "proxyRequest"
  | "consumeBudget";

type _AssertSameKeys<A, B> = keyof A extends keyof B
  ? keyof B extends keyof A
    ? true
    : never
  : never;

// Each direction: the class's method types must match the RPC's
// method types. `Pick` strips the brand from the RPC side. Two
// assignment-checks together catch both narrowing and widening.
const _classMatchesRpc: Pick<CredentialVaultRpc, _RpcMethodNames> =
  null as unknown as Pick<CredentialVault, _RpcMethodNames>;
const _rpcMatchesClass: Pick<CredentialVault, _RpcMethodNames> =
  null as unknown as Pick<CredentialVaultRpc, _RpcMethodNames>;
const _keysAssertion: _AssertSameKeys<
  Pick<CredentialVaultRpc, _RpcMethodNames>,
  Pick<CredentialVault, _RpcMethodNames>
> = true;
// References to silence "declared but never read" (these are
// type-only assertions; tsc errors come from the assignments above).
void _classMatchesRpc;
void _rpcMatchesClass;
void _keysAssertion;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const vaultId = env.VAULT.idFromName("default");
    const vault = env.VAULT.get(vaultId);

    // Step 1: cheap sync validation BEFORE any crypto work.
    // Rejects obviously-invalid paths (bad service names, unknown routes)
    // without forcing JWT verification + DPoP replay RPC on garbage
    // traffic. Mirrors what handleRequest validates synchronously today
    // — handleRequest's own checks still run, this is just an early gate
    // so a flood of /../../etc/passwd or /garbage doesn't force sig work.
    const earlyReject = preValidateRoute(request);
    if (earlyReject) return earlyReject;

    // Step 2: identity resolution (expensive — JWT verify + DPoP replay
    // RPC). Resolved ONCE here so we can charge the rate bucket and
    // hand the cached value to the handler. Anonymous (null) requests
    // get a 401 via the handler without consuming budget — pre-auth
    // DoS is CF's job.
    const sub = await resolveIdentity(request, env, vault);

    // Step 3: rate-bucket charge (DO RPC). Only authenticated callers
    // are budgeted — anonymous traffic short-circuits to handler's 401.
    if (sub) {
      const gate = await vault.consumeBudget(sub, costClassFor(request));
      if (!gate.ok) {
        return new Response(
          JSON.stringify({ error: "rate_limited" }),
          {
            status: 429,
            headers: {
              "Content-Type": "application/json",
              "Retry-After": String(gate.retryAfterSec),
            },
          },
        );
      }
    }

    // Step 4: delegate to handler (which can now trust the route +
    // identity + budget).
    return handleRequest({
      request,
      storage: {
        async get(service) {
          const row = await vault.getCredential(service);
          return row ?? null;
        },
        async put(service, cred) {
          await vault.putCredential(service, cred);
        },
        async delete(service) {
          return vault.deleteCredential(service);
        },
        async list() {
          return vault.listServices();
        },
      },
      resolveIdentity: async () => sub,
      adminSub: env.ADMIN_SUB || "",
      // Proxy via DO — credentials decrypted INSIDE the DO, never cross RPC.
      proxyViaVault: async (service, req) => vault.proxyRequest(service, req),
    });
  },
};

// ── Identity resolution ────────────────────────────────────────────────────
//
// Extracted from the worker.fetch body so it can run BEFORE handleRequest
// — the rate bucket needs the caller's sub to charge the right bucket,
// and the handler needs the same value. We pass it via a no-arg closure
// to handleRequest so it doesn't re-do JWT verification.

async function resolveIdentity(
  req: Request,
  env: Env,
  vault: CredentialVaultRpc,
): Promise<string | null> {
  const authHeader = req.headers.get("Authorization");
  const dpopHeader = req.headers.get("DPoP");
  const token = authHeader?.startsWith("DPoP ") ? authHeader.slice(5) : null;

  if (token && dpopHeader) {
    try {
      const claims = await verifyDPoPToken({
        token,
        proof: dpopHeader,
        method: req.method,
        url: req.url,
        jwksUrl: "https://auth.notme.bot/.well-known/jwks.json",
      });
      // JTI replay check — DO tracks seen proofs for 120s
      const replayed = await vault.checkAndStoreJti(claims.jti);
      if (replayed) return null;
      return claims.sub;
    } catch {
      return null;
    }
  }

  // Try access token only (redirect flow or simple bearer)
  if (token || authHeader?.startsWith("Bearer ")) {
    const accessToken = token || authHeader!.slice(7);
    try {
      const claims = await verifyAccessToken({
        token: accessToken,
        jwksUrl: "https://auth.notme.bot/.well-known/jwks.json",
        // Audience pin — rejects tokens minted for a different
        // resource server (rosary.bot, mache.rosary.bot, etc.) so
        // a stolen-from-elsewhere token can't be replayed at vault.
        audience: env.VAULT_AUDIENCE,
      });
      return claims.sub;
    } catch {
      return null;
    }
  }

  return null;
}

/**
 * Map a request to its rate-bucket cost class. PUT pays the `write`
 * cost (encrypt + SQL write), DELETE and /admin/services are `read`,
 * and everything else routes to the upstream and pays the `proxy` cost
 * (encrypt + SQL read + upstream fetch).
 */
function costClassFor(req: Request): "read" | "write" | "proxy" {
  if (req.method === "PUT") return "write";
  if (req.method === "DELETE") return "read";
  const path = new URL(req.url).pathname;
  if (path === "/admin/services") return "read";
  return "proxy";
}

/**
 * Cheap sync route validation, run BEFORE identity resolution so an
 * attacker hitting `/../../etc/passwd` or `/garbage-path` can't force
 * JWT verification + DPoP replay RPC for nothing. Returns an error
 * Response on reject, or `null` to let the request proceed to identity
 * resolution.
 *
 * The checks mirror what `handleRequest()` validates synchronously
 * today — keeping them here is just a hoist, not a replacement. The
 * handler still does its own validation; this gate exists so the
 * expensive work doesn't happen for obviously-bad requests.
 *
 * Allowed shapes:
 *   - GET /admin/services           (admin route, identity required later)
 *   - GET|PUT|DELETE|...  /:service (service name passes validateServiceName)
 *
 * Exported for direct unit testing — caller is just `worker.fetch`.
 */
export function preValidateRoute(req: Request): Response | null {
  const path = new URL(req.url).pathname;
  if (path === "/admin/services") return null;
  // Extract candidate service segment — same split handleRequest uses.
  const service = path.split("/")[1] || "";
  if (!service || !validateServiceName(service)) {
    return Response.json({ error: "invalid service name" }, { status: 400 });
  }
  return null;
}

// ── Durable Object: CredentialVault ─────────────────────────────────────────
//
// The DO is the security kernel. It:
//   1. Resolves the KEK via the url-driven kek-source (env://, file://,
//      keychain://, http(s)://) — falls back to legacy VAULT_KEK_SECRET
//      with a deprecation warning. Non-extractable in Web Crypto.
//   2. Encrypts credential headers before writing to SQLite
//   3. Decrypts only when proxying (plaintext never crosses RPC)
//   4. Performs the upstream fetch itself — plaintext headers stay in DO memory
//   5. Gates every authenticated request through a per-caller token bucket
//      (consumeBudget) so a noisy caller can't starve neighbours.
//
// The Worker is just a routing/auth shell. It never sees decrypted credentials.

import { deriveKEK, encrypt, decrypt, type SealedCredential } from "./crypto";
import { buildProxyRequest, sanitizeResponse } from "./vault";
import { buildKekSource } from "./kek-source";
import { RATE_LIMITS, refillBucket, tryConsume, type BucketState } from "./rate-bucket";

/**
 * Hard cap on the per-caller bucket map (LRU eviction). Without a cap,
 * a stream of unique `sub` values (each one populating a new Map entry)
 * would grow DO memory without bound — a slow-DoS vector against the
 * single-writer DO instance. Evicting the oldest entry on overflow is
 * a safe heuristic because the bucket math is already idempotent in
 * the loss case: an evicted caller gets a full bucket on their next
 * request, which is the same outcome a long-idle caller sees naturally.
 *
 * 10k is generously large for any plausible legitimate workload — a
 * vault DO that genuinely sees 10k distinct authenticated callers in
 * its uptime window is well past the point where per-caller buckets
 * in DO memory are the right shape.
 */
const BUCKET_CAP = 10_000;

interface StoredRow {
  upstream: string;
  sealed_headers: string;  // JSON-serialized SealedCredential
  allowed_subs_json: string;
}

// DurableObject base class provides this.ctx and this.env automatically.
// Using the type annotation for documentation — actual base class import
// requires cloudflare:workers which is only available at runtime.
//
// We deliberately do NOT add `implements CredentialVaultRpc` here. The
// interface extends `Rpc.DurableObjectBranded`, whose private brand
// (`[__DURABLE_OBJECT_BRAND]`) is only assigned by the runtime DurableObject
// base class. Without importing `cloudflare:workers` (which we avoid here
// so vault tests don't load the workerd-only module), the brand can't be
// declared — `implements` would force a class shape we can't satisfy at
// the type level. The binding `DurableObjectNamespace<CredentialVaultRpc>`
// still picks up method types correctly via structural matching.
export class CredentialVault {
  private sql: any;
  private kekPromise: Promise<CryptoKey> | null = null;
  /**
   * Per-caller token-bucket state, keyed by `sub`. Lives in DO memory
   * (single-writer per DO instance) — persistence isn't needed because
   * the bucket auto-refills from a stale `lastRefillMs` on the next
   * consume attempt. If the DO is evicted, callers get a full bucket
   * on their next request, which is the same outcome a long-idle
   * caller would see anyway.
   */
  private readonly buckets = new Map<string, BucketState>();

  constructor(private ctx: any, private env: Env) {
    this.sql = ctx.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS credentials (
        service TEXT PRIMARY KEY,
        upstream TEXT NOT NULL,
        sealed_headers TEXT NOT NULL,
        allowed_subs_json TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
      )
    `);
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS seen_jti (
        jti TEXT PRIMARY KEY,
        expires_at INTEGER NOT NULL
      )
    `);
  }

  /**
   * Check if a DPoP proof JTI has been seen. If not, store it with 120s expiry.
   * Returns true if this is a replay (already seen), false if fresh.
   * Purges expired entries on each call.
   */
  async checkAndStoreJti(jti: string): Promise<boolean> {
    const now = Math.floor(Date.now() / 1000);
    // Purge expired entries
    this.sql.exec("DELETE FROM seen_jti WHERE expires_at < ?", now);
    // Check if seen
    const rows = this.sql.exec("SELECT 1 FROM seen_jti WHERE jti = ?", jti).toArray();
    if (rows.length > 0) return true; // replay
    // Store with 120s TTL (2x the 60s iat window — safety margin)
    this.sql.exec("INSERT INTO seen_jti (jti, expires_at) VALUES (?, ?)", jti, now + 120);
    return false;
  }

  /**
   * Lazy KEK derivation — resolved once per DO lifetime, cached. The KEK
   * itself comes from the URL-driven kek-source resolver
   * (`env://`, `file://`, `keychain://`, `http(s)://`). If
   * `VAULT_KEK_SOURCE` is unset, falls back to the legacy plaintext
   * `VAULT_KEK_SECRET` env binding with a one-time deprecation warning.
   * On resolver failure the cached promise is cleared so the next call
   * retries instead of permanently poisoning the DO's KEK slot.
   */
  #getKEK(): Promise<CryptoKey> {
    if (!this.kekPromise) {
      this.kekPromise = this.#resolveAndDeriveKEK().catch((err) => {
        this.kekPromise = null;
        throw err;
      });
    }
    return this.kekPromise;
  }

  async #resolveAndDeriveKEK(): Promise<CryptoKey> {
    const spec = this.env.VAULT_KEK_SOURCE;
    if (spec && spec.length > 0) {
      const secret = await buildKekSource(
        spec,
        this.env as unknown as Record<string, unknown>,
      ).resolve();
      return deriveKEK(secret);
    }
    // Legacy path — kept so the lift PR doesn't force every deployment
    // to update its wrangler config on the same day. Removed once all
    // deployments set VAULT_KEK_SOURCE.
    const legacy = this.env.VAULT_KEK_SECRET;
    if (!legacy) {
      throw new Error(
        "vault: no KEK source configured — set VAULT_KEK_SOURCE (preferred) or VAULT_KEK_SECRET",
      );
    }
    console.warn(
      "vault: VAULT_KEK_SECRET is deprecated; set VAULT_KEK_SOURCE=env://VAULT_KEK_SECRET (or another scheme) instead",
    );
    return deriveKEK(legacy);
  }

  /**
   * Per-caller token-bucket gate (cloister-211b68 / dos-friend F1).
   * Looks up the caller's bucket, refills based on wall-clock elapsed,
   * and attempts to consume the cost for `costClass`. Rejected callers
   * get a `retryAfterSec` derived from the bucket's refill rate; the
   * `lastRefillMs` is persisted on reject too so a depleted attacker
   * can't freeze time.
   *
   * Map access uses delete-then-set so iteration order ≡ recency
   * (LRU). When the map exceeds `BUCKET_CAP`, the oldest entry is
   * evicted — bounds DO memory against a flood of unique `sub` values
   * (notme-PR#22 / Copilot review).
   */
  async consumeBudget(
    sub: string,
    costClass: "read" | "write" | "proxy",
  ): Promise<{ ok: true } | { ok: false; retryAfterSec: number }> {
    const cost = RATE_LIMITS.COST[costClass];
    const prev = this.buckets.get(sub) ?? null;
    const refilled = refillBucket(prev, Date.now());
    const result = tryConsume(refilled, cost);
    // Delete-then-set bumps this `sub` to the tail of Map's insertion
    // order — that ordering is what makes `.keys().next()` give us
    // the LRU entry on overflow below.
    this.buckets.delete(sub);
    this.buckets.set(sub, result.next);
    if (this.buckets.size > BUCKET_CAP) {
      const oldest = this.buckets.keys().next().value;
      if (oldest !== undefined) this.buckets.delete(oldest);
    }
    if (result.ok) return { ok: true };
    return { ok: false, retryAfterSec: result.retryAfterSec };
  }

  /** Get credential metadata (upstream, scopes) WITHOUT decrypting headers. */
  async getCredential(service: string) {
    const rows = this.sql.exec(
      "SELECT upstream, sealed_headers, allowed_subs_json FROM credentials WHERE service = ?",
      service,
    ).toArray();
    if (!rows.length) return null;
    const row = rows[0] as StoredRow;
    return {
      upstream: row.upstream,
      // Return a stub — headers are encrypted, not returned to Worker
      headers: {} as Record<string, string>,
      allowedSubs: JSON.parse(row.allowed_subs_json),
    };
  }

  /** Store a credential — headers are encrypted before writing to SQLite. */
  async putCredential(service: string, cred: { upstream: string; headers: Record<string, string>; allowedSubs: string[] }) {
    const kek = await this.#getKEK();
    const sealed = await encrypt(cred.headers, kek);

    this.sql.exec(
      `INSERT INTO credentials (service, upstream, sealed_headers, allowed_subs_json)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(service) DO UPDATE SET
         upstream = excluded.upstream,
         sealed_headers = excluded.sealed_headers,
         allowed_subs_json = excluded.allowed_subs_json,
         updated_at = datetime('now')`,
      service,
      cred.upstream,
      JSON.stringify(sealed),
      JSON.stringify(cred.allowedSubs),
    );
  }

  async deleteCredential(service: string): Promise<boolean> {
    const result = this.sql.exec("DELETE FROM credentials WHERE service = ?", service);
    return result.rowsWritten > 0;
  }

  async listServices(): Promise<string[]> {
    return this.sql.exec("SELECT service FROM credentials ORDER BY service")
      .toArray()
      .map((r: { service: string }) => r.service);
  }

  /**
   * Proxy a request to the upstream service.
   * Decrypts credential headers INSIDE the DO, builds the proxy request,
   * performs the fetch, sanitizes the response. Plaintext headers never
   * leave this DO's memory.
   */
  async proxyRequest(service: string, incomingRequest: Request): Promise<Response> {
    const rows = this.sql.exec(
      "SELECT upstream, sealed_headers, allowed_subs_json FROM credentials WHERE service = ?",
      service,
    ).toArray();
    if (!rows.length) return Response.json({ error: "not_found" }, { status: 404 });

    const row = rows[0] as StoredRow;
    const kek = await this.#getKEK();
    const sealed = JSON.parse(row.sealed_headers) as SealedCredential;
    const headers = await decrypt(sealed, kek);

    const cred = {
      upstream: row.upstream,
      headers,
      allowedSubs: JSON.parse(row.allowed_subs_json),
    };

    const proxyReq = buildProxyRequest(incomingRequest, cred);
    const upstream = await fetch(proxyReq);
    return sanitizeResponse(upstream);
  }

  async fetch(_request: Request): Promise<Response> {
    return new Response("Use RPC methods, not fetch", { status: 500 });
  }
}
