// Credential vault Worker — the HTTP entrypoint.
//
// Wires together:
//   - Identity verification via notme shared SDK
//   - CredentialVault Durable Object for storage
//   - Handler for routing

import { handleRequest } from "./handler";
import { verifyAccessToken, verifyDPoPToken } from "../../gen/ts/dpop";

export interface Env {
  VAULT: DurableObjectNamespace;
  ADMIN_SUB: string;
  /** Secret string used to derive the KEK for credential encryption. */
  VAULT_KEK_SECRET: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const vaultId = env.VAULT.idFromName("default");
    const vault = env.VAULT.get(vaultId);

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
      resolveIdentity: async (req) => {
        // Try DPoP token (Authorization: DPoP <token> + DPoP header)
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
            });
            return claims.sub;
          } catch {
            return null;
          }
        }

        return null;
      },
      adminSub: env.ADMIN_SUB || "",
      // Proxy via DO — credentials decrypted INSIDE the DO, never cross RPC.
      proxyViaVault: async (service, req) => vault.proxyRequest(service, req),
    });
  },
};

// ── Durable Object: CredentialVault ─────────────────────────────────────────
//
// The DO is the security kernel. It:
//   1. Derives the KEK from this.env.VAULT_KEK_SECRET (non-extractable)
//   2. Encrypts credential headers before writing to SQLite
//   3. Decrypts only when proxying (plaintext never crosses RPC)
//   4. Performs the upstream fetch itself — plaintext headers stay in DO memory
//
// The Worker is just a routing/auth shell. It never sees decrypted credentials.

import { deriveKEK, encrypt, decrypt, type SealedCredential } from "./crypto";
import { buildProxyRequest, sanitizeResponse } from "./vault";

interface StoredRow {
  upstream: string;
  sealed_headers: string;  // JSON-serialized SealedCredential
  allowed_subs_json: string;
}

// DurableObject base class provides this.ctx and this.env automatically.
// Using the type annotation for documentation — actual base class import
// requires cloudflare:workers which is only available at runtime.
export class CredentialVault {
  private sql: any;
  private kekPromise: Promise<CryptoKey> | null = null;

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

  /** Lazy KEK derivation — derived once per DO lifetime, cached. */
  #getKEK(): Promise<CryptoKey> {
    if (!this.kekPromise) {
      this.kekPromise = deriveKEK(this.env.VAULT_KEK_SECRET);
    }
    return this.kekPromise;
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
