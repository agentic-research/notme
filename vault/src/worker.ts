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
    });
  },
};

// ── Durable Object: CredentialVault ─────────────────────────────────────────

interface StoredRow {
  upstream: string;
  headers_json: string;
  allowed_subs_json: string;
}

export class CredentialVault {
  private sql: any;

  constructor(private ctx: DurableObjectState) {
    this.sql = ctx.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS credentials (
        service TEXT PRIMARY KEY,
        upstream TEXT NOT NULL,
        headers_json TEXT NOT NULL,
        allowed_subs_json TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
      )
    `);
  }

  async getCredential(service: string) {
    const rows = this.sql.exec(
      "SELECT upstream, headers_json, allowed_subs_json FROM credentials WHERE service = ?",
      service,
    ).toArray();
    if (!rows.length) return null;
    const row = rows[0] as StoredRow;
    return {
      upstream: row.upstream,
      headers: JSON.parse(row.headers_json),
      allowedSubs: JSON.parse(row.allowed_subs_json),
    };
  }

  async putCredential(service: string, cred: { upstream: string; headers: Record<string, string>; allowedSubs: string[] }) {
    this.sql.exec(
      `INSERT INTO credentials (service, upstream, headers_json, allowed_subs_json)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(service) DO UPDATE SET
         upstream = excluded.upstream,
         headers_json = excluded.headers_json,
         allowed_subs_json = excluded.allowed_subs_json,
         updated_at = datetime('now')`,
      service,
      cred.upstream,
      JSON.stringify(cred.headers),
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

  async fetch(request: Request): Promise<Response> {
    return new Response("DO internal only", { status: 500 });
  }
}
