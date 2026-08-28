// Principal model — stable identity independent of credentials.
//
// A principal is a UUID that survives credential rotation, device
// migration, and identity provider changes. It has:
//   - 0+ passkey credentials
//   - 0+ federated identities (OIDC)
//   - capability grants (what cert scopes it can request)
//
// NOTE: sql.exec() below is SQLite's query method on the Durable Object,
// NOT child_process.exec(). This is safe — all parameters are bound, not interpolated.

import { verifyScopeChain } from "./scope-chain";

export interface Principal {
  principalId: string;
  displayName?: string;
  createdAt: string;
  createdBy?: string;
  status: string;
}

export interface CapabilityGrant {
  scope: string;
  grantedBy?: string;
  grantedAt: string;
  expiresAt?: string;
}

export interface FederatedIdentity {
  provider: string;
  providerSub: string;
  providerEmail?: string;
  connectedAt: string;
}

export interface Invite {
  token: string;
  createdBy: string;
  scopes: string[];
  expiresAt: string;
  redeemedAt?: string;
}

export function ensurePrincipalSchema(sql: any): void {
  sql.exec(`
    CREATE TABLE IF NOT EXISTS principals (
      principal_id TEXT PRIMARY KEY,
      display_name TEXT,
      created_at   TEXT NOT NULL DEFAULT (datetime('now')),
      created_by   TEXT,
      status       TEXT NOT NULL DEFAULT 'active'
    )
  `);
  sql.exec(`
    CREATE TABLE IF NOT EXISTS capability_grants (
      id           TEXT PRIMARY KEY,
      principal_id TEXT NOT NULL,
      scope        TEXT NOT NULL,
      granted_by   TEXT,
      granted_at   TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at   TEXT,
      revoked_at   TEXT,
      revoked_by   TEXT,
      UNIQUE(principal_id, scope)
    )
  `);
  // Existing authorities predate revoked_by. SQLite has no ADD COLUMN IF NOT
  // EXISTS; the duplicate-column error is the "already migrated" signal.
  try {
    sql.exec("ALTER TABLE capability_grants ADD COLUMN revoked_by TEXT");
  } catch {
    /* column exists */
  }
  sql.exec(`
    CREATE TABLE IF NOT EXISTS federated_identities (
      id            TEXT PRIMARY KEY,
      principal_id  TEXT NOT NULL,
      provider      TEXT NOT NULL,
      provider_sub  TEXT NOT NULL,
      provider_email TEXT,
      connected_at  TEXT NOT NULL DEFAULT (datetime('now')),
      last_used_at  TEXT,
      UNIQUE(provider, provider_sub)
    )
  `);
  sql.exec(`
    CREATE TABLE IF NOT EXISTS invites (
      token       TEXT PRIMARY KEY,
      created_by  TEXT NOT NULL,
      scopes      TEXT NOT NULL,
      redeemed_by TEXT,
      created_at  TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at  TEXT NOT NULL,
      redeemed_at TEXT
    )
  `);
}

// ── Principal CRUD ──

export function createPrincipal(
  sql: any, principalId: string, displayName?: string, createdBy?: string,
): void {
  ensurePrincipalSchema(sql);
  sql.exec(
    "INSERT INTO principals (principal_id, display_name, created_by) VALUES (?, ?, ?)",
    principalId, displayName ?? null, createdBy ?? null,
  );
}

export function getPrincipal(sql: any, principalId: string): Principal | null {
  ensurePrincipalSchema(sql);
  const rows = sql.exec(
    "SELECT principal_id, display_name, created_at, created_by, status FROM principals WHERE principal_id = ?",
    principalId,
  ).toArray() as Array<{
    principal_id: string;
    display_name: string | null;
    created_at: string;
    created_by: string | null;
    status: string;
  }>;
  if (rows.length === 0) return null;
  const r = rows[0]!;
  return {
    principalId: r.principal_id,
    displayName: r.display_name ?? undefined,
    createdAt: r.created_at,
    createdBy: r.created_by ?? undefined,
    status: r.status,
  };
}

export function principalCount(sql: any): number {
  ensurePrincipalSchema(sql);
  const rows = sql.exec("SELECT COUNT(*) as c FROM principals").toArray() as Array<{ c: number }>;
  return rows[0]?.c ?? 0;
}

// ── Capabilities ──

export function grantCapability(
  sql: any, principalId: string, scope: string, grantedBy?: string, expiresAt?: string,
): void {
  ensurePrincipalSchema(sql);
  const id = crypto.randomUUID();
  sql.exec(
    "INSERT OR REPLACE INTO capability_grants (id, principal_id, scope, granted_by, expires_at) VALUES (?, ?, ?, ?, ?)",
    id, principalId, scope, grantedBy ?? null, expiresAt ?? null,
  );
}

/**
 * Revoke one grant. The grant is the revocation UNIT (notme-77a024, ADR-019
 * D3): finer than rotation, which voids every credential ever issued, and a
 * decision rather than expiry, which is automatic. Returns whether a LIVE
 * grant was revoked — idempotent, and honest about no-ops so an operator
 * revoking the wrong scope is told, not reassured.
 */
export function revokeCapability(
  sql: any, principalId: string, scope: string, revokedBy?: string,
): { revoked: boolean } {
  ensurePrincipalSchema(sql);
  const before = sql.exec(
    "SELECT COUNT(*) AS c FROM capability_grants WHERE principal_id = ? AND scope = ? AND revoked_at IS NULL",
    principalId, scope,
  ).toArray() as Array<{ c: number }>;
  if ((before[0]?.c ?? 0) === 0) return { revoked: false };
  sql.exec(
    "UPDATE capability_grants SET revoked_at = datetime('now'), revoked_by = ? WHERE principal_id = ? AND scope = ? AND revoked_at IS NULL",
    revokedBy ?? null, principalId, scope,
  );
  return { revoked: true };
}

export interface Grant {
  id: string;
  principalId: string;
  scope: string;
  grantedBy: string | null;
  grantedAt: string;
  expiresAt: string | null;
  revokedAt: string | null;
  revokedBy: string | null;
}

/** Every grant ever made to a principal, revoked ones included — the audit view. */
export function listGrants(sql: any, principalId: string): Grant[] {
  ensurePrincipalSchema(sql);
  const rows = sql.exec(
    "SELECT id, principal_id, scope, granted_by, granted_at, expires_at, revoked_at, revoked_by FROM capability_grants WHERE principal_id = ? ORDER BY granted_at",
    principalId,
  ).toArray() as Array<Record<string, string | null>>;
  return rows.map((r) => ({
    id: r.id!,
    principalId: r.principal_id!,
    scope: r.scope!,
    grantedBy: r.granted_by ?? null,
    grantedAt: r.granted_at!,
    expiresAt: r.expires_at ?? null,
    revokedAt: r.revoked_at ?? null,
    revokedBy: r.revoked_by ?? null,
  }));
}

export function getCapabilities(sql: any, principalId: string): string[] {
  ensurePrincipalSchema(sql);
  const rows = sql.exec(
    "SELECT scope FROM capability_grants WHERE principal_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > datetime('now'))",
    principalId,
  ).toArray() as Array<{ scope: string }>;
  return rows.map((r) => r.scope);
}

export function canGrant(grantorScopes: string[], scope: string): boolean {
  // Two separate requirements: authorityManage says the grantor may grant AT
  // ALL; the chain rule says a grant may only carry what the grantor holds.
  // The second is ADR-008's subset rule, so it goes through the same function
  // every other narrowing site uses rather than a private includes() —
  // one predicate, one place to get it wrong (notme-acc822).
  return (
    grantorScopes.includes("authorityManage") &&
    verifyScopeChain(grantorScopes, [scope])
  );
}

// ── Federated Identities ──

export function linkFederatedIdentity(
  sql: any, principalId: string, provider: string, providerSub: string, providerEmail?: string,
): void {
  ensurePrincipalSchema(sql);
  const id = crypto.randomUUID();
  sql.exec(
    "INSERT OR REPLACE INTO federated_identities (id, principal_id, provider, provider_sub, provider_email) VALUES (?, ?, ?, ?, ?)",
    id, principalId, provider, providerSub, providerEmail ?? null,
  );
}

export function findPrincipalByFederated(
  sql: any, provider: string, providerSub: string,
): string | null {
  ensurePrincipalSchema(sql);
  const rows = sql.exec(
    "SELECT principal_id FROM federated_identities WHERE provider = ? AND provider_sub = ?",
    provider, providerSub,
  ).toArray() as Array<{ principal_id: string }>;
  return rows.length > 0 ? rows[0].principal_id : null;
}

export function getFederatedIdentities(sql: any, principalId: string): FederatedIdentity[] {
  ensurePrincipalSchema(sql);
  const rows = sql.exec(
    "SELECT provider, provider_sub, provider_email, connected_at FROM federated_identities WHERE principal_id = ?",
    principalId,
  ).toArray() as Array<{
    provider: string;
    provider_sub: string;
    provider_email: string | null;
    connected_at: string;
  }>;
  return rows.map((r) => ({
    provider: r.provider,
    providerSub: r.provider_sub,
    providerEmail: r.provider_email ?? undefined,
    connectedAt: r.connected_at,
  }));
}

// ── Invites ──

const INVITE_DEFAULT_TTL_SECONDS = 3600;

export function createInvite(
  sql: any, createdBy: string, scopes: string[], ttlSeconds = INVITE_DEFAULT_TTL_SECONDS,
): Invite {
  ensurePrincipalSchema(sql);
  const token = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
  sql.exec(
    "INSERT INTO invites (token, created_by, scopes, expires_at) VALUES (?, ?, ?, ?)",
    token, createdBy, JSON.stringify(scopes), expiresAt,
  );
  return { token, createdBy, scopes, expiresAt };
}

export function redeemInvite(sql: any, token: string, redeemedBy: string): { scopes: string[] } | null {
  ensurePrincipalSchema(sql);
  const rows = sql.exec(
    "SELECT scopes, expires_at, redeemed_at FROM invites WHERE token = ?", token,
  ).toArray() as Array<{ scopes: string; expires_at: string; redeemed_at: string | null }>;

  if (rows.length === 0) return null;
  const invite = rows[0];
  if (invite.redeemed_at) return null;
  if (new Date(invite.expires_at) < new Date()) return null;

  sql.exec(
    "UPDATE invites SET redeemed_by = ?, redeemed_at = datetime('now') WHERE token = ?",
    redeemedBy, token,
  );
  return { scopes: JSON.parse(invite.scopes) };
}
