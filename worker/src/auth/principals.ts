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
  // APPEND-ONLY HISTORY, ONE LIVE GRANT PER SCOPE (ADR-019 D3).
  //
  // This table used to declare `UNIQUE(principal_id, scope)` across ALL rows,
  // and `grantCapability` wrote `INSERT OR REPLACE`. Re-granting a scope then
  // destroyed two things: the `revoked_at`/`revoked_by` of the row it
  // replaced — so a deliberate revocation vanished from the record that
  // `listGrants` advertises as "the audit view" — and the grant's `id`, since
  // each call generates a fresh one. An identifier that moves cannot be
  // REFERENCED, which is what blocked a credential naming the grant that
  // authorized it.
  //
  // The invariant worth keeping is "at most one LIVE grant per scope", not
  // "one row ever". A partial unique index says exactly that and lets
  // revoked rows accumulate as history.
  sql.exec(`
    CREATE TABLE IF NOT EXISTS capability_grants (
      id           TEXT PRIMARY KEY,
      principal_id TEXT NOT NULL,
      scope        TEXT NOT NULL,
      granted_by   TEXT,
      granted_at   TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at   TEXT,
      revoked_at   TEXT,
      revoked_by   TEXT
    )
  `);
  // Migration: rebuild a table carrying the old all-rows UNIQUE.
  //
  // A table-level constraint cannot be dropped in SQLite, so the shape has to
  // be detected and the table rewritten. sqlite_master holds the original
  // CREATE text, which is the only honest place to ask. Existing rows carry
  // at most one grant per (principal, scope) by construction, so the copy
  // cannot violate the new partial index.
  const grantsDdl = (
    sql
      .exec(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'capability_grants'",
      )
      .toArray() as Array<{ sql: string | null }>
  )[0]?.sql;
  if (grantsDdl && grantsDdl.includes("UNIQUE(principal_id, scope)")) {
    sql.exec(`
      CREATE TABLE capability_grants_v2 (
        id           TEXT PRIMARY KEY,
        principal_id TEXT NOT NULL,
        scope        TEXT NOT NULL,
        granted_by   TEXT,
        granted_at   TEXT NOT NULL DEFAULT (datetime('now')),
        expires_at   TEXT,
        revoked_at   TEXT,
        revoked_by   TEXT
      )
    `);
    sql.exec(
      "INSERT INTO capability_grants_v2 (id, principal_id, scope, granted_by, granted_at, expires_at, revoked_at, revoked_by) " +
        "SELECT id, principal_id, scope, granted_by, granted_at, expires_at, revoked_at, revoked_by FROM capability_grants",
    );
    sql.exec("DROP TABLE capability_grants");
    sql.exec("ALTER TABLE capability_grants_v2 RENAME TO capability_grants");
  }
  sql.exec(
    "CREATE UNIQUE INDEX IF NOT EXISTS capability_grants_one_live " +
      "ON capability_grants (principal_id, scope) WHERE revoked_at IS NULL",
  );
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
  // notme-3dfe15: one row per in-flight passkey registration started under an
  // invite. Never a grant by itself — see reserveInvite.
  //
  // secret_hash: SHA-256 (hex) of the reservation secret held ONLY in the
  // reserving browser's HttpOnly cookie. Consumption requires it, so knowing
  // the userId and challenge is not enough to finish someone else's
  // ceremony. A row without one ('' — a pre-column row) can never be consumed.
  sql.exec(`
    CREATE TABLE IF NOT EXISTS invite_reservations (
      user_id     TEXT PRIMARY KEY,
      token       TEXT NOT NULL,
      expires_at  INTEGER NOT NULL,
      secret_hash TEXT NOT NULL DEFAULT ''
    )
  `);
  try {
    sql.exec("ALTER TABLE invite_reservations ADD COLUMN secret_hash TEXT NOT NULL DEFAULT ''");
  } catch {
    /* column exists */
  }
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

/**
 * Grant a scope, or leave an existing live grant exactly as it is.
 *
 * IDEMPOTENT, NOT REPLACING. Granting a scope the principal already holds
 * live is a no-op: same row, same `id`, same `granted_by`, same
 * `granted_at`. That is what makes the id referenceable — a credential or
 * receipt naming a grant still names the same grant afterwards.
 *
 * The previous `INSERT OR REPLACE` did the opposite, and its worst case was
 * not the moved id but the erased revocation: re-granting a revoked scope
 * overwrote the row that recorded the revocation, so the audit view lost the
 * one event it existed to show. A re-grant after a revocation now INSERTS a
 * new grant beside the revoked one — two rows, one history, one live.
 */
export function grantCapability(
  sql: any, principalId: string, scope: string, grantedBy?: string, expiresAt?: string,
): void {
  ensurePrincipalSchema(sql);
  const live = sql.exec(
    "SELECT COUNT(*) AS c FROM capability_grants WHERE principal_id = ? AND scope = ? AND revoked_at IS NULL",
    principalId, scope,
  ).toArray() as Array<{ c: number }>;
  if ((live[0]?.c ?? 0) > 0) return;
  sql.exec(
    "INSERT INTO capability_grants (id, principal_id, scope, granted_by, expires_at) VALUES (?, ?, ?, ?, ?)",
    crypto.randomUUID(), principalId, scope, grantedBy ?? null, expiresAt ?? null,
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
    // ORDER BY granted_at, then rowid: `datetime('now')` has one-second
    // resolution, so a revoke-and-re-grant inside the same second ties and
    // leaves the audit view's order up to the query planner. rowid breaks
    // the tie by insertion order, which is the order the events happened in.
    "SELECT id, principal_id, scope, granted_by, granted_at, expires_at, revoked_at, revoked_by FROM capability_grants WHERE principal_id = ? ORDER BY granted_at, rowid",
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

export const INVITE_DEFAULT_TTL_SECONDS = 3600;

/**
 * The longest an invite may live: 7 days (notme-2131e8).
 *
 * An invite is a bearer way in — whoever holds the link gets the scopes it
 * names, authorityManage included — so its lifetime is exposure. The TTL is
 * caller-supplied and was unclamped. 168 hours is not a new number: it is
 * the ceiling the invite form (public/_invite.html, max="168") has always
 * stated; the API simply did not enforce it. Enforced HERE, in the one
 * function that writes expires_at, so no route can forget it.
 */
export const INVITE_MAX_TTL_SECONDS = 7 * 24 * 3600;

export function createInvite(
  sql: any, createdBy: string, scopes: string[], ttlSeconds = INVITE_DEFAULT_TTL_SECONDS,
): Invite {
  ensurePrincipalSchema(sql);
  if (typeof ttlSeconds !== "number" || !Number.isFinite(ttlSeconds)) {
    throw new Error("invite ttl must be a finite number of seconds");
  }
  const ttl = Math.min(ttlSeconds, INVITE_MAX_TTL_SECONDS);
  const token = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + ttl * 1000).toISOString();
  sql.exec(
    "INSERT INTO invites (token, created_by, scopes, expires_at) VALUES (?, ?, ?, ?)",
    token, createdBy, JSON.stringify(scopes), expiresAt,
  );
  return { token, createdBy, scopes, expiresAt };
}

/** What a live invite grants, and who granted it. */
export interface InviteGrant {
  scopes: string[];
  createdBy: string;
}

/** An invite that exists, is unredeemed and unexpired. A read — never a write. */
export function liveInvite(sql: any, token: string): InviteGrant | null {
  ensurePrincipalSchema(sql);
  if (typeof token !== "string" || token === "") return null;
  const rows = sql.exec(
    "SELECT scopes, created_by, created_at, expires_at, redeemed_at FROM invites WHERE token = ?", token,
  ).toArray() as Array<{ scopes: string; created_by: string; created_at: string; expires_at: string; redeemed_at: string | null }>;

  if (rows.length === 0) return null;
  const invite = rows[0];
  if (invite.redeemed_at) return null;
  if (new Date(invite.expires_at) < new Date()) return null;
  // The ceiling applies to EXISTING rows too (review M3). The clamp is in
  // createInvite, so an invite minted before it with a years-long TTL — the
  // population whose ?t= links sit in invocation logs — would otherwise stay
  // live. created_at is SQLite's "YYYY-MM-DD HH:MM:SS" (UTC, whole seconds),
  // hence the slack; an unparsable row fails closed.
  const createdMs = Date.parse(invite.created_at.replace(" ", "T") + "Z");
  const lifetimeMs = Date.parse(invite.expires_at) - createdMs;
  if (!Number.isFinite(lifetimeMs) || lifetimeMs > (INVITE_MAX_TTL_SECONDS + 60) * 1000) return null;
  const scopes = JSON.parse(invite.scopes) as string[];
  // The inviter's CURRENT grants must still allow every scope (review M2).
  // canGrant ran only at mint, so revoking an admin left their outstanding
  // invites able to hand out what was just taken away. All-or-nothing: an
  // invite is refused rather than silently narrowed.
  const granter = getCapabilities(sql, invite.created_by);
  if (!scopes.every((s) => canGrant(granter, s))) return null;
  return { scopes, createdBy: invite.created_by };
}

/**
 * Mark an invite redeemed by `redeemedBy`. Synchronous, so a caller in a
 * Durable Object can check, redeem and create the principal with no await in
 * between — the single-use property is that block, not this UPDATE alone.
 */
export function redeemInvite(sql: any, token: string, redeemedBy: string): InviteGrant | null {
  const invite = liveInvite(sql, token);
  if (!invite) return null;
  sql.exec(
    "UPDATE invites SET redeemed_by = ?, redeemed_at = datetime('now') WHERE token = ? AND redeemed_at IS NULL",
    redeemedBy, token,
  );
  return invite;
}

// ── Invite reservations: reserve at registration start, consume at verify ──
//
// notme-3dfe15 (parts 4/5). Redeeming an invite when the passkey ceremony
// STARTS meant a cancelled or failed ceremony burned it, and enrolling the
// principal separately at verify meant the invite's scopes were never applied
// at all. A reservation records "WebAuthn user id U is registering under
// invite T" without spending T; consumption happens when U's credential
// verifies, together with creating U as a principal holding T's scopes.
//
// Several reservations may name one invite (a retry after a failed ceremony
// starts a new one). The first to verify consumes the invite; every other one
// then finds it redeemed and is refused. A reservation is not a lock, because
// the token is the bearer credential — anyone able to reserve could equally
// have redeemed.

/** Same window as a registration challenge (passkey.ts, 5 minutes). */
export const INVITE_RESERVATION_TTL_SECONDS = 300;

/**
 * Reserve `token` for registration `userId`, bound to the browser holding the
 * secret whose SHA-256 is `secretHash` (review M1). null when the invite is
 * not live.
 */
export function reserveInvite(
  sql: any, token: string, userId: string, secretHash: string,
): InviteGrant | null {
  const invite = liveInvite(sql, token);
  const now = Math.floor(Date.now() / 1000);
  sql.exec("DELETE FROM invite_reservations WHERE expires_at <= ?", now);
  if (!invite || !secretHash) return null;
  sql.exec(
    "INSERT OR REPLACE INTO invite_reservations (user_id, token, expires_at, secret_hash) VALUES (?, ?, ?, ?)",
    userId, token, now + INVITE_RESERVATION_TTL_SECONDS, secretHash,
  );
  return invite;
}

/**
 * Consume `userId`'s reservation: redeem the invite it names, for `userId`.
 * Requires the reserving browser's secret (as its SHA-256): without it the
 * reservation is left alone — so a caller who merely knows the userId can
 * neither use it nor cancel it — and null is returned. With it, the
 * reservation is deleted whether or not the invite is still live.
 */
export function consumeInviteReservation(
  sql: any, userId: string, secretHash: string,
): InviteGrant | null {
  ensurePrincipalSchema(sql);
  const rows = sql.exec(
    "SELECT token, expires_at, secret_hash FROM invite_reservations WHERE user_id = ?", userId,
  ).toArray() as Array<{ token: string; expires_at: number; secret_hash: string }>;
  if (rows.length === 0) return null;
  if (!secretHash || rows[0].secret_hash === "" || rows[0].secret_hash !== secretHash) return null;
  sql.exec("DELETE FROM invite_reservations WHERE user_id = ?", userId);
  if (rows[0].expires_at <= Math.floor(Date.now() / 1000)) return null;
  return redeemInvite(sql, rows[0].token, userId);
}
