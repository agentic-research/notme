// OIDC connection factory — associates external identity providers with passkey credentials.
//
// A "connection" binds an OIDC-verified identity (GitHub, Google, CF Access, etc.)
// to a passkey credential. Bridge certs can then include claims from connected providers.
//
// The passkey is the root identity. Connections are branches.
//
// NOTE: sql.exec() below is SQLite's query method on the DO, not child_process.

export interface Connection {
  credentialId: string;
  provider: string; // "github", "google", "cf-access", etc.
  providerSubject: string; // OIDC sub claim (username, email, etc.)
  providerEmail?: string;
  connectedAt: string;
}

export interface CreateConnectionInput {
  credentialId: string;
  provider: string;
  providerSubject: string;
  providerEmail?: string;
}

export function ensureConnectionsSchema(sql: any): void {
  sql.exec(`
    CREATE TABLE IF NOT EXISTS connections (
      credential_id    TEXT NOT NULL,
      provider         TEXT NOT NULL,
      provider_subject TEXT NOT NULL,
      provider_email   TEXT,
      connected_at     TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (credential_id, provider)
    )
  `);
}

export async function createConnection(
  sql: any,
  input: CreateConnectionInput,
): Promise<void> {
  ensureConnectionsSchema(sql);
  // UPSERT — update if same credential + provider exists
  sql.exec(
    "INSERT OR REPLACE INTO connections (credential_id, provider, provider_subject, provider_email) VALUES (?, ?, ?, ?)",
    input.credentialId,
    input.provider,
    input.providerSubject,
    input.providerEmail ?? null,
  );
}

export async function getConnections(
  sql: any,
  credentialId: string,
): Promise<Connection[]> {
  ensureConnectionsSchema(sql);
  const rows = sql
    .exec(
      "SELECT credential_id, provider, provider_subject, provider_email, connected_at FROM connections WHERE credential_id = ?",
      credentialId,
    )
    .toArray() as Array<{
    credential_id: string;
    provider: string;
    provider_subject: string;
    provider_email: string | null;
    connected_at: string;
  }>;

  return rows.map((r) => ({
    credentialId: r.credential_id,
    provider: r.provider,
    providerSubject: r.provider_subject,
    providerEmail: r.provider_email ?? undefined,
    connectedAt: r.connected_at,
  }));
}

export async function findByProvider(
  sql: any,
  provider: string,
  providerSubject: string,
): Promise<{ credentialId: string; providerSubject: string } | null> {
  ensureConnectionsSchema(sql);
  const rows = sql
    .exec(
      "SELECT credential_id, provider_subject FROM connections WHERE provider = ? AND provider_subject = ?",
      provider,
      providerSubject,
    )
    .toArray() as Array<{
    credential_id: string;
    provider_subject: string;
  }>;

  if (rows.length === 0) return null;
  return {
    credentialId: rows[0].credential_id,
    providerSubject: rows[0].provider_subject,
  };
}
