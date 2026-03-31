/**
 * connections.test.ts — OIDC connection factory tests.
 * Maps to THREAT_MODEL.md: OIDC association model.
 *
 * Tests the connection storage + lookup logic.
 * The actual OAuth flow (redirect, callback) requires a browser.
 * sql.exec() is SQLite's method, not child_process.
 */

import { describe, expect, it } from "vitest";

// Simple SQL mock for connection storage
function createMockSql() {
  const rows: any[] = [];
  return {
    // SQLite exec method — NOT child_process
    exec(query: string, ...params: unknown[]) {
      const q = query.trim().toUpperCase();
      if (q.startsWith("CREATE TABLE")) return { toArray: () => [] };

      if (q.startsWith("INSERT") || q.includes("REPLACE")) {
        const existing = rows.findIndex(
          (r: any) =>
            r.credential_id === params[0] && r.provider === params[1],
        );
        if (existing >= 0) rows.splice(existing, 1);
        rows.push({
          credential_id: params[0],
          provider: params[1],
          provider_subject: params[2],
          provider_email: params[3] ?? null,
          connected_at: new Date().toISOString(),
        });
        return { toArray: () => [] };
      }

      if (q.startsWith("SELECT")) {
        if (params.length === 1) {
          return {
            toArray: () =>
              rows.filter((r: any) => r.credential_id === params[0]),
          };
        }
        if (params.length === 2) {
          return {
            toArray: () =>
              rows.filter(
                (r: any) =>
                  r.provider === params[0] &&
                  r.provider_subject === params[1],
              ),
          };
        }
        return { toArray: () => rows };
      }

      return { toArray: () => [] };
    },
  };
}

describe("connections.storage", () => {
  it("stores a connection with provider + subject", async () => {
    const { createConnection, getConnections } = await import(
      "../auth/connections"
    );
    const mockSql = createMockSql();

    await createConnection(mockSql, {
      credentialId: "passkey-abc",
      provider: "github",
      providerSubject: "alice",
      providerEmail: "alice@example.com",
    });

    const conns = await getConnections(mockSql, "passkey-abc");
    expect(conns).toHaveLength(1);
    expect(conns[0].provider).toBe("github");
    expect(conns[0].providerSubject).toBe("alice");
  });

  it("supports multiple providers per credential", async () => {
    const { createConnection, getConnections } = await import(
      "../auth/connections"
    );
    const mockSql = createMockSql();

    await createConnection(mockSql, {
      credentialId: "passkey-abc",
      provider: "github",
      providerSubject: "alice",
    });
    await createConnection(mockSql, {
      credentialId: "passkey-abc",
      provider: "google",
      providerSubject: "alice@test.local",
    });

    const conns = await getConnections(mockSql, "passkey-abc");
    expect(conns).toHaveLength(2);
    expect(conns.map((c: any) => c.provider).sort()).toEqual([
      "github",
      "google",
    ]);
  });

  it("updates existing provider for same credential (no duplicates)", async () => {
    const { createConnection, getConnections } = await import(
      "../auth/connections"
    );
    const mockSql = createMockSql();

    await createConnection(mockSql, {
      credentialId: "passkey-abc",
      provider: "github",
      providerSubject: "alice",
    });
    await createConnection(mockSql, {
      credentialId: "passkey-abc",
      provider: "github",
      providerSubject: "othername",
    });

    const conns = await getConnections(mockSql, "passkey-abc");
    expect(conns).toHaveLength(1);
    expect(conns[0].providerSubject).toBe("othername");
  });
});

describe("connections.lookup", () => {
  it("finds credential by provider subject", async () => {
    const { createConnection, findByProvider } = await import(
      "../auth/connections"
    );
    const mockSql = createMockSql();

    await createConnection(mockSql, {
      credentialId: "passkey-abc",
      provider: "github",
      providerSubject: "alice",
    });

    const result = await findByProvider(mockSql, "github", "jamestexas");
    expect(result).not.toBeNull();
    expect(result!.credentialId).toBe("passkey-abc");
  });

  it("returns null for unknown provider subject", async () => {
    const { findByProvider } = await import("../auth/connections");
    const mockSql = createMockSql();

    const result = await findByProvider(mockSql, "github", "nobody");
    expect(result).toBeNull();
  });
});
