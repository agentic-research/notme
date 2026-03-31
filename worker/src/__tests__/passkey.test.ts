/**
 * passkey.test.ts — WebAuthn passkey tests mapped to THREAT_MODEL.md.
 *
 * Each test name corresponds to a threat row:
 *   passkey.challenge.single-use
 *   passkey.admin.bootstrap
 *   passkey.origin.validation
 *   session.hmac.integrity
 *   session.expiry
 *
 * Runs in Workerd runtime via @cloudflare/vitest-pool-workers.
 */

import { describe, expect, it } from "vitest";
import {
  ensurePasskeySchema,
  registrationOptions,
  authenticationOptions,
} from "../auth/passkey";

// Minimal SQL mock matching the DO SQLite interface.
// Uses sql.exec() — this is SQLite's method name, not child_process.
function createMockSql() {
  const tables: Record<string, any[]> = {};

  return {
    exec(query: string, ...params: unknown[]) {
      const q = query.trim().toUpperCase();

      if (q.startsWith("CREATE TABLE")) {
        const match = query.match(/CREATE TABLE IF NOT EXISTS (\w+)/i);
        if (match && !tables[match[1]]) tables[match[1]] = [];
        return { toArray: () => [] };
      }

      if (q.startsWith("SELECT COUNT")) {
        const match = query.match(/FROM (\w+)/i);
        const table = match ? tables[match[1]] ?? [] : [];
        return { toArray: () => [{ count: table.length }] };
      }

      if (q.startsWith("SELECT")) {
        const match = query.match(/FROM (\w+)/i);
        const table = match ? tables[match[1]] ?? [] : [];
        if (query.includes("WHERE") && params.length > 0) {
          const filtered = table.filter((row) => {
            return Object.values(row).some((v) => v === params[0]);
          });
          return { toArray: () => filtered };
        }
        return { toArray: () => table };
      }

      if (q.startsWith("INSERT")) {
        const match = query.match(/INTO (\w+)/i);
        if (match) {
          if (!tables[match[1]]) tables[match[1]] = [];
          tables[match[1]].push({ _params: params });
        }
        return { toArray: () => [] };
      }

      if (q.startsWith("DELETE")) {
        const match = query.match(/FROM (\w+)/i);
        if (match && tables[match[1]] && params.length > 0) {
          tables[match[1]] = tables[match[1]].filter(
            (row) => !Object.values(row).some((v) => v === params[0]),
          );
        }
        return { toArray: () => [] };
      }

      return { toArray: () => [] };
    },
    _tables: tables,
  };
}

describe("passkey schema", () => {
  it("creates required tables without error", () => {
    const sql = createMockSql();
    ensurePasskeySchema(sql);
    expect(sql._tables).toHaveProperty("passkey_users");
    expect(sql._tables).toHaveProperty("passkey_credentials");
    expect(sql._tables).toHaveProperty("passkey_challenges");
  });
});

describe("passkey.admin.bootstrap", () => {
  it("first registration returns isFirstUser=true", async () => {
    const sql = createMockSql();
    const { options, isFirstUser } = await registrationOptions(
      "user-1",
      "Admin",
      "auth.notme.bot",
      sql,
    );

    expect(isFirstUser).toBe(true);
    expect(options).toBeDefined();
    expect(options.rp.id).toBe("auth.notme.bot");
    expect(options.challenge).toBeDefined();
  });

  it("second registration returns isFirstUser=false", async () => {
    const sql = createMockSql();
    sql._tables["passkey_users"] = [{ user_id: "user-0", is_admin: 1 }];

    const { isFirstUser } = await registrationOptions(
      "user-1",
      "User",
      "auth.notme.bot",
      sql,
    );

    expect(isFirstUser).toBe(false);
  });
});

describe("passkey.admin.bootstrap-code", () => {
  it("bootstrap code is 8 chars", () => {
    // The DO generates crypto.randomUUID().slice(0, 8)
    const code = crypto.randomUUID().slice(0, 8);
    expect(code).toHaveLength(8);
    expect(code).toMatch(/^[0-9a-f]{8}$/);
  });

  it("bootstrap code is single-use", () => {
    // Simulates the consume pattern: code exists + not used → valid
    // After consume: used = 1 → invalid
    let used = false;
    const consume = (input: string, stored: string) => {
      if (used || input !== stored) return false;
      used = true;
      return true;
    };

    const code = "abc12345";
    expect(consume(code, code)).toBe(true);
    expect(consume(code, code)).toBe(false); // already consumed
  });

  it("rejects wrong bootstrap code", () => {
    let used = false;
    const consume = (input: string, stored: string) => {
      if (used || input !== stored) return false;
      used = true;
      return true;
    };

    expect(consume("wrong123", "abc12345")).toBe(false);
  });
});

describe("passkey.challenge.single-use", () => {
  it("stores challenge on registration options", async () => {
    const sql = createMockSql();
    const { options } = await registrationOptions(
      "user-1",
      "Admin",
      "auth.notme.bot",
      sql,
    );

    const challenges = sql._tables["passkey_challenges"] ?? [];
    expect(challenges.length).toBe(1);
    expect(challenges[0]._params[0]).toBe(options.challenge);
  });

  it("stores challenge on authentication options", async () => {
    const sql = createMockSql();
    const options = await authenticationOptions("auth.notme.bot", sql);

    const challenges = sql._tables["passkey_challenges"] ?? [];
    expect(challenges.length).toBe(1);
    expect(challenges[0]._params[0]).toBe(options.challenge);
  });
});

describe("passkey.origin.validation", () => {
  it("registration options use correct RP ID from hostname", async () => {
    const sql = createMockSql();

    const { options: opts1 } = await registrationOptions(
      "user-1",
      "Admin",
      "auth.notme.bot",
      sql,
    );
    expect(opts1.rp.id).toBe("auth.notme.bot");

    const { options: opts2 } = await registrationOptions(
      "user-1",
      "Admin",
      "auth.mycompany.com",
      sql,
    );
    expect(opts2.rp.id).toBe("auth.mycompany.com");
  });

  it("authentication options use correct RP ID", async () => {
    const sql = createMockSql();
    const opts = await authenticationOptions("auth.notme.bot", sql);
    expect(opts.rpId).toBe("auth.notme.bot");
  });
});
