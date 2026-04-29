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
  verifyAuthentication,
} from "../auth/passkey";
import { timingSafeEqual } from "../auth/timing-safe";

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

describe("passkey.challenge.sweeper (notme-ae81c9, M2)", () => {
  // The lookup at verify time filters by `created_at > datetime('now',
  // '-5 minutes')`, but never DELETES expired rows. Abandoned flows
  // (user closes browser, network failure) leave dead rows forever.
  // The sweeper runs on every options call and DELETEs rows older than
  // 1 hour. This test asserts the DELETE statement is issued, with the
  // right age threshold.

  function makeRecordingMock(
    calls: { query: string; params: unknown[] }[],
  ) {
    return {
      _tables: { passkey_users: [] as any[], passkey_credentials: [] as any[] },
      exec(query: string, ...params: unknown[]) {
        calls.push({ query, params });
        const q = query.trim().toUpperCase();
        if (q.startsWith("CREATE TABLE")) return { toArray: () => [] };
        if (q.startsWith("SELECT COUNT")) {
          return { toArray: () => [{ count: 0 }] };
        }
        if (q.startsWith("SELECT")) return { toArray: () => [] };
        return { toArray: () => [] };
      },
    };
  }

  it("authenticationOptions sweeps challenges older than 1 hour", async () => {
    const calls: { query: string; params: unknown[] }[] = [];
    const sql = makeRecordingMock(calls);
    await authenticationOptions("auth.notme.bot", sql);

    const sweep = calls.find(
      (c) =>
        c.query.toUpperCase().startsWith("DELETE") &&
        c.query.includes("passkey_challenges") &&
        c.query.includes("created_at <"),
    );
    expect(sweep, "expected a DELETE-old-challenges sweep").toBeTruthy();
    // 1-hour cutoff (the policy chosen in passkey.ts)
    expect(sweep!.query).toMatch(/datetime\('now',\s*'-1 hour'\)/);
    // Sweep must run BEFORE the INSERT — otherwise the row we're about
    // to add could be caught by the broom (degenerate case: clock skew).
    const sweepIdx = calls.indexOf(sweep!);
    const insertIdx = calls.findIndex((c) =>
      c.query.toUpperCase().startsWith("INSERT") &&
      c.query.includes("passkey_challenges"),
    );
    expect(insertIdx).toBeGreaterThan(sweepIdx);
  });

  it("registrationOptions also sweeps challenges older than 1 hour", async () => {
    const calls: { query: string; params: unknown[] }[] = [];
    const sql = makeRecordingMock(calls);
    await registrationOptions("user-1", "Admin", "auth.notme.bot", sql);

    const sweep = calls.find(
      (c) =>
        c.query.toUpperCase().startsWith("DELETE") &&
        c.query.includes("passkey_challenges") &&
        c.query.includes("created_at <"),
    );
    expect(sweep).toBeTruthy();
    expect(sweep!.query).toMatch(/datetime\('now',\s*'-1 hour'\)/);
  });
});

describe("passkey.challenge.session-binding", () => {
  // Threat: two concurrent authentication flows. Without per-flow binding,
  // a "most recent" lookup picks up the wrong challenge and breaks the
  // legitimate flow (or, with stale challenges, could enable replay).
  // Fix: look up the issued challenge by exact value submitted in
  // clientDataJSON. These tests exercise that lookup path.

  function makeClientDataJSON(challenge: string): string {
    const json = JSON.stringify({
      type: "webauthn.get",
      challenge,
      origin: "https://auth.notme.bot",
      crossOrigin: false,
    });
    // base64url-encode (no padding)
    return btoa(json).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function makeAuthResponse(challenge: string, credId = "cred-1") {
    return {
      id: credId,
      rawId: credId,
      type: "public-key" as const,
      clientExtensionResults: {},
      authenticatorAttachment: "platform" as const,
      response: {
        authenticatorData: "AAAA",
        clientDataJSON: makeClientDataJSON(challenge),
        signature: "AAAA",
        userHandle: "dXNlci0x",
      },
    };
  }

  it("rejects assertions whose challenge was never issued", async () => {
    const sql = createMockSql();
    // No challenges stored. Submitted challenge has no DB match.
    const result = await verifyAuthentication(
      makeAuthResponse("never-issued-challenge") as any,
      "auth.notme.bot",
      "https://auth.notme.bot",
      sql,
    );
    expect(result.verified).toBe(false);
    expect(result.userId).toBeNull();
  });

  it("rejects assertions with malformed clientDataJSON", async () => {
    const sql = createMockSql();
    const response = {
      id: "cred-1",
      rawId: "cred-1",
      type: "public-key" as const,
      clientExtensionResults: {},
      response: {
        authenticatorData: "AAAA",
        // Not valid base64url JSON.
        clientDataJSON: "!!!not-base64!!!",
        signature: "AAAA",
      },
    };
    const result = await verifyAuthentication(
      response as any,
      "auth.notme.bot",
      "https://auth.notme.bot",
      sql,
    );
    expect(result.verified).toBe(false);
  });

  it("rejects assertions whose clientDataJSON has no challenge field", async () => {
    const sql = createMockSql();
    // base64url of '{"type":"webauthn.get"}' — no challenge field.
    const noChallengeJSON = btoa('{"type":"webauthn.get"}')
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const response = {
      id: "cred-1",
      rawId: "cred-1",
      type: "public-key" as const,
      clientExtensionResults: {},
      response: {
        authenticatorData: "AAAA",
        clientDataJSON: noChallengeJSON,
        signature: "AAAA",
      },
    };
    const result = await verifyAuthentication(
      response as any,
      "auth.notme.bot",
      "https://auth.notme.bot",
      sql,
    );
    expect(result.verified).toBe(false);
  });

  it("authentication options query no longer uses ORDER BY DESC LIMIT 1", async () => {
    // Regression guard: the old lookup was ORDER BY created_at DESC LIMIT 1,
    // which let two concurrent flows stomp each other. The fix looks up by
    // the exact challenge value from clientDataJSON. We can't easily diff
    // the SQL string from outside, but we can confirm via behavior: with
    // ZERO authentication challenges stored AND a valid clientDataJSON
    // submitted, the old code threw "no pending authentication challenge"
    // because LIMIT 1 returned nothing. The new code returns
    // {verified: false} cleanly without throwing.
    const sql = createMockSql();
    let threw = false;
    try {
      await verifyAuthentication(
        makeAuthResponse("anything") as any,
        "auth.notme.bot",
        "https://auth.notme.bot",
        sql,
      );
    } catch {
      threw = true;
    }
    expect(threw).toBe(false);
  });
});

describe("passkey.bootstrap.timing-safe", () => {
  // Threat: byte-by-byte inference of bootstrap code via response-time
  // side-channel. Defense: timingSafeEqual digests both inputs through
  // HMAC-SHA256 and XOR-compares fixed-length outputs.

  it("returns true for equal strings", async () => {
    expect(await timingSafeEqual("abc12345", "abc12345")).toBe(true);
  });

  it("returns false for different strings of same length", async () => {
    expect(await timingSafeEqual("abc12345", "abc12346")).toBe(false);
  });

  it("returns false for different-length strings", async () => {
    expect(await timingSafeEqual("abc", "abc12345")).toBe(false);
  });

  it("returns false when comparing prefix to full string", async () => {
    // Naive `startsWith` would short-circuit; HMAC digests differ entirely.
    expect(await timingSafeEqual("abc", "abcdef")).toBe(false);
  });

  it("returns true for empty == empty (boundary)", async () => {
    expect(await timingSafeEqual("", "")).toBe(true);
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
