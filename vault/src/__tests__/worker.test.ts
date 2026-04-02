/**
 * worker.test.ts — TDD tests for the vault Worker request handler.
 *
 * Tests the HTTP layer: routing, identity verification, credential
 * lookup, proxy dispatch, admin bootstrap. Uses the vault core functions
 * (already tested) and mocks the identity verification + DO storage.
 */

import { describe, expect, it, beforeEach } from "vitest";

// ── In-memory storage (same as vault.test.ts) ──────────────────────────────

interface StoredCredential {
  upstream: string;
  headers: Record<string, string>;
  allowedSubs: string[];
}

interface VaultStorage {
  get(service: string): Promise<StoredCredential | null>;
  put(service: string, cred: StoredCredential): Promise<void>;
  delete(service: string): Promise<boolean>;
  list(): Promise<string[]>;
}

function createMemoryStorage(): VaultStorage {
  const store = new Map<string, StoredCredential>();
  return {
    async get(service) { return store.get(service) ?? null; },
    async put(service, cred) { store.set(service, cred); },
    async delete(service) { return store.delete(service); },
    async list() { return [...store.keys()]; },
  };
}

// ── Import handler (will fail until implemented) ───────────────────────────

async function getHandler() {
  return (await import("../handler")).handleRequest;
}

// ── Types ──────────────────────────────────────────────────────────────────

interface HandlerInput {
  request: Request;
  storage: VaultStorage;
  /** Resolve identity from the request. Returns sub or null. */
  resolveIdentity: (req: Request) => Promise<string | null>;
  /** Admin sub — only this principal can store/delete credentials. */
  adminSub: string;
}

// ── Helper ─────────────────────────────────────────────────────────────────

function makeInput(
  overrides: Partial<HandlerInput> & { request: Request },
): HandlerInput {
  return {
    storage: createMemoryStorage(),
    resolveIdentity: async () => "principal:alice",
    adminSub: "principal:admin",
    ...overrides,
  };
}

// ── Proxy route: GET/POST /:service/* ──────────────────────────────────────

describe("proxy: GET /:service", () => {
  it("returns 401 when identity cannot be resolved", async () => {
    const handleRequest = await getHandler();
    const res = await handleRequest(makeInput({
      request: new Request("https://vault.example.com/nvd?cveId=CVE-2026-1"),
      resolveIdentity: async () => null,
    }));
    expect(res.status).toBe(401);
    const body = await res.json() as { error: string };
    expect(body.error).toContain("identity");
  });

  it("returns 404 when service not found", async () => {
    const handleRequest = await getHandler();
    const res = await handleRequest(makeInput({
      request: new Request("https://vault.example.com/nonexistent"),
    }));
    expect(res.status).toBe(404);
  });

  it("returns 403 when sub does not match allowedSubs", async () => {
    const handleRequest = await getHandler();
    const storage = createMemoryStorage();
    await storage.put("nvd", {
      upstream: "https://services.nvd.nist.gov/rest/json/cves/2.0",
      headers: { apiKey: "secret" },
      allowedSubs: ["repo:org/venturi:*"],
    });

    const res = await handleRequest(makeInput({
      request: new Request("https://vault.example.com/nvd"),
      storage,
      resolveIdentity: async () => "repo:org/other:read",
    }));
    expect(res.status).toBe(403);
    // Must not contain the API key
    const text = await res.text();
    expect(text).not.toContain("secret");
  });

  it("returns 400 for invalid service name", async () => {
    const handleRequest = await getHandler();
    // Service names with special characters are rejected
    const res = await handleRequest(makeInput({
      request: new Request("https://vault.example.com/.hidden"),
    }));
    expect(res.status).toBe(400);
  });

  it("URL-normalized path traversal results in safe lookup, not traversal", async () => {
    const handleRequest = await getHandler();
    // URL constructor normalizes /../etc/passwd → /etc/passwd
    // Service becomes "etc" (safe alphanumeric) → 404 (not stored)
    const res = await handleRequest(makeInput({
      request: new Request("https://vault.example.com/../etc/passwd"),
    }));
    // Should be 404 (service "etc" not found), not a path traversal
    expect(res.status).toBe(404);
  });
});

// ── Admin: PUT /:service (store credential) ────────────────────────────────

describe("admin: PUT /:service", () => {
  it("allows admin to store a credential", async () => {
    const handleRequest = await getHandler();
    const storage = createMemoryStorage();

    const res = await handleRequest(makeInput({
      request: new Request("https://vault.example.com/nvd", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          upstream: "https://services.nvd.nist.gov/rest/json/cves/2.0",
          headers: { apiKey: "my-nvd-key" },
          allowedSubs: ["repo:org/venturi:*"],
        }),
      }),
      storage,
      resolveIdentity: async () => "principal:admin",
      adminSub: "principal:admin",
    }));

    expect(res.status).toBe(200);
    const stored = await storage.get("nvd");
    expect(stored).not.toBeNull();
    expect(stored!.headers.apiKey).toBe("my-nvd-key");
  });

  it("rejects non-admin from storing credentials", async () => {
    const handleRequest = await getHandler();
    const res = await handleRequest(makeInput({
      request: new Request("https://vault.example.com/nvd", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          upstream: "https://api.example.com",
          headers: { key: "val" },
          allowedSubs: ["*"],
        }),
      }),
      resolveIdentity: async () => "principal:alice",
      adminSub: "principal:admin",
    }));
    expect(res.status).toBe(403);
  });

  it("validates upstream URL on store", async () => {
    const handleRequest = await getHandler();
    const res = await handleRequest(makeInput({
      request: new Request("https://vault.example.com/nvd", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          upstream: "http://evil.com/steal",  // not HTTPS
          headers: { key: "val" },
          allowedSubs: ["*"],
        }),
      }),
      resolveIdentity: async () => "principal:admin",
      adminSub: "principal:admin",
    }));
    expect(res.status).toBe(400);
  });

  it("validates upstream URL is not private", async () => {
    const handleRequest = await getHandler();
    const res = await handleRequest(makeInput({
      request: new Request("https://vault.example.com/internal", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          upstream: "https://169.254.169.254/latest/meta-data",
          headers: { key: "val" },
          allowedSubs: ["*"],
        }),
      }),
      resolveIdentity: async () => "principal:admin",
      adminSub: "principal:admin",
    }));
    expect(res.status).toBe(400);
  });
});

// ── Admin: DELETE /:service ─────────────────────────────────────────────────

describe("admin: DELETE /:service", () => {
  it("allows admin to delete a credential", async () => {
    const handleRequest = await getHandler();
    const storage = createMemoryStorage();
    await storage.put("nvd", {
      upstream: "https://nvd.api",
      headers: { apiKey: "k" },
      allowedSubs: ["*"],
    });

    const res = await handleRequest(makeInput({
      request: new Request("https://vault.example.com/nvd", { method: "DELETE" }),
      storage,
      resolveIdentity: async () => "principal:admin",
      adminSub: "principal:admin",
    }));
    expect(res.status).toBe(200);
    expect(await storage.get("nvd")).toBeNull();
  });

  it("returns 404 when deleting non-existent service", async () => {
    const handleRequest = await getHandler();
    const res = await handleRequest(makeInput({
      request: new Request("https://vault.example.com/nope", { method: "DELETE" }),
      resolveIdentity: async () => "principal:admin",
      adminSub: "principal:admin",
    }));
    expect(res.status).toBe(404);
  });
});

// ── Admin: GET /admin/services ──────────────────────────────────────────────

describe("admin: GET /admin/services", () => {
  it("lists services without exposing credentials", async () => {
    const handleRequest = await getHandler();
    const storage = createMemoryStorage();
    await storage.put("nvd", {
      upstream: "https://nvd.api",
      headers: { apiKey: "SECRET-KEY" },
      allowedSubs: ["repo:org/venturi:*"],
    });
    await storage.put("github", {
      upstream: "https://api.github.com",
      headers: { Authorization: "token gh_SECRET" },
      allowedSubs: ["*"],
    });

    const res = await handleRequest(makeInput({
      request: new Request("https://vault.example.com/admin/services"),
      storage,
      resolveIdentity: async () => "principal:admin",
      adminSub: "principal:admin",
    }));

    expect(res.status).toBe(200);
    const body = await res.json() as { services: Array<{ name: string; upstream: string; allowedSubs: string[] }> };
    expect(body.services).toHaveLength(2);
    // Must expose service names and scopes but NOT credential headers
    const text = JSON.stringify(body);
    expect(text).not.toContain("SECRET-KEY");
    expect(text).not.toContain("gh_SECRET");
    expect(text).toContain("nvd");
    expect(text).toContain("github");
  });

  it("rejects non-admin from listing services", async () => {
    const handleRequest = await getHandler();
    const res = await handleRequest(makeInput({
      request: new Request("https://vault.example.com/admin/services"),
      resolveIdentity: async () => "principal:alice",
      adminSub: "principal:admin",
    }));
    expect(res.status).toBe(403);
  });
});

// ── Audit logging ──────────────────────────────────────────────────────────

describe("audit logging", () => {
  it("never includes credential values in console output", async () => {
    // This is a structural test — we verify the log entry builder
    const { buildAuditEntry } = await import("../handler");

    const entry = buildAuditEntry({
      event: "proxy",
      sub: "principal:alice",
      service: "nvd",
      method: "GET",
      status: 200,
    });

    const json = JSON.stringify(entry);
    expect(json).not.toContain("apiKey");
    expect(json).not.toContain("secret");
    expect(entry.event).toBe("proxy");
    expect(entry.sub).toBe("principal:alice");
    expect(entry.service).toBe("nvd");
    expect(typeof entry.ts).toBe("number");
  });
});
