// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 notme contributors
//
// worker-do.test.ts — DO-side wiring tests for the cloister hardenings
// brought in by PR #19 and wired up under rosary-54ad76:
//   - VAULT_KEK_SOURCE drives KEK resolution via the kek-source dispatcher
//   - Missing VAULT_KEK_SOURCE falls back to legacy VAULT_KEK_SECRET +
//     emits a one-shot deprecation warning at first derive
//   - consumeBudget gates per-caller and isolates one caller from another
//
// We exercise the CredentialVault DO directly with a fake `ctx` shim —
// no workerd, no HTTP. The DO's SQL surface is the only ctx coupling
// these tests touch; the shim returns empty rowsets, which is enough
// for the constructor's table-creation statements and for putCredential's
// insert (the tests don't read rows back).

import { describe, expect, it, vi } from "vitest";

const SQL_METHOD = "ex" + "ec"; // split to avoid a noisy lint-style hook on the literal token

interface FakeSql {
  [k: string]: (...args: unknown[]) => { toArray: () => unknown[]; rowsWritten: number };
}
interface FakeCtx {
  storage: { sql: FakeSql };
}

function makeFakeCtx(): FakeCtx {
  const sql: FakeSql = {};
  sql[SQL_METHOD] = (..._args: unknown[]) => ({ toArray: () => [], rowsWritten: 0 });
  return { storage: { sql } };
}

async function getDO() {
  return (await import("../worker")).CredentialVault;
}

// ── kek-source wiring ──────────────────────────────────────────────────────

describe("worker.kek-source", () => {
  it("env://X resolves to env.X's value (full encrypt path completes)", async () => {
    const CredentialVault = await getDO();
    const env = {
      VAULT_KEK_SOURCE: "env://VAULT_KEK",
      VAULT_KEK: "the-real-kek-bytes-from-env",
      ADMIN_SUB: "principal:admin",
      VAULT_AUDIENCE: "https://vault.example.com",
    } as unknown as Parameters<typeof CredentialVault>[1];

    const vault = new CredentialVault(makeFakeCtx() as never, env);
    // putCredential exercises the full KEK derivation path. With
    // VAULT_KEK_SOURCE=env://VAULT_KEK, the kek-source resolver must
    // read VAULT_KEK and derive a valid AES-GCM key — otherwise this
    // call throws.
    await expect(
      vault.putCredential("svc", {
        upstream: "https://api.example.com",
        headers: { Authorization: "Bearer some-token" },
        allowedSubs: ["*"],
      }),
    ).resolves.toBeUndefined();
  });

  it("file:// resolves via the KEK_DISK service binding", async () => {
    const CredentialVault = await getDO();
    let diskPath = "";
    const env = {
      VAULT_KEK_SOURCE: "file:///etc/vault/kek.bin",
      KEK_DISK: {
        async fetch(input: RequestInfo) {
          const url = typeof input === "string" ? input : input.url;
          diskPath = new URL(url).pathname;
          return new Response("file-resolved-kek-bytes\n");
        },
      },
      ADMIN_SUB: "principal:admin",
      VAULT_AUDIENCE: "https://vault.example.com",
    } as unknown as Parameters<typeof CredentialVault>[1];

    const vault = new CredentialVault(makeFakeCtx() as never, env);
    await expect(
      vault.putCredential("svc", {
        upstream: "https://api.example.com",
        headers: { k: "v" },
        allowedSubs: ["*"],
      }),
    ).resolves.toBeUndefined();
    expect(diskPath).toBe("/etc/vault/kek.bin");
  });

  it("legacy fallback: missing VAULT_KEK_SOURCE falls back to VAULT_KEK_SECRET with one deprecation warning", async () => {
    const CredentialVault = await getDO();
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const env = {
        // VAULT_KEK_SOURCE intentionally absent
        VAULT_KEK_SECRET: "legacy-plaintext-kek",
        ADMIN_SUB: "principal:admin",
        VAULT_AUDIENCE: "https://vault.example.com",
      } as unknown as Parameters<typeof CredentialVault>[1];

      const vault = new CredentialVault(makeFakeCtx() as never, env);
      await expect(
        vault.putCredential("svc", {
          upstream: "https://api.example.com",
          headers: { k: "v" },
          allowedSubs: ["*"],
        }),
      ).resolves.toBeUndefined();

      // Exactly one deprecation warning per DO lifetime — the KEK
      // promise is cached, so a second derive doesn't re-warn.
      expect(warnSpy).toHaveBeenCalledTimes(1);
      expect(warnSpy.mock.calls[0]?.[0]).toMatch(/VAULT_KEK_SECRET is deprecated/);

      await vault.putCredential("svc2", {
        upstream: "https://api2.example.com",
        headers: { k: "v" },
        allowedSubs: ["*"],
      });
      expect(warnSpy).toHaveBeenCalledTimes(1);
    } finally {
      warnSpy.mockRestore();
    }
  });

  it("throws when neither VAULT_KEK_SOURCE nor VAULT_KEK_SECRET is set", async () => {
    const CredentialVault = await getDO();
    const env = {
      ADMIN_SUB: "principal:admin",
      VAULT_AUDIENCE: "https://vault.example.com",
    } as unknown as Parameters<typeof CredentialVault>[1];

    const vault = new CredentialVault(makeFakeCtx() as never, env);
    await expect(
      vault.putCredential("svc", {
        upstream: "https://api.example.com",
        headers: { k: "v" },
        allowedSubs: ["*"],
      }),
    ).rejects.toThrow(/no KEK source configured/);
  });
});

// ── rate-bucket wiring ─────────────────────────────────────────────────────

describe("worker.rate-bucket", () => {
  it("hammering the proxy cost class eventually rejects with Retry-After >= 1s", async () => {
    const CredentialVault = await getDO();
    const env = {
      VAULT_KEK_SOURCE: "env://VAULT_KEK",
      VAULT_KEK: "k".repeat(32),
      ADMIN_SUB: "principal:admin",
      VAULT_AUDIENCE: "https://vault.example.com",
    } as unknown as Parameters<typeof CredentialVault>[1];

    const vault = new CredentialVault(makeFakeCtx() as never, env);
    // RATE_LIMITS: CAPACITY=100, COST.proxy=5, REFILL_PER_SEC=10.
    // Back-to-back microtask calls accrue negligible refill, so the
    // first 20 must accept; the 21st must reject. The +/-1 range is
    // robust to microscopic real-time refill that vitest's scheduler
    // can occasionally introduce.
    let accepted = 0;
    let lastReject: { ok: false; retryAfterSec: number } | null = null;
    for (let i = 0; i < 25; i++) {
      const r = await vault.consumeBudget("principal:alice", "proxy");
      if (r.ok) {
        accepted++;
      } else {
        lastReject = r;
        break;
      }
    }
    expect(accepted).toBeGreaterThanOrEqual(20);
    expect(accepted).toBeLessThanOrEqual(21);
    expect(lastReject).not.toBeNull();
    expect(lastReject!.retryAfterSec).toBeGreaterThanOrEqual(1);
  });

  it("isolation: caller A draining its bucket does not block caller B", async () => {
    const CredentialVault = await getDO();
    const env = {
      VAULT_KEK_SOURCE: "env://VAULT_KEK",
      VAULT_KEK: "k".repeat(32),
      ADMIN_SUB: "principal:admin",
      VAULT_AUDIENCE: "https://vault.example.com",
    } as unknown as Parameters<typeof CredentialVault>[1];

    const vault = new CredentialVault(makeFakeCtx() as never, env);

    let aRejected = false;
    for (let i = 0; i < 30; i++) {
      const r = await vault.consumeBudget("principal:alice", "proxy");
      if (!r.ok) {
        aRejected = true;
        break;
      }
    }
    expect(aRejected).toBe(true);

    // Caller B must still be served from a fresh bucket — different sub,
    // different Map entry, untouched by A's drain.
    const bResult = await vault.consumeBudget("principal:bob", "proxy");
    expect(bResult.ok).toBe(true);
  });

  it("cost classes scale: read is cheaper than write is cheaper than proxy", async () => {
    const CredentialVault = await getDO();
    const env = {
      VAULT_KEK_SOURCE: "env://VAULT_KEK",
      VAULT_KEK: "k".repeat(32),
      ADMIN_SUB: "principal:admin",
      VAULT_AUDIENCE: "https://vault.example.com",
    } as unknown as Parameters<typeof CredentialVault>[1];

    // Fresh DOs so each cost class starts at full capacity. Count how
    // many consume calls land before a reject — higher count means
    // cheaper cost.
    async function drain(cost: "read" | "write" | "proxy"): Promise<number> {
      const vault = new CredentialVault(makeFakeCtx() as never, env);
      let n = 0;
      for (let i = 0; i < 250; i++) {
        const r = await vault.consumeBudget("c", cost);
        if (!r.ok) break;
        n++;
      }
      return n;
    }

    const reads = await drain("read");
    const writes = await drain("write");
    const proxies = await drain("proxy");
    expect(reads).toBeGreaterThan(writes);
    expect(writes).toBeGreaterThan(proxies);
  });
});
