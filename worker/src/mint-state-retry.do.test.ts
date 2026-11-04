/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * mint-state-retry.do.test.ts — a re-check refusal after a spent proof is
 * retried once, then answered, never thrown (notme-b54368, review L2).
 *
 * mintBridgeCert's gha-oidc path spends the token's jti (notme-f850f2) and
 * only then captures the key and epoch, awaits a module import, and
 * re-checks. A rotate() or revokeEpoch() that commits in that window made the
 * re-check throw: the token was already burnt, and a refusal-or-result RPC
 * method raised an exception instead (security review F5).
 *
 * Now the mint re-captures and retries once — the proof is verified and
 * spent, so retrying is safe — and if the state moved again it returns
 * { ok: false, reason: "authority_state_changed" }.
 *
 * The window is driven through the SQL reads the capture and the re-check
 * make. Both read `SELECT epoch FROM state` once, capture first, so the
 * re-checks are the even-numbered epoch reads. A revokeEpoch() lands there
 * as the real epoch bump it commits. A rotate() lands as the re-check's key
 * id read returning a key id other than the captured one: its commit cannot
 * be made synchronously from the hook (its new key is generated across
 * awaits), but what the re-check observes is exactly that.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type GhaSigner, installGhaSigner, spkiPem } from "./__tests__/helpers/gha-token";
import type { SigningAuthority } from "./signing-authority";

const EPOCH_READ = "SELECT epoch FROM state WHERE id = 'authority'";
const KEY_ID_READ = "SELECT key_id FROM keys WHERE id = 'authority'";
type Sql = { exec: (q: string, ...a: unknown[]) => { toArray(): unknown[] } };

let gha: GhaSigner;
let pem: string;
beforeAll(async () => {
  gha = await installGhaSigner({ owner: "agentic-research", repo: "notme", audience: "notme.bot" });
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  pem = await spkiPem(kp.publicKey);
});
afterAll(() => gha.restore());

const authority = () => env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));

/**
 * Call mintBridgeCert with the read hook armed. `onRecheck(n)` runs at the
 * n-th re-check (1-based) and says what it observes: "epoch" bumps the real
 * epoch first (revokeEpoch committed), "key" reports a different key id
 * (rotate committed), null leaves it alone.
 */
async function mintWith(onRecheck: (n: number) => "epoch" | "key" | null) {
  const token = await gha.token();
  return runInDurableObject(authority(), async (inst, state) => {
    const auth = inst as SigningAuthority;
    await auth.getAuthorityState(); // key loaded before the hook is armed
    const sql = state.storage.sql as unknown as Sql;
    const orig = sql.exec.bind(sql);
    let epochReads = 0;
    let rechecks = 0;
    let pendingKey = false;
    sql.exec = (q: string, ...a: unknown[]) => {
      if (q === KEY_ID_READ && epochReads % 2 === 1) {
        // The key id read that opens a re-check (one capture has happened).
        const what = onRecheck(++rechecks);
        if (what === "epoch") orig("UPDATE state SET epoch = epoch + 1 WHERE id = 'authority'");
        if (what === "key") pendingKey = true;
        if (pendingKey) {
          pendingKey = false;
          return { toArray: () => [{ key_id: "f".repeat(32) }] };
        }
      }
      if (q === EPOCH_READ) epochReads++;
      return orig(q, ...a);
    };
    try {
      const first = await auth.mintBridgeCert({ kind: "gha-oidc", token }, pem).then(
        (r) => ({ threw: false as const, r }),
        (e: Error) => ({ threw: true as const, e: e.message }),
      );
      delete (sql as Partial<Sql>).exec;
      const again = await auth.mintBridgeCert({ kind: "gha-oidc", token }, pem);
      const epoch = (await auth.getAuthorityState()).epoch;
      return { first, again, epoch, rechecks };
    } finally {
      delete (sql as Partial<Sql>).exec;
    }
  });
}

describe("mintBridgeCert retries a moved re-check once, then refuses with a result (review L2)", () => {
  it("mint.gha.retry.epoch — a revokeEpoch() landing after the jti spend: the retry mints under the new epoch", async () => {
    const r = await mintWith((n) => (n === 1 ? "epoch" : null));
    expect(r.first.threw ? r.first.e : "result").toBe("result");
    if (r.first.threw) return;
    expect(r.first.r.ok).toBe(true);
    expect(r.first.r.ok && r.first.r.authority.epoch).toBe(r.epoch);
    expect(r.rechecks).toBe(2);
    // The token is spent exactly once.
    expect(r.again).toEqual({ ok: false, reason: "gha_token_reused" });
  });

  it("mint.gha.retry.rotate — a rotate() landing after the jti spend: the retry mints", async () => {
    const r = await mintWith((n) => (n === 1 ? "key" : null));
    expect(r.first.threw ? r.first.e : "result").toBe("result");
    if (r.first.threw) return;
    expect(r.first.r.ok).toBe(true);
    expect(r.rechecks).toBe(2);
  });

  it("mint.gha.retry.refusal — state still moving on the retry: a refusal result, not an exception", async () => {
    const r = await mintWith(() => "epoch");
    expect(r.first.threw ? r.first.e : "result").toBe("result");
    if (r.first.threw) return;
    expect(r.first.r).toEqual({ ok: false, reason: "authority_state_changed" });
    expect(r.rechecks).toBe(2);
    expect(r.again).toEqual({ ok: false, reason: "gha_token_reused" });
  });
});
