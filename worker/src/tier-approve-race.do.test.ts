/// <reference types="@cloudflare/vitest-plugin/types" />
/**
 * tier-approve-race.do.test.ts — an approve that changed nothing must not
 * report success (notme-052431).
 *
 * `approveTierEnrolment` reads the enrolment, checks it is pending and
 * unexpired, then awaits the authority state before its guarded UPDATE. That
 * await is a window: a revoke, a second approval or the expiry deadline can
 * land in it. The UPDATE's own guard then matches nothing, and the method used
 * to return ok anyway, so the approving human was told the machine had a tier
 * when the row said otherwise.
 *
 * HOW THE RACE IS DRIVEN. The call is started without awaiting. It runs
 * synchronously through its read and checks to the first await; the test then
 * changes the row synchronously, before the method resumes, which is exactly
 * the interleaving a concurrent request produces in a Durable Object.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { parseAuthMethod } from "./auth/session";
import { ED25519 } from "./platform";
import type { SigningAuthority } from "./signing-authority";

type Sql = { exec(q: string, ...a: unknown[]): { toArray(): unknown[] } };

async function pemKey(): Promise<string> {
  const kp = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = new Uint8Array((await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer);
  const b64 = btoa(String.fromCharCode(...spki));
  return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
}

const approval = (userCode: string, principalId: string) => ({
  userCode,
  principalId,
  identity: `spiffe://test/principal/${principalId}`,
  authMethod: parseAuthMethod("passkey")!,
  scopes: ["bridgeCert"],
  renewDays: 30,
  clonePolicy: "singleton" as const,
  criteria: [],
});

/**
 * Start an enrolment, begin an approval, apply `interleave` while the approval
 * is suspended at its await, then let it finish.
 */
async function raceApprove(name: string, interleave: (sql: Sql, userCode: string) => void) {
  const stub = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(name));
  const publicKeyPem = await pemKey();
  return runInDurableObject(stub, async (instance) => {
    const auth = instance as unknown as SigningAuthority;
    const started = await auth.startTierEnrolment({ publicKeyPem, requestedScopes: ["bridgeCert"] });
    if (!started.ok) throw new Error(`start failed: ${started.reason}`);
    const sql = (auth as unknown as { ctx: { storage: { sql: Sql } } }).ctx.storage.sql;
    const pending = auth.approveTierEnrolment(approval(started.userCode, "approver-a"));
    interleave(sql, started.userCode);
    const result = await pending;
    const row = sql
      .exec("SELECT status, principal_id FROM tier_enrolments WHERE user_code = ?", started.userCode)
      .toArray()[0] as { status: string; principal_id: string | null };
    return { result, row };
  });
}

describe("approveTierEnrolment: the guarded UPDATE's row count decides the answer", () => {
  it("refuses when the enrolment is revoked between the read and the write", async () => {
    const { result, row } = await raceApprove("tier-approve-race-revoke", (sql, userCode) => {
      sql.exec("UPDATE tier_enrolments SET status = 'revoked' WHERE user_code = ?", userCode);
    });
    expect(row.status, "the revoke stood").toBe("revoked");
    expect(result).toEqual({ ok: false, reason: "not_pending" });
  });

  it("refuses when a second approval wins the window, and keeps the winner's binding", async () => {
    const { result, row } = await raceApprove("tier-approve-race-double", (sql, userCode) => {
      sql.exec(
        "UPDATE tier_enrolments SET status = 'approved', principal_id = 'approver-b' WHERE user_code = ? AND status = 'pending'",
        userCode,
      );
    });
    expect(row.principal_id, "the first approval's binding is not overwritten").toBe("approver-b");
    expect(result).toEqual({ ok: false, reason: "not_pending" });
  });

  it("refuses when the enrolment expires in the window, and leaves it pending", async () => {
    const { result, row } = await raceApprove("tier-approve-race-expiry", (sql, userCode) => {
      sql.exec("UPDATE tier_enrolments SET expires_at = 1 WHERE user_code = ?", userCode);
    });
    expect(row.status, "an expired enrolment is not approved").toBe("pending");
    expect(result).toEqual({ ok: false, reason: "expired" });
  });

  it("still approves when nothing interleaves (control)", async () => {
    const { result, row } = await raceApprove("tier-approve-race-control", () => {});
    expect(result).toEqual({ ok: true });
    expect(row).toEqual({ status: "approved", principal_id: "approver-a" });
  });
});
