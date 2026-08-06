/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * challenge-freshness.do.test.ts — a WebAuthn REGISTRATION challenge must
 * expire on the same clock as an authentication challenge (notme-addef9, from
 * the identity audit's N5).
 *
 * The two sibling lookups in auth/passkey.ts disagree:
 *
 *   authentication: WHERE challenge = ? AND type='authentication'
 *                     AND created_at > datetime('now','-5 minutes')
 *   registration:   WHERE user_id  = ? AND type='registration'
 *
 * So a registration challenge stayed valid until the one-hour sweep — a
 * twelve-fold longer replay window than its sibling, and with no ORDER BY, an
 * arbitrary pick when several exist. The challenge is a fresh unguessable
 * server value, so this is not remotely exploitable on its own; it is an
 * unintended asymmetry between two functions that should agree, which is
 * exactly the kind of thing that stops being harmless when something else
 * leaks.
 *
 * TESTING IT WITHOUT A REAL AUTHENTICATOR: the challenge lookup runs BEFORE
 * any attestation verification, so an expired challenge must be rejected with
 * "no pending registration challenge" rather than reaching — and failing in —
 * the attestation code. Asserting on WHICH failure occurs is what makes this a
 * test of freshness rather than a test that garbage input fails.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { SigningAuthority } from "./signing-authority";

/** Insert a registration challenge with a chosen age, bypassing the route. */
async function seedChallenge(name: string, userId: string, ageMinutes: number) {
  const stub = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(name));
  await runInDurableObject(stub, async (auth) => {
    const a = auth as SigningAuthority;
    const sql = (a as any).ctx.storage.sql;
    const { ensurePasskeySchema } = await import("./auth/passkey");
    ensurePasskeySchema(sql);
    sql.exec(
      "INSERT INTO passkey_challenges (user_id, challenge, type, created_at) VALUES (?, ?, 'registration', datetime('now', ?))",
      userId,
      "seeded-challenge-value",
      `-${ageMinutes} minutes`,
    );
  });
  return stub;
}

/** Drive the real verify path and report which failure occurred. */
async function verifyAndClassify(
  stub: any,
  userId: string,
): Promise<"no-challenge" | "other"> {
  try {
    await stub.passkeyVerifyRegistration(
      userId,
      "test user",
      { id: "x", rawId: "x", response: {}, type: "public-key" },
      "notme.bot",
      "https://notme.bot",
    );
    return "other"; // returned without throwing — not the freshness path
  } catch (e: any) {
    return /no pending registration challenge/i.test(e?.message ?? "")
      ? "no-challenge"
      : "other";
  }
}

describe("registration challenge freshness (notme-addef9 / audit N5)", () => {
  it("rejects a registration challenge older than the 5-minute window", async () => {
    const stub = await seedChallenge("chal-stale", "user-stale", 10);
    expect(await verifyAndClassify(stub, "user-stale")).toBe("no-challenge");
  });

  it("still accepts a FRESH challenge — the window narrows, it does not close", async () => {
    // A fresh challenge must get PAST the lookup and fail later, in the
    // attestation code, on the garbage response. If this returned
    // "no-challenge" the fix would have broken registration outright.
    const stub = await seedChallenge("chal-fresh", "user-fresh", 1);
    expect(await verifyAndClassify(stub, "user-fresh")).toBe("other");
  });

  it("agrees with the authentication sibling's window", async () => {
    // The point is not the exact number, it is that the two lookups use the
    // same one. Just outside it must fail; just inside must not.
    const stale = await seedChallenge("chal-6m", "user-6m", 6);
    expect(await verifyAndClassify(stale, "user-6m")).toBe("no-challenge");
    const fresh = await seedChallenge("chal-4m", "user-4m", 4);
    expect(await verifyAndClassify(fresh, "user-4m")).toBe("other");
  });
});
