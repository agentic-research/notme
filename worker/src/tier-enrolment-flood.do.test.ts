/// <reference types="@cloudflare/vitest-plugin/types" />
/**
 * tier-enrolment-flood.do.test.ts — an unauthenticated flood cannot keep
 * machine enrolment "busy" (notme-a36d10, overnight review H1).
 *
 * THE DEFECT. `POST /cert/issuing-ca/device` needs no login and had no
 * limiter. Every call wrote a pending `tier_enrolments` row, and the only
 * bound was one GLOBAL cap of 500 in-flight rows. 500 calls every 10 minutes
 * (0.83 rps, far under the WAF threshold) held the cap, and every honest
 * machine then got 503 "busy".
 *
 * THE FIX, three layers:
 *  1. a pre-DO CERT_LIMITER key `enrol-ip:<ip bucket>` (10 / 60 s), so one
 *     address cannot reach the singleton at volume;
 *  2. a per-SOURCE cap inside the DO, by network (IPv4 /24, IPv6 /48), far
 *     below the global cap, so one network cannot hold it;
 *  3. fair-share eviction when the global cap IS full (a distributed flood):
 *     a source holding fewer rows than the busiest one evicts that source's
 *     oldest PENDING row. A newcomer (0 rows) always gets in; only an
 *     approved or collecting row, which a human vetted, is never evicted.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../worker";
import { ED25519 } from "./platform";
import type { SigningAuthority } from "./signing-authority";
import { TIER_ENROLMENT_CAP, TIER_ENROLMENT_PER_SOURCE_CAP } from "./signing-authority";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };

async function pem(): Promise<string> {
  const kp = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = new Uint8Array((await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer);
  return `-----BEGIN PUBLIC KEY-----\n${btoa(String.fromCharCode(...spki)).match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
}

/** A fresh authority per test, so caps filled here touch no other suite. */
const freshAuthority = () =>
  env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(`flood-${crypto.randomUUID()}`)) as unknown as
    DurableObjectStub<SigningAuthority>;

const inFlight = (auth: DurableObjectStub<SigningAuthority>) =>
  runInDurableObject(auth, (_i, state) =>
    [...state.storage.sql.exec<{ n: number }>(
      "SELECT COUNT(*) AS n FROM tier_enrolments WHERE status IN ('pending', 'approved', 'collecting')",
    )][0]!.n,
  );

/**
 * Fill the global cap the way a distributed flood would — sources of
 * TIER_ENROLMENT_PER_SOURCE_CAP rows each, oldest first — by writing the rows
 * directly. 500 RPCs would test nothing more and take seconds under load. The
 * first row goes through startTierEnrolment, so the schema is the real one.
 */
async function fillGlobalCap(auth: DurableObjectStub<SigningAuthority>, key: string, prefix: string) {
  const first = await auth.startTierEnrolment({ publicKeyPem: key, requestedScopes: ["bridgeCert"], source: `${prefix}-0` });
  if (!first.ok) throw new Error("seed refused");
  await runInDurableObject(auth, (_i, state) => {
    const now = Math.floor(Date.now() / 1000);
    for (let i = 1; i < TIER_ENROLMENT_CAP; i++) {
      state.storage.sql.exec(
        `INSERT INTO tier_enrolments
           (device_code_hash, user_code, public_key_pem, key_fingerprint, requested_scopes, status, expires_at, source)
         VALUES (?, ?, ?, 'fp', '["bridgeCert"]', 'pending', ?, ?)`,
        `fill-${i}`, `FILL-${i}`, key, now + 600 - (TIER_ENROLMENT_CAP - i),
        `${prefix}-${Math.floor(i / TIER_ENROLMENT_PER_SOURCE_CAP)}`,
      );
    }
  });
}

describe("one source cannot fill the global enrolment cap", () => {
  it("tier.enrol.per-source-cap — is refused at its per-source cap, far below the global cap, and a second source still enrols", async () => {
    // The caps are ordered as the design needs: per-source well under global.
    expect(TIER_ENROLMENT_PER_SOURCE_CAP * 10).toBeLessThanOrEqual(TIER_ENROLMENT_CAP);
    const auth = freshAuthority();
    const key = await pem(); // one key is fine: the table does not dedupe pending keys
    let accepted = 0;
    let refusal: string | undefined;
    for (let i = 0; i < TIER_ENROLMENT_CAP + 1; i++) {
      const r = await auth.startTierEnrolment({ publicKeyPem: key, requestedScopes: ["bridgeCert"], source: "203.0.113.0/24" });
      if (!r.ok) {
        refusal = r.reason;
        break;
      }
      accepted++;
    }
    expect(accepted).toBe(TIER_ENROLMENT_PER_SOURCE_CAP);
    expect(refusal).toBe("source_busy");

    const other = await auth.startTierEnrolment({ publicKeyPem: key, requestedScopes: ["bridgeCert"], source: "198.51.100.0/24" });
    expect(other.ok).toBe(true);
  });
});

describe("a distributed flood that fills the global cap", () => {
  it("tier.enrol.fair-eviction — still lets a NEW source enrol, by evicting the busiest source's oldest pending row", async () => {
    const auth = freshAuthority();
    const key = await pem();
    await fillGlobalCap(auth, key, "flood");
    expect(await inFlight(auth)).toBe(TIER_ENROLMENT_CAP);

    // The operator, from a network the flood does not hold, still enrols.
    const operator = await auth.startTierEnrolment({ publicKeyPem: key, requestedScopes: ["bridgeCert"], source: "operator" });
    expect(operator.ok).toBe(true);
    // ...and the table did not grow past the cap to admit it.
    expect(await inFlight(auth)).toBe(TIER_ENROLMENT_CAP);

    // A flood source already at the busiest level evicts nobody to get in:
    // it is refused, so it cannot recycle the operator's slot out.
    const again = await auth.startTierEnrolment({ publicKeyPem: key, requestedScopes: ["bridgeCert"], source: "flood-1" });
    expect(again.ok).toBe(false);
    if (operator.ok) expect(await auth.getTierEnrolment(operator.userCode)).not.toBeNull();
  });

  it("tier.enrol.no-approved-eviction — never evicts an approved row: with only approved rows left to take, a newcomer is refused", async () => {
    const auth = freshAuthority();
    const key = await pem();
    await fillGlobalCap(auth, key, "src");
    const codes = await runInDurableObject(auth, (_i, state) =>
      [...state.storage.sql.exec<{ user_code: string }>("SELECT user_code FROM tier_enrolments LIMIT 3")].map((r) => r.user_code),
    );
    await runInDurableObject(auth, (_i, state) => {
      state.storage.sql.exec("UPDATE tier_enrolments SET status = 'approved' WHERE status = 'pending'");
    });
    const newcomer = await auth.startTierEnrolment({ publicKeyPem: key, requestedScopes: ["bridgeCert"], source: "newcomer" });
    expect(newcomer).toEqual({ ok: false, reason: "busy" });
    for (const c of codes) expect((await auth.getTierEnrolment(c))?.status).toBe("approved");
  });
});

describe("the route limits per IP before the DO, and charges the DO by network", () => {
  function limiter(allow: (key: string) => boolean) {
    const keys: string[] = [];
    return { keys, binding: { limit: async ({ key }: { key: string }) => (keys.push(key), { success: allow(key) }) } };
  }
  const start = async (ip: string, extra: Record<string, unknown>) =>
    worker.fetch(
      new Request(`${ORIGIN}/cert/issuing-ca/device`, {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": ip },
        body: JSON.stringify({ public_key: await pem() }),
      }),
      { ...env, ...LOCAL_ENV, ...extra } as never,
    );

  it("tier.enrol.ip-limited — 429s on the enrol-ip limiter, keyed by the client's IP bucket", async () => {
    const lim = limiter(() => false);
    const res = await start("2001:db8:1:2:3:4:5:6", { CERT_LIMITER: lim.binding });
    expect(res.status).toBe(429);
    expect(lim.keys).toEqual(["enrol-ip:2001:db8:1:2::/64"]);
  });

  it("tier.enrol.per-source-cap — passes when the limiter allows, and a network at its cap gets 429, not the global 503", async () => {
    const lim = limiter(() => true);
    const ns = env.SIGNING_AUTHORITY;
    const name = `flood-route-${crypto.randomUUID()}`;
    const SA = { idFromName: () => ns.idFromName(name), get: (id: DurableObjectId) => ns.get(id) };
    const statuses: number[] = [];
    for (let i = 0; i < TIER_ENROLMENT_PER_SOURCE_CAP + 1; i++) {
      // Different hosts in ONE /24: one network, one DO bucket.
      statuses.push((await start(`192.0.2.${i + 1}`, { CERT_LIMITER: lim.binding, SIGNING_AUTHORITY: SA })).status);
    }
    expect(statuses.slice(0, -1).every((s) => s === 200)).toBe(true);
    expect(statuses.at(-1)).toBe(429);
    // Another network is unaffected.
    expect((await start("198.51.100.7", { CERT_LIMITER: lim.binding, SIGNING_AUTHORITY: SA })).status).toBe(200);
  });
});
