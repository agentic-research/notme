/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * tier-renewal.do.test.ts — a paused machine resumes without a human
 * (notme-337d82).
 *
 * THE CASE. A VM pauses longer than its tier's lifetime (1 h by default, 24 h
 * at most) and resumes holding an expired tier. Before renewal existed the
 * only way back was a human passkey re-enrollment — an approved action,
 * blocked on a person.
 *
 * NOW. The human approves a RENEWAL HORIZON once (1 / 7 / 30 days, default 7).
 * Inside it, the machine renews by proof of possession of the tier key — no
 * secret, no human — and only while the approval still holds:
 *   not revoked · inside the horizon · the epoch has not moved (the mass-
 *   revocation lever still works) · the approver still holds certMint and the
 *   granted scopes live.
 * Renewal looks the enrollment up by KEY, so it never needs the old (expired)
 * tier certificate at all — which is the point.
 */
import worker from "../worker";
import { env, runInDurableObject } from "cloudflare:test";
import { X509Certificate } from "@peculiar/x509";
import { describe, expect, it } from "vitest";
import { createSessionCookie } from "./auth/session";
import { tierEnrolmentBinding, deviceCodeHash, tierRenewalBindingV2 } from "./auth/tier-enrolment-binding";
import { ED25519 } from "./platform";
import type { SigningAuthority } from "./signing-authority";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };
const call = (url: string, init: RequestInit = {}) =>
  (worker.fetch as (r: Request, e: unknown) => Promise<Response>)(new Request(url, init), { ...env, ...LOCAL_ENV });
const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  call(`${ORIGIN}${path}`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
const authority = () => env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
const b64u = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function machine() {
  const kp = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = new Uint8Array((await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer);
  const pem = `-----BEGIN PUBLIC KEY-----\n${btoa(String.fromCharCode(...spki)).match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
  return { kp, spki, pem };
}

async function human(scopes = ["bridgeCert", "certMint"]) {
  const pid = `renew-${crypto.randomUUID()}`;
  await authority().createPrincipalWithCapabilities(pid, scopes);
  const cookie = await createSessionCookie({ principalId: pid, scopes, authMethod: "passkey" }, await authority().getSessionSecret());
  return { pid, cookie };
}

/** Enroll a machine end to end; returns its key and the collected tier. */
async function enrolled(renewDays?: number) {
  const m = await machine();
  const start = (await (await post("/cert/issuing-ca/device", { public_key: m.pem })).json()) as { device_code: string; user_code: string };
  const h = await human();
  const ap = await post("/cert/issuing-ca/device/approve", { user_code: start.user_code, ...(renewDays ? { renew_days: renewDays } : {}) }, { cookie: h.cookie });
  expect(ap.status, await ap.clone().text()).toBe(200);
  const proof = b64u(new Uint8Array(await crypto.subtle.sign(ED25519, m.kp.privateKey, tierEnrolmentBinding(m.spki, await deviceCodeHash(start.device_code)))));
  const tok = await post("/cert/issuing-ca/device/token", { device_code: start.device_code, proof });
  expect(tok.status, await tok.clone().text()).toBe(200);
  const tier = (await tok.json()) as { certificate: string; renew_until: number; generation: number };
  generations.set(m, tier.generation);
  return { m, h, tier };
}

/** The generation each machine must sign next: from collect, then from each renewal. */
const generations = new WeakMap<object, number>();

/** A v2 renewal at the machine's current generation (0 if it never enrolled). */
async function renew(m: { kp: CryptoKeyPair; spki: Uint8Array; pem: string }, iat = Math.floor(Date.now() / 1000), key = m.kp.privateKey) {
  const generation = generations.get(m) ?? 0;
  const proof = b64u(new Uint8Array(await crypto.subtle.sign(ED25519, key, tierRenewalBindingV2(m.spki, iat, generation))));
  const res = await post("/cert/issuing-ca/renew", { public_key: m.pem, iat, generation, proof });
  if (res.status === 200) generations.set(m, ((await res.clone().json()) as { generation: number }).generation);
  return res;
}

const fp = async (spki: Uint8Array) =>
  Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", spki))).map((b) => b.toString(16).padStart(2, "0")).join("");

describe("approving a machine sets a renewal horizon", () => {
  it("defaults to 7 days", async () => {
    const { tier } = await enrolled();
    const days = (tier.renew_until - Date.now() / 1000) / 86400;
    expect(days).toBeGreaterThan(6.9);
    expect(days).toBeLessThanOrEqual(7.01);
  });

  it("accepts 1 and 30, and nothing else", async () => {
    expect((((await enrolled(1)).tier.renew_until - Date.now() / 1000) / 86400)).toBeLessThanOrEqual(1.01);
    expect((((await enrolled(30)).tier.renew_until - Date.now() / 1000) / 86400)).toBeGreaterThan(29.9);
    const m = await machine();
    const start = (await (await post("/cert/issuing-ca/device", { public_key: m.pem })).json()) as { user_code: string };
    const h = await human();
    expect((await post("/cert/issuing-ca/device/approve", { user_code: start.user_code, renew_days: 365 }, { cookie: h.cookie })).status).toBe(400);
  });
});

describe("renewal — the resumed machine, no human", () => {
  it("issues a fresh tier for the SAME key, identity and scopes", async () => {
    const { m, tier } = await enrolled();
    const res = await renew(m);
    expect(res.status, await res.clone().text()).toBe(200);
    const fresh = new X509Certificate(((await res.json()) as { certificate: string }).certificate);
    const old = new X509Certificate(tier.certificate);
    expect(new Uint8Array(fresh.publicKey.rawData)).toEqual(m.spki);
    expect(fresh.subject).toBe(old.subject);
    expect(fresh.serialNumber).not.toBe(old.serialNumber);
    expect(fresh.notAfter.getTime()).toBeLessThanOrEqual(tier.renew_until * 1000);
  });

  it("refuses a proof by a different key", async () => {
    const { m } = await enrolled();
    const thief = await machine();
    expect((await renew(m, undefined, thief.kp.privateKey)).status).toBe(401);
  });

  it("refuses a stale proof — the timestamp must be fresh", async () => {
    const { m } = await enrolled();
    expect((await renew(m, Math.floor(Date.now() / 1000) - 3600)).status).toBe(401);
  });

  it("refuses a key that was never enrolled", async () => {
    expect((await renew(await machine())).status).toBe(404);
  });

  it("refuses once the horizon has passed — then a human must re-approve", async () => {
    const { m } = await enrolled();
    const f = await fp(m.spki);
    await runInDurableObject(authority(), (a) => {
      (a as SigningAuthority)["ctx"].storage.sql.exec("UPDATE tier_enrolments SET renew_until = 0 WHERE key_fingerprint = ?", f);
    });
    const res = await renew(m);
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: "horizon_passed" });
  });

  it("refuses after the epoch moves — mass revocation still reaches machines", async () => {
    const { m } = await enrolled();
    await authority().revokeEpoch();
    const res = await renew(m);
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: "epoch_changed" });
  });

  it("refuses after the approver loses certMint", async () => {
    const { m, h } = await enrolled();
    await authority().revokeCapability(h.pid, "certMint", "test");
    const res = await renew(m);
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: "approval_withdrawn" });
  });
});

describe("an enrollment outlives its device code", () => {
  it("is not pruned when its device code expires and someone else enrolls", async () => {
    // startTierEnrolment prunes expired device codes. If it pruned ACTIVE
    // enrollments too, renewal would silently stop ten minutes after
    // collection — the first time any other machine enrolled.
    const { m } = await enrolled();
    const f = await fp(m.spki);
    await runInDurableObject(authority(), (a) => {
      (a as SigningAuthority)["ctx"].storage.sql.exec("UPDATE tier_enrolments SET expires_at = 0 WHERE key_fingerprint = ?", f);
    });
    const other = await machine();
    expect((await post("/cert/issuing-ca/device", { public_key: other.pem })).status).toBe(200);
    expect((await renew(m)).status).toBe(200);
  });
});

describe("a human can see and revoke their machines", () => {
  it("lists the approver's enrollments", async () => {
    const { m, h } = await enrolled();
    const res = await call(`${ORIGIN}/cert/issuing-ca/enrollments`, { headers: { cookie: h.cookie } });
    expect(res.status).toBe(200);
    const list = (await res.json()) as Array<{ key_fingerprint: string; status: string }>;
    expect(list.map((e) => e.key_fingerprint)).toContain(await fp(m.spki));
  });

  it("revoking an enrollment stops its renewals", async () => {
    const { m, h } = await enrolled();
    const r = await post("/cert/issuing-ca/enrollments/revoke", { key_fingerprint: await fp(m.spki) }, { cookie: h.cookie });
    expect(r.status).toBe(200);
    const res = await renew(m);
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: "revoked" });
  });

  it("another user cannot revoke someone else's machine", async () => {
    const { m } = await enrolled();
    const other = await human(["bridgeCert"]);
    expect((await post("/cert/issuing-ca/enrollments/revoke", { key_fingerprint: await fp(m.spki) }, { cookie: other.cookie })).status).toBe(404);
    expect((await renew(m)).status).toBe(200);
  });

  it("an administrator can revoke any machine", async () => {
    const { m } = await enrolled();
    const admin = await human(["bridgeCert", "authorityManage", "certMint"]);
    expect((await post("/cert/issuing-ca/enrollments/revoke", { key_fingerprint: await fp(m.spki) }, { cookie: admin.cookie })).status).toBe(200);
    expect((await renew(m)).status).toBe(403);
  });
});
