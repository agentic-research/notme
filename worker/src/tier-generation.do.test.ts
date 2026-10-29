/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * tier-generation.do.test.ts — a copied machine key renewing is a fork
 * (notme-747cc7, mint path phase 1).
 *
 * THE CASE. Renewal by proof of possession (notme-337d82) means anyone who
 * copies a machine's tier key can renew it too, forever, unnoticed. Renewal
 * binding v2 commits to a GENERATION counter the authority keeps per
 * enrollment: each accepted renewal at generation g moves the counter to g+1.
 * Two holders of one key cannot both keep up — the second to renew at g
 * presents a stale generation, and that is a fork: the enrollment is shut off.
 *
 * WHAT MUST NOT BE A FORK. An honest machine that lost a renewal response
 * resends the EXACT same request (same iat, same generation, same digest);
 * that is a retry and mints again. A replay of an accepted request, or an old
 * request past the retry window, is stale — refused, never revoked. A proof
 * that does not verify changes nothing at all.
 */
import worker from "../worker";
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { createSessionCookie } from "./auth/session";
import {
  tierEnrolmentBinding,
  deviceCodeHash,
  tierRenewalBindingV2,
  renewalRequestDigest,
} from "./auth/tier-enrolment-binding";
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

type Machine = { kp: CryptoKeyPair; spki: Uint8Array; pem: string };

async function machine(): Promise<Machine> {
  const kp = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = new Uint8Array((await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer);
  const pem = `-----BEGIN PUBLIC KEY-----\n${btoa(String.fromCharCode(...spki)).match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
  return { kp, spki, pem };
}

async function human(scopes = ["bridgeCert", "certMint"]) {
  const pid = `gen-${crypto.randomUUID()}`;
  await authority().createPrincipalWithCapabilities(pid, scopes);
  const cookie = await createSessionCookie({ principalId: pid, scopes, authMethod: "passkey" }, await authority().getSessionSecret());
  return { pid, cookie };
}

/** Enroll a machine end to end; returns its key and the collected tier. */
async function enrolled() {
  const m = await machine();
  const start = (await (await post("/cert/issuing-ca/device", { public_key: m.pem })).json()) as { device_code: string; user_code: string };
  const h = await human();
  const ap = await post("/cert/issuing-ca/device/approve", { user_code: start.user_code }, { cookie: h.cookie });
  expect(ap.status, await ap.clone().text()).toBe(200);
  const proof = b64u(new Uint8Array(await crypto.subtle.sign(ED25519, m.kp.privateKey, tierEnrolmentBinding(m.spki, await deviceCodeHash(start.device_code)))));
  const tok = await post("/cert/issuing-ca/device/token", { device_code: start.device_code, proof });
  expect(tok.status, await tok.clone().text()).toBe(200);
  return { m, h, tier: (await tok.json()) as { certificate: string; renew_until: number; generation?: number } };
}

const nowS = () => Math.floor(Date.now() / 1000);

/** A v2 renewal request body, signed but not sent. */
async function renewalBody(m: Machine, generation: number, iat = nowS(), key = m.kp.privateKey) {
  const proof = b64u(new Uint8Array(await crypto.subtle.sign(ED25519, key, tierRenewalBindingV2(m.spki, iat, generation))));
  return { public_key: m.pem, iat, generation, proof };
}

const send = (body: unknown) => post("/cert/issuing-ca/renew", body);

async function renew(m: Machine, generation: number, iat = nowS(), key = m.kp.privateKey) {
  return send(await renewalBody(m, generation, iat, key));
}

const fp = async (spki: Uint8Array) =>
  Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", spki))).map((b) => b.toString(16).padStart(2, "0")).join("");

/** The enrollment row as the authority holds it. */
async function rowOf(m: Machine) {
  const f = await fp(m.spki);
  return runInDurableObject(authority(), (a) =>
    (a as SigningAuthority)["ctx"].storage.sql
      .exec("SELECT generation, revoked_at, revoke_reason FROM tier_enrolments WHERE key_fingerprint = ? AND status = 'active'", f)
      .toArray()[0] as { generation: number; revoked_at: number | null; revoke_reason: string | null },
  );
}

async function expectOk(res: Response, generation: number) {
  expect(res.status, await res.clone().text()).toBe(200);
  expect(await res.json()).toMatchObject({ generation });
}

async function expectErr(res: Response, status: number, error: string) {
  expect(res.status, await res.clone().text()).toBe(status);
  expect(await res.json()).toMatchObject({ error });
}

describe("generations advance on each renewal", () => {
  it("a fresh enrollment collects at generation 0 and renews 0 → 1 → 2", async () => {
    const { m, tier } = await enrolled();
    expect(tier.generation).toBe(0);
    await expectOk(await renew(m, 0), 1);
    await expectOk(await renew(m, 1), 2);
    expect((await rowOf(m)).generation).toBe(2);
  });
});

describe("a copy renewing is a fork", () => {
  it("a copy that renews second is a fork, and the enrollment is shut off", async () => {
    const { m } = await enrolled();
    const t = nowS();
    await expectOk(await renew(m, 0, t), 1);
    // The copy holds the same key and the same generation, but signs its own
    // request: a different iat, so a different digest.
    await expectErr(await renew(m, 0, t + 1), 403, "fork_detected");
    const row = await rowOf(m);
    expect(row.revoked_at).not.toBeNull();
    expect(row.revoke_reason).toBe("fork_detected");
    // The original is shut off too: nobody can tell which holder is honest.
    await expectErr(await renew(m, 1), 403, "fork_detected");
  });

  it("a freshly signed request at current-1 is a fork, not a retry", async () => {
    const { m } = await enrolled();
    const t = nowS();
    await expectOk(await renew(m, 0, t), 1);
    await expectErr(await renew(m, 0, t + 1), 403, "fork_detected");
  });

  it("two concurrent renewals at the same generation: one wins, one forks", async () => {
    const { m } = await enrolled();
    const t = nowS();
    const [a, b] = await Promise.all([renew(m, 0, t), renew(m, 0, t + 1)]);
    expect([a.status, b.status].sort()).toEqual([200, 403]);
    expect((await rowOf(m)).generation).toBe(1);
  });

  it("the claim is guarded: a renewal that read the counter before a rival claimed it forks", async () => {
    // Review Focus 3, deterministically. Two requests at g may both read the
    // counter at g before either claims it (renewTier awaits in between).
    // Open that window on purpose: the rival claims g while this request is
    // past its read and before its claim. Only the `generation = ?` guard on
    // the claim stops both from winning.
    const { m } = await enrolled();
    const f = await fp(m.spki);
    const t = nowS();
    const ours = await renewalBody(m, 0, t);
    const rivalDigest = await renewalRequestDigest(tierRenewalBindingV2(m.spki, t + 1, 0));
    const r = await runInDurableObject(authority(), async (a) => {
      const sa = a as SigningAuthority & { getPrincipalScopes: SigningAuthority["getPrincipalScopes"] };
      const sql = sa["ctx"].storage.sql;
      const orig = sa.getPrincipalScopes.bind(sa);
      sa.getPrincipalScopes = async (pid: string) => {
        sql.exec("UPDATE tier_enrolments SET generation = 1 WHERE key_fingerprint = ? AND status = 'active'", f);
        sql.exec("INSERT INTO tier_renewal_digests (key_fingerprint, generation, digest, iat) VALUES (?, 0, ?, ?)", f, rivalDigest, t + 1);
        return orig(pid);
      };
      try {
        return await sa.renewTier({ publicKeyPem: m.pem, iat: ours.iat, proof: ours.proof, generation: 0 });
      } finally {
        delete (sa as { getPrincipalScopes?: unknown }).getPrincipalScopes;
      }
    });
    expect(r).toMatchObject({ ok: false, reason: "fork_detected" });
    const row = await rowOf(m);
    expect(row.generation).toBe(1);
    expect(row.revoke_reason).toBe("fork_detected");
  });
});

describe("what is not a fork", () => {
  it("a lost response: resending the exact request is a retry, not a fork", async () => {
    const { m } = await enrolled();
    const body = await renewalBody(m, 0);
    expect((await send(body)).status).toBe(200); // response "lost"
    await expectOk(await send(body), 1);
    expect((await rowOf(m)).generation).toBe(1);
    await expectOk(await renew(m, 1), 2);
  });

  it("an exact resend after the retry window is stale, not a fork", async () => {
    const { m } = await enrolled();
    const f = await fp(m.spki);
    const iat = nowS() - 3601;
    const body = await renewalBody(m, 0, iat);
    const digest = await renewalRequestDigest(tierRenewalBindingV2(m.spki, iat, 0));
    // As if generation 0 was accepted an hour and a second ago.
    await runInDurableObject(authority(), (a) => {
      const sql = (a as SigningAuthority)["ctx"].storage.sql;
      sql.exec("INSERT INTO tier_renewal_digests (key_fingerprint, generation, digest, iat) VALUES (?, 0, ?, ?)", f, digest, iat);
      sql.exec("UPDATE tier_enrolments SET generation = 1 WHERE key_fingerprint = ?", f);
    });
    await expectErr(await send(body), 401, "stale_proof");
    expect((await rowOf(m)).revoked_at).toBeNull();
  });

  it("an old request nobody accepted, at a spent generation, is stale, not a fork", async () => {
    // A copy's request that sat unsent past the skew: it cannot be told from
    // a delayed replay, so it is refused and nothing is revoked.
    const { m } = await enrolled();
    await expectOk(await renew(m, 0), 1);
    await expectErr(await renew(m, 0, nowS() - 600), 401, "stale_proof");
    expect((await rowOf(m)).revoked_at).toBeNull();
    await expectOk(await renew(m, 1), 2);
  });

  it("a replayed request with a stale generation does not revoke", async () => {
    // Review Focus 1: a replay of an ACCEPTED request is not a fork, however
    // fresh its timestamp still is — only a request nobody accepted can be.
    const { m } = await enrolled();
    const gen0 = await renewalBody(m, 0);
    await expectOk(await send(gen0), 1);
    await expectOk(await renew(m, 1), 2);
    await expectErr(await send(gen0), 401, "stale_proof");
    expect((await rowOf(m)).revoked_at).toBeNull();
    await expectOk(await renew(m, 2), 3);
  });

  it("an invalid proof at a stale generation changes nothing", async () => {
    // Review Focus 2: anyone can POST a stale generation for a public key.
    // Without the key's signature it must not shut the enrollment off.
    const { m } = await enrolled();
    await expectOk(await renew(m, 0), 1);
    const thief = await machine();
    await expectErr(await renew(m, 0, nowS() + 1, thief.kp.privateKey), 401, "invalid_proof");
    const row = await rowOf(m);
    expect(row.generation).toBe(1);
    expect(row.revoked_at).toBeNull();
  });

  it("a generation ahead of the authority is stale, never revoked", async () => {
    const { m } = await enrolled();
    await expectErr(await renew(m, 5), 401, "stale_proof");
    expect((await rowOf(m)).revoked_at).toBeNull();
    await expectOk(await renew(m, 0), 1);
  });
});
