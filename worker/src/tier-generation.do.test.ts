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
  tierRenewalBindingV3,
  tierRenewalBinding,
  tierEnrolmentId,
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
async function enrolled(m?: Machine, renewDays?: number) {
  m ??= await machine();
  const start = (await (await post("/cert/issuing-ca/device", { public_key: m.pem })).json()) as { device_code: string; user_code: string };
  const h = await human();
  const ap = await post("/cert/issuing-ca/device/approve", { user_code: start.user_code, ...(renewDays ? { renew_days: renewDays } : {}) }, { cookie: h.cookie });
  expect(ap.status, await ap.clone().text()).toBe(200);
  const proof = b64u(new Uint8Array(await crypto.subtle.sign(ED25519, m.kp.privateKey, tierEnrolmentBinding(m.spki, await deviceCodeHash(start.device_code)))));
  const tok = await post("/cert/issuing-ca/device/token", { device_code: start.device_code, proof });
  expect(tok.status, await tok.clone().text()).toBe(200);
  return {
    m,
    h,
    deviceCode: start.device_code,
    tier: (await tok.json()) as { certificate: string; renew_until: number; generation?: number; enrollment_id: string },
  };
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

const unhex = (s: string) => Uint8Array.from(s.match(/../g)!, (h) => parseInt(h, 16));

/** A v3 renewal request body (notme-c9fc8c): v2 plus the enrollment id. */
async function renewalBodyV3(m: Machine, enrollmentId: string, generation: number, iat = nowS(), key = m.kp.privateKey) {
  const binding = tierRenewalBindingV3(m.spki, iat, generation, unhex(enrollmentId));
  const proof = b64u(new Uint8Array(await crypto.subtle.sign(ED25519, key, binding)));
  return { public_key: m.pem, iat, generation, enrollment_id: enrollmentId, proof };
}

async function renewV3(m: Machine, enrollmentId: string, generation: number, iat = nowS(), key = m.kp.privateKey) {
  return send(await renewalBodyV3(m, enrollmentId, generation, iat, key));
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

  it("the human's enrollment list says why a forked machine stopped", async () => {
    const { m, h } = await enrolled();
    const list = async () =>
      (await (await call(`${ORIGIN}/cert/issuing-ca/enrollments`, { headers: { cookie: h.cookie } })).json()) as Array<{
        revoked_at: number | null;
        revoke_reason: string | null;
      }>;
    const before = await list();
    expect(before).toHaveLength(1);
    expect(before[0]).toHaveProperty("revoke_reason", null);
    const t = nowS();
    await expectOk(await renew(m, 0, t), 1);
    await expectErr(await renew(m, 0, t + 1), 403, "fork_detected");
    const [after] = await list();
    expect(after.revoked_at).not.toBeNull();
    expect(after.revoke_reason).toBe("fork_detected");
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

  it("an invalid proof at the current generation leaves the counter alone", async () => {
    const { m } = await enrolled();
    await expectOk(await renew(m, 0), 1);
    const thief = await machine();
    await expectErr(await renew(m, 1, nowS(), thief.kp.privateKey), 401, "invalid_proof");
    const row = await rowOf(m);
    expect(row.generation).toBe(1);
    expect(row.revoked_at).toBeNull();
    await expectOk(await renew(m, 1), 2);
  });

  it("a request that never arrived, resent 121 s and 3599 s later at the current generation, renews", async () => {
    // The honest machine was offline (or met a 5xx or 429): its saved request
    // is resent byte for byte with its original iat, past the 120 s skew.
    const { m } = await enrolled();
    await expectOk(await send(await renewalBody(m, 0, nowS() - 121)), 1);
    await expectOk(await send(await renewalBody(m, 1, nowS() - 3599)), 2);
    const row = await rowOf(m);
    expect(row.generation).toBe(2);
    expect(row.revoked_at).toBeNull();
  });

  it("a request older than the retry window at the current generation is stale, not revoked", async () => {
    const { m } = await enrolled();
    await expectErr(await send(await renewalBody(m, 0, nowS() - 3601)), 401, "stale_proof");
    const row = await rowOf(m);
    expect(row.generation).toBe(0);
    expect(row.revoked_at).toBeNull();
    await expectOk(await renew(m, 0), 1);
  });

  it("an iat beyond the skew ahead is stale at the current generation", async () => {
    const { m } = await enrolled();
    await expectErr(await send(await renewalBody(m, 0, nowS() + 121)), 401, "stale_proof");
    expect((await rowOf(m)).generation).toBe(0);
  });

  it("a generation ahead of the authority is stale, never revoked", async () => {
    const { m } = await enrolled();
    await expectErr(await renew(m, 5), 401, "stale_proof");
    expect((await rowOf(m)).revoked_at).toBeNull();
    await expectOk(await renew(m, 0), 1);
  });
});

describe("re-enrolling a key", () => {
  /** Every row this key has ever had, oldest first. */
  async function rowsOf(m: Machine) {
    const f = await fp(m.spki);
    return runInDurableObject(authority(), (a) =>
      (a as SigningAuthority)["ctx"].storage.sql
        .exec("SELECT status, generation, revoked_at, renew_until FROM tier_enrolments WHERE key_fingerprint = ? ORDER BY rowid", f)
        .toArray() as Array<{ status: string; generation: number; revoked_at: number | null; renew_until: number }>,
    );
  }

  it("re-enrolling the same key supersedes the old enrollment; renewal counts the new one", async () => {
    // The old enrollment has the LONGER horizon, so a lookup that picked by
    // horizon would keep renewing against it — and read the new enrollment's
    // generation 0 as a fork of the old one's generation 2.
    const { m } = await enrolled(undefined, 30);
    await expectOk(await renew(m, 0), 1);
    await expectOk(await renew(m, 1), 2);
    const again = await enrolled(m, 1);
    expect(again.tier.generation).toBe(0);
    // A re-enrolled key speaks v3 only (notme-c9fc8c).
    await expectOk(await renewV3(m, again.tier.enrollment_id, 0), 1);
    const rows = await rowsOf(m);
    expect(rows.map((r) => r.status)).toEqual(["superseded", "active"]);
    expect(rows[0].revoked_at).toBeNull();
    expect(rows[1].generation).toBe(1);
  });

  it("re-enrolling after a fork recovers", async () => {
    // Re-enrollment is the documented recovery after a fork, so the revoked
    // enrollment must not keep hiding the new one.
    const { m } = await enrolled(undefined, 30);
    const t = nowS();
    await expectOk(await renew(m, 0, t), 1);
    await expectErr(await renew(m, 0, t + 1), 403, "fork_detected");
    const again = await enrolled(m, 1);
    await expectOk(await renewV3(m, again.tier.enrollment_id, 0), 1);
    expect((await rowsOf(m)).map((r) => r.status)).toEqual(["superseded", "active"]);
  });

  it("collect clears a re-enrolled key's digest rows", async () => {
    const { m } = await enrolled();
    await expectOk(await renew(m, 0), 1);
    await expectOk(await renew(m, 1), 2);
    const f = await fp(m.spki);
    const count = () =>
      runInDurableObject(authority(), (a) =>
        (a as SigningAuthority)["ctx"].storage.sql
          .exec<{ n: number }>("SELECT COUNT(*) AS n FROM tier_renewal_digests WHERE key_fingerprint = ?", f)
          .toArray()[0].n,
      );
    expect(await count()).toBe(2);
    await enrolled(m);
    expect(await count()).toBe(0);
  });
});

/** A v1 renewal request: no generation, v1 binding. */
async function renewV1(m: Machine, iat = nowS()) {
  const proof = b64u(new Uint8Array(await crypto.subtle.sign(ED25519, m.kp.privateKey, tierRenewalBinding(m.spki, iat))));
  return send({ public_key: m.pem, iat, proof });
}

describe("binding v1 is retired", () => {
  it("a new enrollment refuses v1 renewal, by its own name", async () => {
    // binding_v2_required, not invalid_proof: the client says "update task-cert", not "approval ended".
    const { m } = await enrolled();
    await expectErr(await renewV1(m), 400, "binding_v2_required");
    expect((await rowOf(m)).generation).toBe(0);
  });

  it("a legacy enrollment renews with v1 until its first v2 renewal", async () => {
    const { m } = await enrolled();
    const f = await fp(m.spki);
    await runInDurableObject(authority(), (a) => {
      (a as SigningAuthority)["ctx"].storage.sql.exec("UPDATE tier_enrolments SET binding_version = NULL WHERE key_fingerprint = ?", f);
    });
    expect((await renewV1(m)).status).toBe(200);
    await expectOk(await renew(m, 0), 1);
    await expectErr(await renewV1(m), 400, "binding_v2_required");
  });

  it("a legacy enrollment accepts a v1 request up to the retry window old", async () => {
    const { m } = await enrolled();
    const f = await fp(m.spki);
    await runInDurableObject(authority(), (a) => {
      (a as SigningAuthority)["ctx"].storage.sql.exec("UPDATE tier_enrolments SET binding_version = NULL WHERE key_fingerprint = ?", f);
    });
    expect((await renewV1(m, nowS() - 121)).status).toBe(200);
    expect((await renewV1(m, nowS() - 3599)).status).toBe(200);
    await expectErr(await renewV1(m, nowS() - 3601), 401, "stale_proof");
    expect((await rowOf(m)).revoked_at).toBeNull();
  });
});

describe("clone policy", () => {
  const startOne = async () => {
    const m = await machine();
    const start = (await (await post("/cert/issuing-ca/device", { public_key: m.pem })).json()) as { device_code: string; user_code: string };
    return { m, start };
  };
  const approveWith = (h: { cookie: string }, user_code: string, extra: Record<string, unknown>) =>
    post("/cert/issuing-ca/device/approve", { user_code, ...extra }, { cookie: h.cookie });
  const listOf = async (h: { cookie: string }) =>
    (await (await call(`${ORIGIN}/cert/issuing-ca/enrollments`, { headers: { cookie: h.cookie } })).json()) as Array<{ clone_policy: string; generation: number }>;
  const collect = async (m: Machine, device_code: string) => {
    const proof = b64u(new Uint8Array(await crypto.subtle.sign(ED25519, m.kp.privateKey, tierEnrolmentBinding(m.spki, await deviceCodeHash(device_code)))));
    return post("/cert/issuing-ca/device/token", { device_code, proof });
  };

  it("a plain approval is singleton", async () => {
    const { m, start } = await startOne();
    const h = await human();
    const ap = await approveWith(h, start.user_code, {});
    expect(ap.status).toBe(200);
    expect(((await ap.json()) as { clone_policy: string }).clone_policy).toBe("singleton");
    const tok = await collect(m, start.device_code);
    expect(((await tok.json()) as { clone_policy: string }).clone_policy).toBe("singleton");
    const rows = await listOf(h);
    expect(rows[0].clone_policy).toBe("singleton");
    expect(rows[0].generation).toBe(0);
  });

  it("replicas requires authorityManage", async () => {
    const a = await startOne();
    const weak = await human(["bridgeCert", "certMint"]);
    expect((await approveWith(weak, a.start.user_code, { clone_policy: "replicas:4", renew_days: 7 })).status).toBe(403);
    const b = await startOne();
    const strong = await human(["bridgeCert", "certMint", "authorityManage"]);
    const ap = await approveWith(strong, b.start.user_code, { clone_policy: "replicas:4", renew_days: 7 });
    expect(ap.status, await ap.clone().text()).toBe(200);
    expect(((await ap.json()) as { clone_policy: string }).clone_policy).toBe("replicas:4");
    await collect(b.m, b.start.device_code);
    expect((await listOf(strong))[0].clone_policy).toBe("replicas:4");
  });

  it("replicas needs LIVE authorityManage, not the cookie's", async () => {
    const a = await startOne();
    const h = await human(["bridgeCert", "certMint"]);
    // cookie claims authorityManage the principal does not hold
    const cookie = await createSessionCookie(
      { principalId: h.pid, scopes: ["bridgeCert", "certMint", "authorityManage"], authMethod: "passkey" },
      await authority().getSessionSecret(),
    );
    expect((await approveWith({ cookie }, a.start.user_code, { clone_policy: "replicas:2", renew_days: 7 })).status).toBe(403);
  });

  it("replicas allows at most a 7-day horizon", async () => {
    const strong = await human(["bridgeCert", "certMint", "authorityManage"]);
    const a = await startOne();
    expect((await approveWith(strong, a.start.user_code, { clone_policy: "replicas:2", renew_days: 30 })).status).toBe(400);
    expect((await approveWith(strong, a.start.user_code, { clone_policy: "replicas:2", renew_days: 7 })).status).toBe(200);
  });

  it("anything else is refused", async () => {
    const strong = await human(["bridgeCert", "certMint", "authorityManage"]);
    const a = await startOne();
    for (const bad of ["replicas:3", "many", ""]) {
      expect((await approveWith(strong, a.start.user_code, { clone_policy: bad })).status, bad).toBe(400);
    }
  });

  it("the enroll page offers the policy, singleton selected", async () => {
    const a = await startOne();
    const h = await human();
    const res = await call(`${ORIGIN}/enroll?code=${a.start.user_code}`, { headers: { cookie: h.cookie } });
    const html = await res.text();
    expect(html).toContain('id="clone"');
    expect(html).toContain('<option value="singleton" selected');
  });
});

// ── notme-c9fc8c ────────────────────────────────────────────────────────────

describe("a request from an earlier enrollment of the same key (notme-c9fc8c M4)", () => {
  /** Set the active row's generation, standing in for the new enrollment's honest renewals. */
  const setGeneration = async (m: Machine, g: number) => {
    const f = await fp(m.spki);
    await runInDurableObject(authority(), (a) => {
      (a as SigningAuthority)["ctx"].storage.sql.exec(
        "UPDATE tier_enrolments SET generation = ? WHERE key_fingerprint = ? AND status = 'active'",
        g,
        f,
      );
    });
  };

  it("cannot claim the re-enrollment's generation", async () => {
    const { m } = await enrolled();
    // Signed for the FIRST enrollment and captured (never sent, or sent and lost).
    const captured = await renewalBody(m, 0);
    const again = await enrolled(m); // the same key is enrolled again
    const res = await send(captured);
    expect(res.status, await res.clone().text()).not.toBe(200);
    // A re-enrolled key speaks v3 only: the v2 request is refused by name.
    expect(await res.json()).toMatchObject({ error: "binding_v3_required" });
    const row = await rowOf(m);
    expect(row.generation).toBe(0);
    expect(row.revoked_at).toBeNull();
    await expectOk(await renewV3(m, again.tier.enrollment_id, 0), 1);
  });

  it("cannot fork the re-enrollment", async () => {
    const { m } = await enrolled();
    const captured = await renewalBody(m, 0); // fresh: inside the 120 s fork window
    await enrolled(m);
    await setGeneration(m, 1); // the new enrollment's machine has renewed once
    const res = await send(captured);
    expect(res.status, await res.clone().text()).not.toBe(200);
    expect(await res.json()).toMatchObject({ error: "binding_v3_required" });
    const row = await rowOf(m);
    expect(row.revoked_at, "a request for another enrollment revoked this one").toBeNull();
    expect(row.generation).toBe(1);
  });

  it("a v3 request names its enrollment: one for the earlier enrollment changes nothing in the new one", async () => {
    const first = await enrolled();
    const { m } = first;
    await expectOk(await renewV3(m, first.tier.enrollment_id, 0), 1);
    const captured = await renewalBodyV3(m, first.tier.enrollment_id, 1); // never answered
    const again = await enrolled(m);
    expect(again.tier.enrollment_id).not.toBe(first.tier.enrollment_id);
    await setGeneration(m, 1);
    // Not this enrollment's request: as if the key had none. No claim, no fork.
    await expectErr(await send(captured), 404, "unknown_key");
    const row = await rowOf(m);
    expect(row.generation).toBe(1);
    expect(row.revoked_at).toBeNull();
    await expectOk(await renewV3(m, again.tier.enrollment_id, 1), 2);
  });
});

describe("binding v3 (notme-c9fc8c)", () => {
  /** binding_version as the authority holds it. */
  async function bindingOf(m: Machine) {
    const f = await fp(m.spki);
    return runInDurableObject(authority(), (a) =>
      ((a as SigningAuthority)["ctx"].storage.sql
        .exec("SELECT binding_version FROM tier_enrolments WHERE key_fingerprint = ? AND status = 'active'", f)
        .toArray()[0] as { binding_version: number | null }).binding_version,
    );
  }

  it("collect returns the enrollment id; it is derived from the device code and every renewal repeats it", async () => {
    const { m, tier, deviceCode } = await enrolled();
    const want = Array.from(await tierEnrolmentId(await deviceCodeHash(deviceCode)), (b) => b.toString(16).padStart(2, "0")).join("");
    expect(tier.enrollment_id).toBe(want);
    const r = await renew(m, 0); // v2: still accepted on a first-time key
    expect(r.status).toBe(200);
    expect(((await r.json()) as { enrollment_id: string }).enrollment_id).toBe(want);
  });

  it("a first-time key collects at v2, so a client that predates v3 keeps renewing", async () => {
    const { m } = await enrolled();
    expect(await bindingOf(m)).toBe(2);
    await expectOk(await renew(m, 0), 1);
    await expectOk(await renew(m, 1), 2);
    expect(await bindingOf(m)).toBe(2);
  });

  it("a re-enrolled key collects at v3", async () => {
    const { m } = await enrolled();
    await enrolled(m);
    expect(await bindingOf(m)).toBe(3);
  });

  it("v3 renews 0 -> 1 -> 2, and the first v3 renewal retires v2 and v1 for that enrollment", async () => {
    const { m, tier } = await enrolled();
    await expectOk(await renewV3(m, tier.enrollment_id, 0), 1);
    expect(await bindingOf(m)).toBe(3);
    await expectOk(await renewV3(m, tier.enrollment_id, 1), 2);
    await expectErr(await renew(m, 2), 400, "binding_v3_required");
    await expectErr(await renewV1(m), 400, "binding_v3_required");
    expect((await rowOf(m)).generation).toBe(2);
  });

  it("a legacy enrollment can move straight from v1 to v3", async () => {
    const { m } = await enrolled();
    const f = await fp(m.spki);
    await runInDurableObject(authority(), (a) => {
      (a as SigningAuthority)["ctx"].storage.sql.exec("UPDATE tier_enrolments SET binding_version = NULL WHERE key_fingerprint = ?", f);
    });
    const r = await renewV1(m);
    expect(r.status).toBe(200);
    const id = ((await r.json()) as { enrollment_id: string }).enrollment_id;
    await expectOk(await renewV3(m, id, 0), 1);
    expect(await bindingOf(m)).toBe(3);
  });

  it("a v3 lost response is a retry; a v3 copy is a fork: generations work as in v2", async () => {
    const { m, tier } = await enrolled();
    const body = await renewalBodyV3(m, tier.enrollment_id, 0);
    expect((await send(body)).status).toBe(200);
    await expectOk(await send(body), 1); // the same bytes: a retry
    const t = nowS();
    await expectOk(await renewV3(m, tier.enrollment_id, 1, t), 2);
    await expectErr(await renewV3(m, tier.enrollment_id, 1, t + 1), 403, "fork_detected");
  });

  it("a v3 proof never verifies as v2, nor with a malformed id", async () => {
    const { m, tier } = await enrolled();
    const v3 = await renewalBodyV3(m, tier.enrollment_id, 0);
    const { enrollment_id: _id, ...asV2 } = v3;
    await expectErr(await send(asV2), 401, "invalid_proof");
    for (const bad of ["", "zz", tier.enrollment_id.toUpperCase(), tier.enrollment_id.slice(2), 7]) {
      await expectErr(await send({ ...v3, enrollment_id: bad }), 401, "invalid_proof");
    }
    expect((await rowOf(m)).generation).toBe(0);
  });
});

describe("without the key, a refusal says nothing about the enrollment (notme-c9fc8c M3)", () => {
  /** A refusal's status and reason. */
  const refusalOf = async (res: Response) => ({ status: res.status, error: ((await res.json()) as { error: string }).error });

  async function legacy(m: Machine) {
    const f = await fp(m.spki);
    await runInDurableObject(authority(), (a) => {
      (a as SigningAuthority)["ctx"].storage.sql.exec("UPDATE tier_enrolments SET binding_version = NULL WHERE key_fingerprint = ?", f);
    });
  }

  /** A v1 body for m's public key with a proof m did not sign. */
  async function forgedV1(m: Machine, iat: number) {
    const thief = await machine();
    const proof = b64u(new Uint8Array(await crypto.subtle.sign(ED25519, thief.kp.privateKey, tierRenewalBinding(m.spki, iat))));
    return { public_key: m.pem, iat, proof };
  }

  for (const [label, iat] of [["a stale iat", () => nowS() - 7200], ["a fresh iat", () => nowS()]] as const) {
    it(`a forged v1 request with ${label} reads the same on a v2 enrollment, a legacy one, and none`, async () => {
      const v2 = (await enrolled()).m;
      const old = (await enrolled()).m;
      await legacy(old);
      const none = await machine();
      const seen = [];
      for (const m of [v2, old, none]) seen.push(await refusalOf(await send(await forgedV1(m, iat()))));
      expect(seen).toEqual([
        { status: 401, error: "invalid_proof" },
        { status: 401, error: "invalid_proof" },
        { status: 401, error: "invalid_proof" },
      ]);
    });
  }

  it("a forged v2 request reads the same for an enrolled key and an unknown one", async () => {
    const { m } = await enrolled();
    const none = await machine();
    const thief = await machine();
    const seen = [];
    for (const k of [m, none]) seen.push(await refusalOf(await renew(k, 0, nowS(), thief.kp.privateKey)));
    expect(seen).toEqual([
      { status: 401, error: "invalid_proof" },
      { status: 401, error: "invalid_proof" },
    ]);
  });
});

describe("RENEWAL_BINDING_V3 gates handing out enrollment ids (review M1)", () => {
  /** Run `fn` with the authority's RENEWAL_BINDING_V3 set to `value` (undefined: unset), then restore it. */
  async function withV3<T>(value: string | undefined, fn: () => Promise<T>): Promise<T> {
    const prior = await runInDurableObject(authority(), (a) => {
      const sa = a as unknown as { env: Record<string, unknown> };
      const was = sa.env.RENEWAL_BINDING_V3;
      const e = { ...sa.env };
      if (value === undefined) delete e.RENEWAL_BINDING_V3;
      else e.RENEWAL_BINDING_V3 = value;
      sa.env = e;
      return was as string | undefined;
    });
    try {
      return await fn();
    } finally {
      await runInDurableObject(authority(), (a) => {
        const sa = a as unknown as { env: Record<string, unknown> };
        sa.env = { ...sa.env, RENEWAL_BINDING_V3: prior };
      });
    }
  }
  const bindingOf = async (m: Machine) => {
    const f = await fp(m.spki);
    return runInDurableObject(authority(), (a) =>
      ((a as SigningAuthority)["ctx"].storage.sql
        .exec("SELECT binding_version FROM tier_enrolments WHERE key_fingerprint = ? AND status = 'active'", f)
        .toArray()[0] as { binding_version: number | null }).binding_version,
    );
  };

  for (const off of [undefined, "off"]) {
    it(`off (${off ?? "unset"}): no id at collect or renewal, and a re-enrolled key collects at v2`, async () => {
      await withV3(off, async () => {
        const { m, tier } = await enrolled();
        expect("enrollment_id" in tier, "collect handed out an id with v3 off").toBe(false);
        const r = await renew(m, 0);
        expect(r.status).toBe(200);
        expect("enrollment_id" in ((await r.json()) as object), "renewal handed out an id with v3 off").toBe(false);
        // No client can learn an id, so a v3-only row would strand it.
        await enrolled(m);
        expect(await bindingOf(m)).toBe(2);
        await expectOk(await renew(m, 0), 1);
      });
    });
  }

  it("turned off after ids went out: a v3 request is still accepted, so nobody is stranded", async () => {
    const { m, tier } = await withV3("on", () => enrolled());
    expect(tier.enrollment_id).toMatch(/^[0-9a-f]{64}$/);
    await withV3(undefined, async () => {
      await expectOk(await renewV3(m, tier.enrollment_id, 0), 1);
      expect(await bindingOf(m)).toBe(3);
    });
  });
});
