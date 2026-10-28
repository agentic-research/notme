/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * tier-enrolment.do.test.ts — a machine can actually obtain a delegation tier
 * (notme-486e8a).
 *
 * THE DEFECT. `/cert/issuing-ca` verified a proof over
 * `SPKI || SHA-256(notme_session)`. notme_session is HttpOnly and every login
 * path runs in a browser, so no legitimate client could ever compute that
 * proof. Nothing called the route. The tier — ADR-019 D4's human→machine hop,
 * which every task certificate chains through — had never been enrollable.
 *
 * THE FLOW (RFC 8628 shape). The machine generates the tier key and starts an
 * enrolment. A human approves the short user code in a passkey-authenticated
 * browser session, comparing a key fingerprint shown on both screens. The
 * machine collects the tier with a proof over
 * `"notme/tier-enrol/v1\0" || SPKI || SHA-256(device_code)`. The device code
 * never appears in a browser, so the anti-replay property the cookie binding
 * was for — a captured key+proof cannot be bound under someone else's
 * approval — is kept, without needing a secret the caller cannot read.
 *
 * The last test is the point: a task certificate minted OFFLINE from the
 * collected tier chains to this authority's root.
 */
import worker from "../worker";
import { env, runInDurableObject } from "cloudflare:test";
import { BasicConstraintsExtension, X509Certificate } from "@peculiar/x509";
import { describe, expect, it } from "vitest";
import { createSessionCookie } from "./auth/session";
import { mintTaskCertPair } from "./cert-authority";
import { ED25519 } from "./platform";
import type { SigningAuthority } from "./signing-authority";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };
const START = `${ORIGIN}/cert/issuing-ca/device`;
const APPROVE = `${ORIGIN}/cert/issuing-ca/device/approve`;
const TOKEN = `${ORIGIN}/cert/issuing-ca/device/token`;

const call = (url: string, init: RequestInit = {}) =>
  (worker.fetch as (r: Request, e: unknown) => Promise<Response>)(
    new Request(url, init),
    { ...env, ...LOCAL_ENV },
  );
const post = (url: string, body: unknown, headers: Record<string, string> = {}) =>
  call(url, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });

const authority = () =>
  env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));

async function machineKey() {
  const kp = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = new Uint8Array((await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer);
  const b64 = btoa(String.fromCharCode(...spki));
  const pem = `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
  return { kp, spki, pem };
}

/** The proof the machine sends at collection — mirrors the route exactly. */
async function proofFor(privateKey: CryptoKey, spki: Uint8Array, deviceCode: string) {
  const tag = new TextEncoder().encode("notme/tier-enrol/v1\0");
  const codeHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(deviceCode)),
  );
  const input = new Uint8Array(tag.length + spki.length + 32);
  input.set(tag, 0);
  input.set(spki, tag.length);
  input.set(codeHash, tag.length + spki.length);
  const sig = new Uint8Array(await crypto.subtle.sign(ED25519, privateKey, input));
  return btoa(String.fromCharCode(...sig)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function humanWith(scopes: string[], claimed = scopes) {
  const pid = crypto.randomUUID();
  await authority().createPrincipalWithCapabilities(pid, scopes);
  // createSessionCookie returns the full `notme_session=...` pair, as
  // admin-revoke-epoch-route.do.test.ts uses it.
  const cookie = await createSessionCookie(
    { principalId: pid, scopes: claimed, authMethod: "passkey" },
    await authority().getSessionSecret(),
  );
  return { pid, cookie };
}

async function started(scopes?: string[]) {
  const key = await machineKey();
  const res = await post(START, { public_key: key.pem, ...(scopes ? { scopes } : {}) });
  expect(res.status).toBe(200);
  const body = (await res.json()) as {
    device_code: string;
    user_code: string;
    verification_uri: string;
    key_fingerprint: string;
    expires_in: number;
    interval: number;
  };
  return { key, ...body };
}

describe("starting an enrolment (notme-486e8a)", () => {
  it("returns a device code, a short user code, a verification URI and the key's fingerprint", async () => {
    const e = await started();
    expect(e.device_code.length).toBeGreaterThanOrEqual(43);
    expect(e.user_code).toMatch(/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/);
    expect(e.verification_uri).toBe(`${ORIGIN}/enrol?code=${e.user_code}`);
    // The fingerprint the human compares: SHA-256 of the SPKI, hex.
    const fp = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", e.key.spki)))
      .map((b) => b.toString(16).padStart(2, "0")).join("");
    expect(e.key_fingerprint).toBe(fp);
    expect(e.expires_in).toBe(600);
  });

  it("refuses a missing or non-Ed25519 key", async () => {
    expect((await post(START, {})).status).toBe(400);
    const p256 = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"])) as CryptoKeyPair;
    const spki = new Uint8Array((await crypto.subtle.exportKey("spki", p256.publicKey)) as ArrayBuffer);
    const pem = `-----BEGIN PUBLIC KEY-----\n${btoa(String.fromCharCode(...spki))}\n-----END PUBLIC KEY-----`;
    expect((await post(START, { public_key: pem })).status).toBe(400);
  });
});

describe("the human approves with a passkey session", () => {
  it("refuses approval without a session", async () => {
    const e = await started();
    expect((await post(APPROVE, { user_code: e.user_code })).status).toBe(401);
  });

  it("refuses a session without a LIVE certMint grant — even one whose cookie claims it", async () => {
    // The old route read certMint from the cookie. A cookie is a cache of
    // the grant, never the source: a revoked certMint must stop working at
    // once, not when the cookie expires.
    const e = await started();
    const { cookie } = await humanWith(["bridgeCert"], ["bridgeCert", "certMint"]);
    expect((await post(APPROVE, { user_code: e.user_code }, { cookie })).status).toBe(403);
  });

  it("404s an unknown user code", async () => {
    const { cookie } = await humanWith(["bridgeCert", "certMint"]);
    expect((await post(APPROVE, { user_code: "BBBB-BBBB" }, { cookie })).status).toBe(404);
  });

  it("serves an approval page that shows the fingerprint to compare", async () => {
    const e = await started();
    const { cookie } = await humanWith(["bridgeCert", "certMint"]);
    const res = await call(`${ORIGIN}/enrol?code=${e.user_code}`, { headers: { cookie } });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(e.user_code);
    // Grouped in fours — the form a human reads across from the terminal.
    expect(html).toContain(e.key_fingerprint.slice(0, 16).match(/..../g)!.join(" "));
  });
});

describe("the machine collects the tier", () => {
  it("is pending until approved", async () => {
    const e = await started();
    const res = await post(TOKEN, {
      device_code: e.device_code,
      proof: await proofFor(e.key.kp.privateKey, e.key.spki, e.device_code),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "authorization_pending" });
  });

  it("issues a tier for the APPROVER's identity, bound to the enrolled key", async () => {
    const e = await started();
    const { pid, cookie } = await humanWith(["bridgeCert", "certMint"]);
    expect((await post(APPROVE, { user_code: e.user_code }, { cookie })).status).toBe(200);

    const res = await post(TOKEN, {
      device_code: e.device_code,
      proof: await proofFor(e.key.kp.privateKey, e.key.spki, e.device_code),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { certificate: string; identity: string; scopes: string[] };
    const tier = new X509Certificate(body.certificate);
    const bc = tier.getExtension(BasicConstraintsExtension);
    expect(bc?.ca).toBe(true);
    expect(bc?.pathLength).toBe(0);
    // Trust domain = SITE_URL's host, port included, as every route mints it.
    expect(body.identity).toBe(`wimse://${new URL(ORIGIN).host}/principal/${encodeURIComponent(pid)}`);
    // The cert's SubjectPublicKeyInfo, byte for byte.
    const tierSpki = new Uint8Array(tier.publicKey.rawData);
    expect(tierSpki).toEqual(e.key.spki);
    // certMint and authorityManage are never carried into an exportable cert.
    expect(body.scopes).toEqual(["bridgeCert"]);
  });

  it("refuses a proof by a different key, and does NOT burn the enrolment for the real holder", async () => {
    const e = await started();
    const { cookie } = await humanWith(["bridgeCert", "certMint"]);
    await post(APPROVE, { user_code: e.user_code }, { cookie });
    const thief = await machineKey();
    const bad = await post(TOKEN, {
      device_code: e.device_code,
      proof: await proofFor(thief.kp.privateKey, e.key.spki, e.device_code),
    });
    expect(bad.status).toBe(401);
    const good = await post(TOKEN, {
      device_code: e.device_code,
      proof: await proofFor(e.key.kp.privateKey, e.key.spki, e.device_code),
    });
    expect(good.status).toBe(200);
  });

  it("is single-use", async () => {
    const e = await started();
    const { cookie } = await humanWith(["bridgeCert", "certMint"]);
    await post(APPROVE, { user_code: e.user_code }, { cookie });
    const proof = await proofFor(e.key.kp.privateKey, e.key.spki, e.device_code);
    expect((await post(TOKEN, { device_code: e.device_code, proof })).status).toBe(200);
    const again = await post(TOKEN, { device_code: e.device_code, proof });
    expect(again.status).toBe(400);
    expect(await again.json()).toMatchObject({ error: "invalid_grant" });
  });

  it("expires", async () => {
    const e = await started();
    const { cookie } = await humanWith(["bridgeCert", "certMint"]);
    await post(APPROVE, { user_code: e.user_code }, { cookie });
    // Expire it in storage rather than through a method: a test-only DO
    // method would sit on the pinned RPC surface.
    await runInDurableObject(authority(), (a) => {
      (a as SigningAuthority)["ctx"].storage.sql.exec(
        "UPDATE tier_enrolments SET expires_at = 0 WHERE user_code = ?",
        e.user_code,
      );
    });
    const res = await post(TOKEN, {
      device_code: e.device_code,
      proof: await proofFor(e.key.kp.privateKey, e.key.spki, e.device_code),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "expired_token" });
  });
});

describe("end to end: a task certificate, minted offline, chains to the root", () => {
  it("root → tier (collected) → task cert for a named task and goal", async () => {
    const e = await started();
    const { cookie } = await humanWith(["bridgeCert", "certMint"]);
    await post(APPROVE, { user_code: e.user_code }, { cookie });
    const tierRes = (await (
      await post(TOKEN, {
        device_code: e.device_code,
        proof: await proofFor(e.key.kp.privateKey, e.key.spki, e.device_code),
      })
    ).json()) as { certificate: string; authority: { epoch: number } };

    // OFFLINE from here: no call to the authority.
    const mtls = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const signing = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
    const pem = async (k: CryptoKey) => {
      const b = new Uint8Array((await crypto.subtle.exportKey("spki", k)) as ArrayBuffer);
      return `-----BEGIN PUBLIC KEY-----\n${btoa(String.fromCharCode(...b)).match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
    };
    const goalHash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("ship the task-cert demo"))))
      .map((b) => b.toString(16).padStart(2, "0")).join("");
    const task = await mintTaskCertPair(
      tierRes.certificate,
      e.key.kp.privateKey,
      await pem(mtls.publicKey),
      await pem(signing.publicKey),
      { task: "notme-486e8a", goalHash, scopes: ["bridgeCert"], epoch: tierRes.authority.epoch },
    );

    const root = new X509Certificate(await authority().getCACertificatePem());
    const tier = new X509Certificate(tierRes.certificate);
    const leaf = new X509Certificate(task.certificates.signing);
    const rootKey = await root.publicKey.export();
    const tierKey = await tier.publicKey.export();
    expect(await tier.verify({ publicKey: rootKey, signatureOnly: true })).toBe(true);
    expect(await leaf.verify({ publicKey: tierKey, signatureOnly: true })).toBe(true);
    expect(leaf.issuer).toBe(tier.subject);
    expect(task.identity.endsWith("/notme-486e8a")).toBe(true);
  });
});
