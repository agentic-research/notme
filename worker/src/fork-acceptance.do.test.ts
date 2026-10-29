/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * fork-acceptance.do.test.ts — the end-to-end acceptance for mint path phase 1
 * (notme-747cc7). The REAL task-cert client (scripts/task-cert/lib.ts
 * renewTier) runs unmodified against the REAL worker; only `fetchFn` is a
 * shim that turns the client's request into worker.fetch. Pending state is
 * held in memory via renewTier's callbacks (chosen for determinism; the client
 * itself defaults to files on disk).
 *
 * Falsifiable: against the plan-start commit (no generation) it fails; removing
 * the client's pending-resend branch or the v1 lock makes at least one scenario
 * here fail. It does NOT pin the atomic `generation = ?` guard: removing that
 * guard leaves these scenarios green, because they run requests sequentially.
 * That guard is pinned by tier-generation.do.test.ts's direct-injection test.
 */
import worker from "../worker";
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";
import { createSessionCookie } from "./auth/session";
import { tierEnrolmentBinding, deviceCodeHash } from "./auth/tier-enrolment-binding";
import { ED25519 } from "./platform";
import type { SigningAuthority } from "./signing-authority";
import { renewTier, type PendingRenewal, type RenewalResult } from "../../scripts/task-cert/lib";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };
const toWorker = (r: Request) => (worker.fetch as (r: Request, e: unknown) => Promise<Response>)(r, { ...env, ...LOCAL_ENV });
const call = (url: string, init: RequestInit = {}) => toWorker(new Request(url, init));
const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  call(`${ORIGIN}${path}`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
const authority = () => env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
const b64u = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

type Key = { privateKey: CryptoKey; spki: Uint8Array; pem: string };

/** What a machine holds on disk: its key and the generation of its last tier. */
type Client = { key: Key; generation: number | undefined; pending: PendingRenewal | null; human: { cookie: string } };

async function enroll(): Promise<Client> {
  const kp = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = new Uint8Array((await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer);
  const pem = `-----BEGIN PUBLIC KEY-----\n${btoa(String.fromCharCode(...spki)).match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
  const start = (await (await post("/cert/issuing-ca/device", { public_key: pem })).json()) as { device_code: string; user_code: string };
  const pid = `acc-${crypto.randomUUID()}`;
  const scopes = ["bridgeCert", "certMint"];
  await authority().createPrincipalWithCapabilities(pid, scopes);
  const cookie = await createSessionCookie({ principalId: pid, scopes, authMethod: "passkey" }, await authority().getSessionSecret());
  const ap = await post("/cert/issuing-ca/device/approve", { user_code: start.user_code }, { cookie });
  expect(ap.status, await ap.clone().text()).toBe(200);
  const proof = b64u(new Uint8Array(await crypto.subtle.sign(ED25519, kp.privateKey, tierEnrolmentBinding(spki, await deviceCodeHash(start.device_code)))));
  const tok = await post("/cert/issuing-ca/device/token", { device_code: start.device_code, proof });
  expect(tok.status, await tok.clone().text()).toBe(200);
  const tier = (await tok.json()) as { generation?: number };
  return { key: { privateKey: kp.privateKey, spki, pem }, generation: tier.generation, pending: null, human: { cookie } };
}

/** Copy the machine's disk: same key, same generation, its own pending slot. */
const copyOf = (c: Client): Client => ({ ...c, pending: c.pending && { ...c.pending } });

type Fetch = (url: string, init?: RequestInit) => Promise<Response>;
const direct: Fetch = (url, init) => toWorker(new Request(url, init));

/** One run of the real client. Updates the client's "disk" through the callbacks, as renewTierInDir does. */
async function runClient(c: Client, fetchFn: Fetch = direct, force?: { v1: boolean }): Promise<RenewalResult> {
  return renewTier(
    ORIGIN,
    c.key,
    {
      generation: force?.v1 ? undefined : c.generation,
      pending: c.pending,
      savePending: (p) => { c.pending = p; },
      clearPending: (body) => { if (c.pending?.body === body) c.pending = null; },
      persist: (r) => { c.generation = r.generation; },
      currentGeneration: async () => (force?.v1 ? undefined : c.generation),
    },
    fetchFn as typeof fetch,
  );
}

const refusal = async (p: Promise<unknown>) => (await p.then(() => null, (e) => e)) as (Error & { reason?: string }) | null;

const enrollmentsOf = async (c: Client) =>
  (await (await call(`${ORIGIN}/cert/issuing-ca/enrollments`, { headers: { cookie: c.human.cookie } })).json()) as Array<{ revoked_at: number | null; generation: number }>;

describe("mint path phase 1, end to end with the real client", () => {
  it("the honest machine renews through a lost response", async () => {
    const c = await enroll();
    expect(c.generation).toBe(0);
    // The request reaches the authority, which acts on it; the response never returns.
    const lost: Fetch = async (url, init) => {
      await direct(url, init);
      throw new TypeError("network lost");
    };
    await expect(runClient(c, lost)).rejects.toThrow();
    expect(c.pending, "the signed request was saved before it was sent").not.toBeNull();
    expect(c.generation).toBe(0);

    // The client resends the SAME request; the authority serves it as a retry.
    // (A fresh second passes first: signing anew here would carry a different iat, which is a fork.)
    await sleep(1100);
    const r1 = await runClient(c);
    expect(r1.generation).toBe(1);
    expect(c.pending).toBeNull();
    expect(c.generation).toBe(1);

    const r2 = await runClient(c);
    expect(r2.generation).toBe(2);
    expect((await enrollmentsOf(c))[0].revoked_at).toBeNull();
  });

  it("a request that never arrived is resent minutes later and renews", async () => {
    const c = await enroll();
    // Offline on resume: the connection fails before any byte reaches the
    // authority (no error code the client could prove that from, so it keeps
    // the request). The client signed it 130 s before the resend below.
    const signedAt = Date.now() - 130_000;
    const now = vi.spyOn(Date, "now").mockReturnValue(signedAt);
    // Never calls the worker.
    const offline: Fetch = async () => {
      throw new TypeError("fetch failed");
    };
    try {
      await expect(runClient(c, offline)).rejects.toThrow();
    } finally {
      now.mockRestore();
    }
    expect(c.pending, "the request is kept for a resend").not.toBeNull();
    expect(Math.floor(Date.now() / 1000) - c.pending!.iat).toBeGreaterThanOrEqual(121);

    // Back online, past the 120 s skew: the same bytes renew at generation 0.
    const sent: string[] = [];
    const watching: Fetch = (url, init) => {
      sent.push(String(init?.body));
      return direct(url, init);
    };
    const pendingBody = c.pending!.body;
    const r = await runClient(c, watching);
    expect(sent).toEqual([pendingBody]);
    expect(r.generation).toBe(1);
    expect(c.pending).toBeNull();
    expect((await enrollmentsOf(c))[0].revoked_at).toBeNull();
    expect((await runClient(c)).generation).toBe(2);
  });

  it("a copied machine is caught at renewal, and both lines are shut off", async () => {
    const original = await enroll();
    const copy = copyOf(original);
    expect((await runClient(original)).generation).toBe(1);

    await sleep(1100); // the copy signs its own request: a different iat
    const caught = await refusal(runClient(copy));
    expect(caught?.reason).toBe("fork_detected");

    const next = await refusal(runClient(original));
    expect(next?.reason).toBe("fork_detected");

    const [row] = await enrollmentsOf(original);
    expect(row.revoked_at).not.toBeNull();
  });

  it("two holders of one key renewing at the same moment: exactly one wins", async () => {
    const a = await enroll();
    const b = copyOf(a);
    // renewTier reads the clock on entry, so each holder signs at its own second.
    const t = Date.now();
    const now = vi.spyOn(Date, "now");
    now.mockReturnValue(t);
    const pa = refusal(runClient(a));
    now.mockReturnValue(t + 1000);
    const pb = refusal(runClient(b));
    now.mockRestore();
    const [ea, eb] = await Promise.all([pa, pb]);
    expect([ea, eb].filter((e) => e === null), "exactly one renewal succeeds").toHaveLength(1);
    expect([ea, eb].find((e) => e)?.reason).toBe("fork_detected");
    expect((await enrollmentsOf(a))[0].revoked_at).not.toBeNull();
  });

  it("a captured request replayed later does not shut the machine off", async () => {
    const c = await enroll();
    let recorded: { url: string; init: RequestInit } | undefined;
    const recording: Fetch = (url, init) => {
      recorded ??= { url, init: init! };
      return direct(url, init);
    };
    expect((await runClient(c, recording)).generation).toBe(1);
    expect((await runClient(c)).generation).toBe(2);
    expect(recorded).toBeDefined();

    // An observer replays the very first request body at once. It is stale, not a fork.
    const replay = await direct(recorded!.url, recorded!.init);
    expect(replay.status).toBe(401);
    expect(await replay.json()).toMatchObject({ error: "stale_proof" });
    expect((await enrollmentsOf(c))[0].revoked_at).toBeNull();

    expect((await runClient(c)).generation).toBe(3);
  });

  it("a legacy machine keeps working until its first v2 renewal", async () => {
    const c = await enroll();
    const fpHex = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", c.key.spki))).map((b) => b.toString(16).padStart(2, "0")).join("");
    await runInDurableObject(authority(), (a) => {
      (a as SigningAuthority)["ctx"].storage.sql.exec("UPDATE tier_enrolments SET binding_version = NULL WHERE key_fingerprint = ?", fpHex);
    });
    // A tier.json from before generations: no generation field, v1 proof.
    const v1 = await runClient(c, direct, { v1: true });
    expect(v1.certificate.length).toBeGreaterThan(0);
    const v2 = await runClient(c);
    expect(v2.generation).toBe(1);
    // v1 is retired for this machine now.
    const refused = await refusal(runClient(copyOf({ ...c, generation: undefined }), direct, { v1: true }));
    expect(refused?.reason).toBe("binding_v2_required");
  });
});
