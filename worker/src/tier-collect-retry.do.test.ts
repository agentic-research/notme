/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * tier-collect-retry.do.test.ts — a failed tier mint at collect leaves the
 * enrolment collectable (notme-d06b7b).
 *
 * collectTierEnrolment marked the enrolment `active` (consuming the device
 * code) BEFORE calling mintIssuingCa. When that mint threw — any mint error,
 * or notme-b52d7c's refusal when a rotate or revokeEpoch lands during the CT
 * wait — the next collect got invalid_grant and the machine had to re-enrol
 * through a new passkey approval.
 *
 * The invariant kept alongside: a device code is NEVER collected twice after
 * a successful mint — not by a retry, not by a concurrent collect, and not by
 * a collect that reclaims a claim abandoned by an evicted isolate while the
 * original is in fact still minting.
 *
 * The mint is faulted by shadowing mintIssuingCa on the instance inside
 * runInDurableObject: collect calls `this.mintIssuingCa`, and the instance
 * and the test share one isolate.
 */
import worker from "../worker";
import { env, runInDurableObject } from "cloudflare:test";
import { X509Certificate } from "@peculiar/x509";
import { describe, expect, it } from "vitest";
import { createSessionCookie } from "./auth/session";
import { serialOf } from "./ct/verify-sct";
import { ED25519 } from "./platform";
import type { SigningAuthority } from "./signing-authority";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };
const post = (url: string, body: unknown, headers: Record<string, string> = {}) =>
  (worker.fetch as (r: Request, e: unknown) => Promise<Response>)(
    new Request(`${ORIGIN}${url}`, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body: JSON.stringify(body),
    }),
    { ...env, ...LOCAL_ENV },
  );
const authority = () => env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));

/** Start an enrolment over the route and approve it with a passkey session. */
async function approvedEnrolment() {
  const kp = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = new Uint8Array((await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer);
  const pem = `-----BEGIN PUBLIC KEY-----\n${btoa(String.fromCharCode(...spki)).match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
  const start = await post("/cert/issuing-ca/device", { public_key: pem });
  expect(start.status).toBe(200);
  const e = (await start.json()) as { device_code: string; user_code: string };

  const pid = crypto.randomUUID();
  await authority().createPrincipalWithCapabilities(pid, ["bridgeCert", "certMint"]);
  const cookie = await createSessionCookie(
    { principalId: pid, scopes: ["bridgeCert", "certMint"], authMethod: "passkey" },
    await authority().getSessionSecret(),
  );
  expect((await post("/cert/issuing-ca/device/approve", { user_code: e.user_code }, { cookie })).status).toBe(200);

  // The proof the route checks: Ed25519 over tag || SPKI || SHA-256(device_code).
  const tag = new TextEncoder().encode("notme/tier-enrol/v1\0");
  const codeHash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(e.device_code)));
  const input = new Uint8Array(tag.length + spki.length + 32);
  input.set(tag, 0);
  input.set(spki, tag.length);
  input.set(codeHash, tag.length + spki.length);
  const sig = new Uint8Array(await crypto.subtle.sign(ED25519, kp.privateKey, input));
  const proof = btoa(String.fromCharCode(...sig)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const hash = Array.from(codeHash, (b) => b.toString(16).padStart(2, "0")).join("");
  return { deviceCode: e.device_code, proof, hash };
}

type Mint = SigningAuthority["mintIssuingCa"];
/** Shadow mintIssuingCa on the instance for the duration of `fn`. */
async function withMint<T>(auth: SigningAuthority, mint: Mint, fn: () => Promise<T>): Promise<T> {
  const a = auth as unknown as { mintIssuingCa: Mint };
  a.mintIssuingCa = mint;
  try {
    return await fn();
  } finally {
    delete (a as Partial<typeof a>).mintIssuingCa;
  }
}

const status = (state: DurableObjectState, hash: string) =>
  (
    state.storage.sql
      .exec("SELECT status FROM tier_enrolments WHERE device_code_hash = ?", hash)
      .toArray()[0] as { status: string } | undefined
  )?.status;

describe("a tier mint failure at collect (notme-d06b7b)", () => {
  it("leaves the enrolment collectable: the retry mints", async () => {
    const e = await approvedEnrolment();
    await runInDurableObject(authority(), async (inst, state) => {
      const auth = inst as SigningAuthority;
      await expect(
        withMint(auth, () => Promise.reject(new Error("injected mint failure")), () =>
          auth.collectTierEnrolment({ deviceCode: e.deviceCode, proof: e.proof }),
        ),
      ).rejects.toThrow(/injected mint failure/);
      expect(status(state, e.hash)).toBe("approved");

      const retry = await auth.collectTierEnrolment({ deviceCode: e.deviceCode, proof: e.proof });
      expect(retry.ok).toBe(true);
      expect(retry.ok && retry.certificate).toMatch(/BEGIN CERTIFICATE/);
      expect(status(state, e.hash)).toBe("active");

      // ...and once collected, never again.
      const again = await auth.collectTierEnrolment({ deviceCode: e.deviceCode, proof: e.proof });
      expect(again).toEqual({ ok: false, reason: "invalid_grant" });
    });
  });

  it("a collect while the mint is in flight is told to poll, and after the success it is refused", async () => {
    const e = await approvedEnrolment();
    await runInDurableObject(authority(), async (inst) => {
      const auth = inst as SigningAuthority;
      const real = auth.mintIssuingCa.bind(auth);
      let release!: () => void;
      const gate = new Promise<void>((r) => (release = r));
      await withMint(auth, (async (p) => { await gate; return real(p); }) as Mint, async () => {
        const first = auth.collectTierEnrolment({ deviceCode: e.deviceCode, proof: e.proof });
        // Let the first collect reach its mint.
        await new Promise((r) => setTimeout(r, 20));
        const second = await auth.collectTierEnrolment({ deviceCode: e.deviceCode, proof: e.proof });
        expect(second).toEqual({ ok: false, reason: "authorization_pending" });
        release();
        expect((await first).ok).toBe(true);
      });
      const third = await auth.collectTierEnrolment({ deviceCode: e.deviceCode, proof: e.proof });
      expect(third).toEqual({ ok: false, reason: "invalid_grant" });
    });
  });

  it("an abandoned claim (evicted isolate) is reclaimed; the original, if still minting, does not deliver", async () => {
    const e = await approvedEnrolment();
    await runInDurableObject(authority(), async (inst, state) => {
      const auth = inst as SigningAuthority;
      const real = auth.mintIssuingCa.bind(auth);
      let release!: () => void;
      const gate = new Promise<void>((r) => (release = r));
      // Only the FIRST mint waits on the gate; the reclaimer's mints at once.
      let calls = 0;
      const slow = withMint(auth, (async (p) => { if (++calls === 1) await gate; return real(p); }) as Mint, () =>
        auth.collectTierEnrolment({ deviceCode: e.deviceCode, proof: e.proof }),
      );
      await new Promise((r) => setTimeout(r, 20));
      expect(status(state, e.hash)).toBe("collecting");
      // Age the claim past the reclaim window, as an eviction mid-mint would.
      state.storage.sql.exec(
        "UPDATE tier_enrolments SET collect_started_at = collect_started_at - 3600 WHERE device_code_hash = ?",
        e.hash,
      );
      const reclaimed = await auth.collectTierEnrolment({ deviceCode: e.deviceCode, proof: e.proof });
      expect(reclaimed.ok).toBe(true);
      release();
      // The original's claim was taken over: its certificate is not delivered.
      expect(await slow).toEqual({ ok: false, reason: "invalid_grant" });
      expect(status(state, e.hash)).toBe("active");
    });
  });

  it("a minter whose claim was taken over does not hand the reclaimer's claim back when it fails", async () => {
    const e = await approvedEnrolment();
    await runInDurableObject(authority(), async (inst, state) => {
      const auth = inst as SigningAuthority;
      const real = auth.mintIssuingCa.bind(auth);
      let failFirst!: () => void;
      let releaseSecond!: () => void;
      const gate1 = new Promise<void>((r) => (failFirst = r));
      const gate2 = new Promise<void>((r) => (releaseSecond = r));
      let calls = 0;
      const mint = (async (p) => {
        const n = ++calls;
        if (n === 1) {
          await gate1;
          throw new Error("injected mint failure");
        }
        if (n === 2) await gate2;
        return real(p);
      }) as Mint;
      await withMint(auth, mint, async () => {
        const original = auth
          .collectTierEnrolment({ deviceCode: e.deviceCode, proof: e.proof })
          .catch((err: Error) => err.message);
        await new Promise((r) => setTimeout(r, 20));
        state.storage.sql.exec(
          "UPDATE tier_enrolments SET collect_started_at = collect_started_at - 3600 WHERE device_code_hash = ?",
          e.hash,
        );
        const reclaimer = auth.collectTierEnrolment({ deviceCode: e.deviceCode, proof: e.proof });
        await new Promise((r) => setTimeout(r, 20));
        failFirst();
        expect(await original).toMatch(/injected mint failure/);
        // The reclaimer is still minting: its claim stands, so a third
        // collect polls instead of starting a second mint.
        expect(status(state, e.hash)).toBe("collecting");
        const third = await auth.collectTierEnrolment({ deviceCode: e.deviceCode, proof: e.proof });
        expect(third).toEqual({ ok: false, reason: "authorization_pending" });
        releaseSecond();
        expect((await reclaimer).ok).toBe(true);
      });
      expect(calls).toBe(2);
      expect(status(state, e.hash)).toBe("active");
    });
  });

  it("ct.not-delivered.takeover: the taken-over minter's certificate is recorded as not delivered; the reclaimer's is not (notme-b35676)", async () => {
    // The loser's certificate was signed, and with CT bound was logged or
    // backlogged, but nobody receives it. A monitor must be able to tell.
    const e = await approvedEnrolment();
    await runInDurableObject(authority(), async (inst, state) => {
      const auth = inst as SigningAuthority;
      const real = auth.mintIssuingCa.bind(auth);
      let release!: () => void;
      const gate = new Promise<void>((r) => (release = r));
      let calls = 0;
      const minted: string[] = [];
      const mint = (async (p) => {
        const n = ++calls;
        const out = await real(p);
        minted[n - 1] = out.certificate;
        if (n === 1) await gate;
        return out;
      }) as Mint;
      const { loser, winner } = await withMint(auth, mint, async () => {
        const slow = auth.collectTierEnrolment({ deviceCode: e.deviceCode, proof: e.proof });
        await new Promise((r) => setTimeout(r, 50));
        state.storage.sql.exec(
          "UPDATE tier_enrolments SET collect_started_at = collect_started_at - 3600 WHERE device_code_hash = ?",
          e.hash,
        );
        const reclaimed = await auth.collectTierEnrolment({ deviceCode: e.deviceCode, proof: e.proof });
        release();
        return { loser: await slow, winner: reclaimed };
      });
      expect(loser).toEqual({ ok: false, reason: "invalid_grant" });
      expect(winner.ok).toBe(true);
      const serial = (pem: string) => serialOf(new Uint8Array(new X509Certificate(pem).rawData));
      const loserSerial = serial(minted[0]!);
      const winnerSerial = serial(winner.ok ? winner.certificate : "");
      expect(loserSerial).not.toBe(winnerSerial);

      const list = await auth.listNotDeliveredCerts();
      const row = list.find((x) => x.serial === loserSerial);
      expect(row, "the discarded certificate's serial is not recorded").toBeDefined();
      expect(row!.reason).toBe("claim_taken_over");
      expect(list.map((x) => x.serial)).not.toContain(winnerSerial);
    });

    // ...and a monitor can read it with no credential, read-only.
    const url = "/.well-known/ct-not-delivered.json";
    const get = await (worker.fetch as (r: Request, e: unknown) => Promise<Response>)(
      new Request(`${ORIGIN}${url}`),
      { ...env, ...LOCAL_ENV },
    );
    expect(get.status).toBe(200);
    const body = (await get.json()) as { notDelivered: Array<{ serial: string; reason: string }> };
    expect(body.notDelivered.some((x) => x.reason === "claim_taken_over")).toBe(true);
    expect((await post(url, {})).status).toBe(405);
  });
});
