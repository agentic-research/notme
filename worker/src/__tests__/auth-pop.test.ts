/**
 * auth-pop.test.ts — AuthService.authenticate() requires proof that the
 * caller holds the private keys of the certs it presents (notme-fbbfbc).
 *
 * It checked that the certs chained to the CA and never that the caller
 * held their keys. Bridge certs are not secret — they are returned to
 * clients and CT-logged — so any holder of an AUTH binding could present a
 * victim's pair and have proxy() audit its requests under the victim's
 * identity. Now authenticate() takes a challenge from authChallenge() —
 * single-use, bound to the identity it was asked for, at most 60 s old —
 * and a PoP from EACH key over the authenticate binding
 * (src/auth/cert-pair-binding.ts), checked with the same verifyPopProofs
 * /cert uses.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { authenticateWithPop, identityOf, makeCA, mintCreds, popProofs, stubEnv } from "./helpers/mint-creds";

vi.mock("cloudflare:workers", () => ({
  WorkerEntrypoint: class WorkerEntrypoint {
    ctx: any;
    env: any;
    constructor(ctx: any, env: any) {
      this.ctx = ctx;
      this.env = env;
    }
  },
  DurableObject: class DurableObject {},
}));

const { AuthService } = await import("../../worker");
type AuthService = InstanceType<typeof AuthService>;

const CA = await makeCA();
const IDENTITY = "wimse://notme.bot/test/pop-holder";

// One env per test file section, so a challenge issued by one instance can
// be presented to another — as two binding calls would be.
function services() {
  const env = {
    ...stubEnv(CA),
    PROXY_ALLOWED_DESTINATIONS: "api.github.com",
  };
  // getAuthorityState for proxy()'s epoch gate.
  const authority = env.SIGNING_AUTHORITY.get() as Record<string, unknown>;
  authority.getAuthorityState = async () => ({ epoch: 1, seqno: 1, keyId: "k" });
  return () => new (AuthService as unknown as new (c: unknown, e: unknown) => AuthService)(null, env);
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("authenticate() requires proof of possession (notme-fbbfbc)", () => {
  it("auth.pop.required — certs presented without a challenge and proofs are refused", async () => {
    const svc = services()();
    const creds = await mintCreds(CA, IDENTITY);
    await expect(svc.authenticate(creds as never)).rejects.toThrow(/challenge|proof/i);
    expect((await svc.identity()).authenticated).toBe(false);
    // Cert strings alone, as a binding caller can send them.
    await expect(
      svc.authenticate({ mtlsCert: creds.mtlsCert, signingCert: creds.signingCert } as never),
    ).rejects.toThrow(/challenge|proof/i);
  });

  it("auth.pop.wrong-key — a PoP signed by keys other than the certs' is refused", async () => {
    const svc = services()();
    const victim = await mintCreds(CA, IDENTITY);
    const attacker = await mintCreds(CA, "wimse://notme.bot/test/attacker");
    const { challenge } = await svc.authChallenge(IDENTITY);
    await expect(
      svc.authenticate({
        mtlsCert: victim.mtlsCert,
        signingCert: victim.signingCert,
        challenge,
        proofs: await popProofs(victim, challenge, attacker),
      } as never),
    ).rejects.toThrow(/proof-of-possession/);
    expect((await svc.identity()).authenticated).toBe(false);
  });

  it("auth.pop.replay — a challenge is single-use, across instances", async () => {
    const make = services();
    const creds = await mintCreds(CA, IDENTITY);
    const a = make();
    const { challenge } = await a.authChallenge(IDENTITY);
    const presented = { mtlsCert: creds.mtlsCert, signingCert: creds.signingCert, challenge, proofs: await popProofs(creds, challenge) };
    await a.authenticate(presented as never);
    expect((await a.identity()).authenticated).toBe(true);
    const b = make();
    await expect(b.authenticate(presented as never)).rejects.toThrow(/challenge/);
    expect((await b.identity()).authenticated).toBe(false);
  });

  it("auth.pop.expired — a challenge older than 60 s is refused", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const svc = services()();
    const creds = await mintCreds(CA, IDENTITY);
    const { challenge, expires_in } = await svc.authChallenge(IDENTITY);
    expect(expires_in).toBeLessThanOrEqual(60);
    vi.setSystemTime(Date.now() + 61_000);
    await expect(
      svc.authenticate({ ...creds, challenge, proofs: await popProofs(creds, challenge) } as never),
    ).rejects.toThrow(/expired/);
  });

  it("auth.pop.bound — a challenge issued for one identity does not authenticate another", async () => {
    const svc = services()();
    const other = await mintCreds(CA, "wimse://notme.bot/test/someone-else");
    const { challenge } = await svc.authChallenge(IDENTITY);
    await expect(
      svc.authenticate({ ...other, challenge, proofs: await popProofs(other, challenge) } as never),
    ).rejects.toThrow(/challenge/);
  });

  it("auth.pop.tamper — editing the challenge's timestamp invalidates it", async () => {
    const svc = services()();
    const creds = await mintCreds(CA, IDENTITY);
    const { challenge } = await svc.authChallenge(IDENTITY);
    const [, nonce] = challenge.split(".");
    const forged = `${Math.floor(Date.now() / 1000) + 30}.${nonce}`;
    await expect(
      svc.authenticate({ ...creds, challenge: forged, proofs: await popProofs(creds, forged) } as never),
    ).rejects.toThrow(/challenge/);
  });

  it("auth.pop.valid — a valid PoP authenticates, and proxy() audits the PROVEN identity", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("ok", { status: 200 })));
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((l: unknown) => void logs.push(String(l)));
    const svc = services()();
    const creds = await mintCreds(CA, IDENTITY);
    await authenticateWithPop(svc, creds);
    expect((await svc.identity()).identity).toBe(await identityOf(creds));
    await svc.proxy({ url: "https://api.github.com/zen" });
    const line = JSON.parse(logs.find((l) => l.includes('"type":"proxy"'))!);
    expect(line).toMatchObject({ allowed: true, identity: IDENTITY });
  });

  it("auth.pop.no-keys — over a binding (no CryptoKeys), PoP still authenticates; sign() then refuses cleanly", async () => {
    const svc = services()();
    const creds = await mintCreds(CA, IDENTITY);
    const { challenge } = await svc.authChallenge(IDENTITY);
    await svc.authenticate({
      mtlsCert: creds.mtlsCert,
      signingCert: creds.signingCert,
      challenge,
      proofs: await popProofs(creds, challenge),
    } as never);
    expect((await svc.identity()).authenticated).toBe(true);
    await expect(svc.sign(new Uint8Array([1]).buffer)).rejects.toThrow(/signing key/);
  });
});
