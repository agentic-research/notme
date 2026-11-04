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
  // AuthSession (src/auth/auth-session.ts) extends it (notme-153f03).
  RpcTarget: class RpcTarget {},
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
  });

  it("auth.pop.replay — a challenge is single-use, across instances", async () => {
    const make = services();
    const creds = await mintCreds(CA, IDENTITY);
    const a = make();
    const { challenge } = await a.authChallenge(IDENTITY);
    const presented = { mtlsCert: creds.mtlsCert, signingCert: creds.signingCert, challenge, proofs: await popProofs(creds, challenge) };
    const session = await a.authenticate(presented as never);
    expect((await session.identity()).authenticated).toBe(true);
    const b = make();
    await expect(b.authenticate(presented as never)).rejects.toThrow(/challenge/);
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
    const session = await authenticateWithPop(svc, creds);
    expect((await session.identity()).identity).toBe(await identityOf(creds));
    await session.proxy({ url: "https://api.github.com/zen" });
    const line = JSON.parse(logs.find((l) => l.includes('"type":"proxy"'))!);
    expect(line).toMatchObject({ allowed: true, identity: IDENTITY });
  });

  it("auth.pop.no-keys — over a binding (no CryptoKeys), PoP still authenticates; sign() then refuses cleanly", async () => {
    const svc = services()();
    const creds = await mintCreds(CA, IDENTITY);
    const { challenge } = await svc.authChallenge(IDENTITY);
    const session = await svc.authenticate({
      mtlsCert: creds.mtlsCert,
      signingCert: creds.signingCert,
      challenge,
      proofs: await popProofs(creds, challenge),
    } as never);
    expect((await session.identity()).authenticated).toBe(true);
    await expect(session.sign(new Uint8Array([1]).buffer)).rejects.toThrow(/signing key/);
  });

  it("auth.pop.key-mismatch — an in-isolate signingKey that is not the signing cert's is refused, and the challenge survives", async () => {
    const svc = services()();
    const creds = await mintCreds(CA, IDENTITY);
    const other = await mintCreds(CA, "wimse://notme.bot/test/other-key");
    const { challenge } = await svc.authChallenge(IDENTITY);
    const presented = { mtlsCert: creds.mtlsCert, signingCert: creds.signingCert, challenge, proofs: await popProofs(creds, challenge) };
    await expect(svc.authenticate({ ...presented, signingKey: other.signingKey } as never)).rejects.toThrow(
      /signing key does not match/,
    );
    // Checked before the challenge is spent: the holder can still use it.
    const session = await svc.authenticate({ ...presented, signingKey: creds.signingKey } as never);
    expect((await session.identity()).identity).toBe(IDENTITY);
  });
});

describe("AuthSession disposal (notme-153f03)", () => {
  it("auth.session.dispose — the session's disposer drops the credentials it held", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("ok", { status: 200 })));
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((l: unknown) => void logs.push(String(l)));
    const svc = services()();
    const creds = await mintCreds(CA, IDENTITY, ["bridgeCert", "sign:git"]);
    const session = await authenticateWithPop(svc, creds);
    expect((await session.identity()).authenticated).toBe(true);

    // What workerd calls once the caller's last stub is disposed.
    session[Symbol.dispose]();

    expect((await session.identity()).authenticated).toBe(false);
    await expect(session.proxy({ url: "https://api.github.com/zen" })).rejects.toThrow(/disposed/);
    await expect(session.sign(new Uint8Array([1]).buffer, "raw")).rejects.toThrow(/disposed/);
    const records = logs.map((l) => JSON.parse(l));
    expect(records.find((r) => r.type === "session")).toMatchObject({ event: "disposed", identity: IDENTITY });
    expect(records.find((r) => r.type === "proxy")).toMatchObject({ allowed: false, reason: "not_authenticated" });
  });
});

describe("authChallenge() is throttled (notme-153f03)", () => {
  /** A stand-in for the CERT_LIMITER binding, which has no test constructor. */
  function limiter(allow: number) {
    const keys: string[] = [];
    return {
      keys,
      binding: {
        limit: async ({ key }: { key: string }) => {
          keys.push(key);
          return { success: keys.filter((k) => k === key).length <= allow };
        },
      },
    };
  }
  function throttled(rl: ReturnType<typeof limiter>, props?: unknown) {
    const env = { ...stubEnv(CA), CERT_LIMITER: rl.binding };
    const authority = env.SIGNING_AUTHORITY.get() as Record<string, unknown>;
    const issued: string[] = [];
    const issue = authority.issuePopNonce as (k: string) => Promise<unknown>;
    authority.issuePopNonce = async (k: string) => {
      issued.push(k);
      return issue(k);
    };
    const ctx = props === undefined ? null : { props };
    const make = () => new (AuthService as unknown as new (c: unknown, e: unknown) => AuthService)(ctx, env);
    return { make, issued };
  }

  it("auth.challenge.throttled — past the limit authChallenge() refuses, and writes no nonce row", async () => {
    const rl = limiter(2);
    const { make, issued } = throttled(rl);
    await make().authChallenge(IDENTITY);
    await make().authChallenge(IDENTITY);
    await expect(make().authChallenge(IDENTITY)).rejects.toThrow(/rate limited/);
    expect(issued).toHaveLength(2);
  });

  it("auth.challenge.keyed-by-binding — rotating the claimed identity does not escape the limit", async () => {
    const rl = limiter(1);
    const { make, issued } = throttled(rl, { agent: "a" });
    await make().authChallenge("wimse://notme.bot/test/one");
    await expect(make().authChallenge("wimse://notme.bot/test/two")).rejects.toThrow(/rate limited/);
    expect(issued).toHaveLength(1);
    // The key is the binding's props, and nothing the caller chose.
    expect(new Set(rl.keys)).toEqual(new Set([`authchallenge:${JSON.stringify({ agent: "a" })}`]));
  });

  it("auth.challenge.per-binding — one binding's flood does not spend another binding's budget", async () => {
    const rl = limiter(1);
    const a = throttled(rl, { agent: "a" });
    const b = throttled(rl, { agent: "b" });
    await a.make().authChallenge(IDENTITY);
    await expect(a.make().authChallenge(IDENTITY)).rejects.toThrow(/rate limited/);
    await expect(b.make().authChallenge(IDENTITY)).resolves.toMatchObject({ expires_in: 60 });
  });
});
