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
function services(authorityEpoch: number | (() => number) = 1) {
  const env = {
    ...stubEnv(CA),
    PROXY_ALLOWED_DESTINATIONS: "api.github.com",
  };
  // getAuthorityState for the epoch gate proxy() and sign() run; a function
  // lets a test move the epoch mid-call.
  const authority = env.SIGNING_AUTHORITY.get() as Record<string, unknown>;
  authority.getAuthorityState = async () => ({
    epoch: typeof authorityEpoch === "function" ? authorityEpoch() : authorityEpoch,
    seqno: 1,
    keyId: "k",
  });
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

  it("auth.pop.cheap-first — a missing or stale challenge is refused before any DO call or X.509 parse", async () => {
    const env = stubEnv(CA);
    const authority = env.SIGNING_AUTHORITY.get() as Record<string, unknown>;
    const getPem = vi.fn(authority.getPublicKeyPem as () => Promise<string>);
    authority.getPublicKeyPem = getPem;
    const svc = new (AuthService as unknown as new (c: unknown, e: unknown) => AuthService)(null, env);
    const junk = { mtlsCert: "not a cert", signingCert: "not a cert", proofs: { mtls: "", signing: "" } };
    await expect(svc.authenticate({ ...junk } as never)).rejects.toThrow(/challenge required/);
    await expect(svc.authenticate({ ...junk, challenge: `1.${"A".repeat(43)}` } as never)).rejects.toThrow(
      /challenge expired/,
    );
    expect(getPem).not.toHaveBeenCalled();
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

  it("auth.pop.no-keys — PoP authenticates with strings alone; no key is taken, and sign() without a signer refuses", async () => {
    const svc = services()();
    const creds = await mintCreds(CA, IDENTITY, ["bridgeCert", "sign:attestation"]);
    const { challenge } = await svc.authChallenge(IDENTITY);
    // A private key handed to authenticate() is ignored: the session holds
    // none (notme-153f03). Signing goes through the caller's signer.
    const session = await svc.authenticate({
      mtlsCert: creds.mtlsCert,
      signingCert: creds.signingCert,
      challenge,
      proofs: await popProofs(creds, challenge),
      signingKey: creds.signingKey,
    } as never);
    expect((await session.identity()).authenticated).toBe(true);
    await expect(session.sign(new Uint8Array([1]).buffer, "raw", undefined as never)).rejects.toThrow(/signer/);
  });
});

describe("AuthSession.sign() — the gates run before the agent's signer is asked (notme-153f03)", () => {
  const signerOf = (key: CryptoKey) => vi.fn(async (b: ArrayBuffer) => crypto.subtle.sign({ name: "Ed25519" }, key, b));
  const signAudits = (logs: string[]) => logs.map((l) => JSON.parse(l)).filter((r) => r.type === "sign");
  const SIGNS = ["bridgeCert", "sign:attestation"];

  it("auth.sign.epoch — a revoked epoch refuses before the signer is called, and is audited", async () => {
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((l: unknown) => void logs.push(String(l)));
    const creds = await mintCreds(CA, IDENTITY, SIGNS, 1);
    const session = await authenticateWithPop(services(2)(), creds);
    const signer = signerOf(creds.signingKey);

    await expect(session.sign(new Uint8Array([1]).buffer, "raw", signer)).rejects.toThrow(/revoked/);

    expect(signer).not.toHaveBeenCalled();
    expect(signAudits(logs).at(-1)).toMatchObject({ allowed: false, reason: "epoch_mismatch", identity: IDENTITY });
  });

  it("auth.sign.expired — expired certs refuse before the signer is called, and are audited", async () => {
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((l: unknown) => void logs.push(String(l)));
    const creds = await mintCreds(CA, IDENTITY, SIGNS);
    const session = await authenticateWithPop(services()(), creds);
    const signer = signerOf(creds.signingKey);
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 24 * 3600 * 1000);

    await expect(session.sign(new Uint8Array([1]).buffer, "raw", signer)).rejects.toThrow(/expired/);

    expect(signer).not.toHaveBeenCalled();
    expect(signAudits(logs).at(-1)).toMatchObject({ allowed: false, reason: "credentials_expired" });
  });

  it("auth.sign.scope — EVERY format needs a sign:* scope, raw included, checked before the signer", async () => {
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((l: unknown) => void logs.push(String(l)));
    const creds = await mintCreds(CA, IDENTITY, ["bridgeCert"]);
    const session = await authenticateWithPop(services()(), creds);
    const signer = signerOf(creds.signingKey);

    for (const format of ["raw", "dsse", "git-commit"] as const) {
      await expect(session.sign(new Uint8Array([1]).buffer, format, signer), format).rejects.toThrow(
        /scope insufficient/,
      );
    }

    expect(signer).not.toHaveBeenCalled();
    expect(signAudits(logs).map((r) => r.reason)).toEqual(["scope_insufficient", "scope_insufficient", "scope_insufficient"]);
  });

  it("auth.sign.claimed-format — the format is the caller's CLAIM: audited as claimed_format, not gated per format", async () => {
    // format is not bound into the signature (git and DSSE verifiers need a
    // signature over their own bytes, so it cannot be), so a per-format scope
    // check would be a pretence: any sign:* scope signs any claimed format.
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((l: unknown) => void logs.push(String(l)));
    const creds = await mintCreds(CA, IDENTITY, SIGNS);
    const session = await authenticateWithPop(services()(), creds);

    await session.sign(new Uint8Array([7]), "git-commit", signerOf(creds.signingKey));

    const line = signAudits(logs).at(-1);
    expect(line).toMatchObject({ allowed: true, claimed_format: "git-commit", scope_checked: "sign:attestation" });
    expect(line).not.toHaveProperty("format");
  });

  it("auth.sign.verified — the signer's signature is returned only after it verifies under the signing cert", async () => {
    const creds = await mintCreds(CA, IDENTITY, SIGNS);
    const other = await mintCreds(CA, "wimse://notme.bot/test/other-key");
    const session = await authenticateWithPop(services()(), creds);
    const payload = new TextEncoder().encode("payload");

    const good = await session.sign(payload, "raw", signerOf(creds.signingKey));
    expect(new Uint8Array(good.signature).length).toBe(64);
    await expect(session.sign(payload, "raw", signerOf(other.signingKey))).rejects.toThrow(
      /signature does not verify/,
    );
    // A signer returning something that is not a signature at all.
    await expect(session.sign(payload, "raw", async () => "nope" as never)).rejects.toThrow(
      /signature does not verify|signer returned/,
    );
  });
});

describe("AuthSession.sign() — nothing is returned if the session changed while the signer ran (notme-153f03)", () => {
  const signAudits = (logs: string[]) => logs.map((l) => JSON.parse(l)).filter((r) => r.type === "sign");
  const SIGNS = ["bridgeCert", "sign:attestation"];
  function capture() {
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((l: unknown) => void logs.push(String(l)));
    return logs;
  }

  it("auth.sign.timeout — a signer that stalls is cut off at 10 s, refused and audited", async () => {
    const logs = capture();
    const creds = await mintCreds(CA, IDENTITY, SIGNS);
    const session = await authenticateWithPop(services()(), creds);
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    let asked = false;
    const stalled = session.sign(new Uint8Array([1]), "raw", () => {
      asked = true;
      return new Promise<ArrayBuffer>(() => {});
    });
    stalled.catch(() => {});
    await vi.waitFor(() => expect(asked).toBe(true));
    await vi.advanceTimersByTimeAsync(9_000);
    let settled = false;
    void stalled.then(
      () => (settled = true),
      () => (settled = true),
    );
    await Promise.resolve();
    expect(settled, "refused before the 10 s bound").toBe(false);
    await vi.advanceTimersByTimeAsync(1_500);
    await expect(stalled).rejects.toThrow(/timed out/);
    expect(signAudits(logs).at(-1)).toMatchObject({ allowed: false, reason: "signer_timeout" });
  });

  it("auth.sign.expired-during — certs that expire while the signer runs: refused, not returned", async () => {
    const logs = capture();
    const creds = await mintCreds(CA, IDENTITY, SIGNS);
    const session = await authenticateWithPop(services()(), creds);
    vi.useFakeTimers({ toFake: ["Date"] });
    const result = session.sign(new Uint8Array([1]), "raw", async (b: ArrayBuffer) => {
      const sig = await crypto.subtle.sign({ name: "Ed25519" }, creds.signingKey, b);
      vi.setSystemTime(Date.now() + 24 * 3600 * 1000); // the cert lapses mid-call
      return sig;
    });
    await expect(result).rejects.toThrow(/expired/);
    expect(signAudits(logs).at(-1)).toMatchObject({ allowed: false, reason: "credentials_expired" });
  });

  it("auth.sign.revoked-during — an epoch moved while the signer ran: refused, not returned", async () => {
    const logs = capture();
    let epoch = 1;
    const creds = await mintCreds(CA, IDENTITY, SIGNS, 1);
    const session = await authenticateWithPop(services(() => epoch)(), creds);
    const result = session.sign(new Uint8Array([1]), "raw", async (b: ArrayBuffer) => {
      const sig = await crypto.subtle.sign({ name: "Ed25519" }, creds.signingKey, b);
      epoch = 2; // revokeEpoch() lands mid-call
      return sig;
    });
    await expect(result).rejects.toThrow(/revoked/);
    expect(signAudits(logs).at(-1)).toMatchObject({ allowed: false, reason: "revoked_during_sign" });
  });

  it("auth.sign.disposed-during — a session disposed while the signer ran: refused, not returned", async () => {
    const logs = capture();
    const creds = await mintCreds(CA, IDENTITY, SIGNS);
    const session = await authenticateWithPop(services()(), creds);
    const result = session.sign(new Uint8Array([1]), "raw", async (b: ArrayBuffer) => {
      const sig = await crypto.subtle.sign({ name: "Ed25519" }, creds.signingKey, b);
      session[Symbol.dispose]();
      return sig;
    });
    await expect(result).rejects.toThrow(/disposed/);
    expect(signAudits(logs).at(-1)).toMatchObject({ allowed: false, reason: "not_authenticated" });
  });
});

describe("AuthSession expiry drops the credentials, as dispose does (notme-153f03)", () => {
  it("auth.session.expiry-drops — after expiry identity() is unauthenticated and the certs are gone for good", async () => {
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((l: unknown) => void logs.push(String(l)));
    const creds = await mintCreds(CA, IDENTITY, ["bridgeCert", "sign:attestation"]);
    const session = await authenticateWithPop(services()(), creds);
    expect((await session.identity()).authenticated).toBe(true);
    const realNow = Date.now();

    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(realNow + 24 * 3600 * 1000);
    const expired = await session.identity();
    expect(expired).toMatchObject({ authenticated: false, identity: "", certificates: { mtls: "", signing: "" } });

    // Dropped, not merely hidden: winding the clock back does not revive it.
    vi.setSystemTime(realNow);
    expect((await session.identity()).authenticated).toBe(false);
    expect(logs.map((l) => JSON.parse(l)).find((r) => r.type === "session")).toMatchObject({
      event: "expired",
      identity: IDENTITY,
    });
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
    await expect(
      session.sign(new Uint8Array([1]).buffer, "raw", async (b: ArrayBuffer) =>
        crypto.subtle.sign({ name: "Ed25519" }, creds.signingKey, b),
      ),
    ).rejects.toThrow(/disposed/);
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

  it("auth.challenge.fallback — with CERT_LIMITER unbound, a per-isolate limiter still bounds it", async () => {
    // Self-hosted workerd (config.capnp) binds no rate limiter. Unique props
    // per test run: the fallback is module state, shared by this isolate.
    const props = { agent: `fallback-${crypto.randomUUID()}` };
    const env = stubEnv(CA, { limiter: false });
    const make = () =>
      new (AuthService as unknown as new (c: unknown, e: unknown) => AuthService)({ props }, env);
    let granted = 0;
    let refused = "";
    for (let i = 0; i < 50 && !refused; i++) {
      try {
        await make().authChallenge(IDENTITY);
        granted++;
      } catch (e) {
        refused = (e as Error).message;
      }
    }
    expect(refused).toMatch(/rate limited/);
    expect(granted).toBe(10);
    // Another binding's bucket is untouched.
    const otherProps = { agent: `fallback-other-${crypto.randomUUID()}` };
    await expect(
      new (AuthService as unknown as new (c: unknown, e: unknown) => AuthService)({ props: otherProps }, env).authChallenge(IDENTITY),
    ).resolves.toMatchObject({ expires_in: 60 });
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

describe("authChallenge() with no binding props — per identity AND a shared cap (notme-153f03, review M1)", () => {
  // Props-less callers share a binding identity, so the props bucket alone
  // let one agent lock out every peer. Now each claimed identity has its own
  // 10 / 60 s bucket, and a per-isolate shared cap bounds how many rows all
  // props-less callers together can make the authority write.
  const make = (env: unknown = stubEnv(CA, { limiter: false })) =>
    new (AuthService as unknown as new (c: unknown, e: unknown) => AuthService)(null, env);
  const id = (n: string) => `wimse://notme.bot/test/noprops-${n}-${crypto.randomUUID()}`;

  /**
   * Fresh fixed windows for the shared cap, which is per-isolate module
   * state: run `days` in the future. When real time resumes, a window whose
   * start lies in the future is treated as stale.
   */
  function fresh(days: number) {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + days * 24 * 3600 * 1000);
  }

  async function drain(call: () => Promise<unknown>, max = 200): Promise<{ granted: number; refused: string }> {
    let granted = 0;
    for (let i = 0; i < max; i++) {
      try {
        await call();
        granted++;
      } catch (e) {
        return { granted, refused: (e as Error).message };
      }
    }
    return { granted, refused: "" };
  }

  it("auth.challenge.noprops-per-identity — identity A draining its budget does not refuse identity B", async () => {
    fresh(100);
    const env = stubEnv(CA, { limiter: false });
    const a = id("a");
    const b = id("b");
    const drained = await drain(() => make(env).authChallenge(a));
    expect(drained).toMatchObject({ granted: 10, refused: expect.stringMatching(/rate limited/) });
    // A keeps hammering; none of it reaches B.
    for (let i = 0; i < 20; i++) await expect(make(env).authChallenge(a)).rejects.toThrow(/rate limited/);
    await expect(make(env).authChallenge(b)).resolves.toMatchObject({ expires_in: 60 });
  });

  it("auth.challenge.noprops-per-identity-bound — with CERT_LIMITER bound, the identity bucket is keyed there too", async () => {
    fresh(200);
    const keys: string[] = [];
    const env = {
      ...stubEnv(CA),
      CERT_LIMITER: {
        limit: async ({ key }: { key: string }) => {
          keys.push(key);
          return { success: keys.filter((k) => k === key).length <= 10 };
        },
      },
    };
    const a = id("bound-a");
    const b = id("bound-b");
    expect(await drain(() => make(env).authChallenge(a))).toMatchObject({ granted: 10 });
    await expect(make(env).authChallenge(b)).resolves.toMatchObject({ expires_in: 60 });
    expect(new Set(keys)).toEqual(new Set([`authchallenge:null:id:${a}`, `authchallenge:null:id:${b}`]));
  });

  it("auth.challenge.noprops-shared-cap — rotating claimed identities is still bounded by the shared cap", async () => {
    fresh(365);
    let n = 0;
    const flood = await drain(() => make().authChallenge(id(`rot-${n++}`)));
    expect(flood.refused).toMatch(/rate limited/);
    expect(flood.granted).toBe(60);
  });
});
