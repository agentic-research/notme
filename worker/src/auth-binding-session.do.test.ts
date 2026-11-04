/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * auth-binding-session.do.test.ts — AuthService over a REAL service binding
 * (the loopback `exports.AuthService` workerd provides), against the real
 * SigningAuthority (notme-fbbfbc, notme-153f03).
 *
 * What it pins:
 *
 * 1. THE SESSION. Each top-level call on a service binding is its own RPC
 *    session with a fresh AuthService `this` — measured under notme-fbbfbc,
 *    when `authenticate()` stored the verified certs on `this` and a later
 *    `proxy()` / `sign()` call found nothing. So authenticate() now RETURNS
 *    an `AuthSession` (an `RpcTarget`): the caller receives a stub, and the
 *    verified certs live on the object behind it for exactly as long as the
 *    stub does. proxy(), sign() and identity() are its methods.
 * 2. DISPOSAL. A disposed stub cannot be called, and the session's own
 *    disposer drops the held credentials.
 * 3. NO CROSS-IDENTITY USE. Two sessions over one binding each act only as
 *    the identity they proved.
 * 4. THE PoP PATH WORKS OVER A BINDING. authChallenge() and authenticate()
 *    serialize (strings only — no CryptoKey), and the challenge is spent in
 *    the real DO, once.
 */
import { env, exports } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AUTH_METHOD } from "./auth/session";
import { popProofs } from "./__tests__/helpers/mint-creds";

/** The one host the pool's PROXY_ALLOWED_DESTINATIONS lists (vitest.workers.config.mts). */
const PROXY_DEST = "https://proxy-dest.notme.test/echo";

async function pem(key: CryptoKey) {
  const spki = (await crypto.subtle.exportKey("spki", key)) as ArrayBuffer;
  return `-----BEGIN PUBLIC KEY-----\n${btoa(String.fromCharCode(...new Uint8Array(spki))).match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
}

async function realCreds(name = "binding-session", scopes = ["bridgeCert"]) {
  const identity = `wimse://notme.bot/principal/${name}`;
  const authority: any = (env as any).SIGNING_AUTHORITY.get((env as any).SIGNING_AUTHORITY.idFromName("default"));
  const mtls = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const signing = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const r = await authority.mintBridgeCertPair({
    subject: name,
    identity,
    mtlsPublicKeyPem: await pem(mtls.publicKey),
    signingPublicKeyPem: await pem(signing.publicKey),
    scopes,
    authMethod: AUTH_METHOD.ghaOidc,
  });
  return {
    identity,
    mtlsCert: r.certificates.mtls as string,
    signingCert: r.certificates.signing as string,
    mtlsKey: mtls.privateKey,
    signingKey: signing.privateKey,
    signingPublicKey: signing.publicKey,
  };
}

type Creds = Awaited<ReturnType<typeof realCreds>>;

/**
 * The binding, specialised with `props` as an operator would set them per
 * binding. Fresh props per test: authChallenge() is rate limited per binding
 * props (notme-153f03), and this pool binds no CERT_LIMITER, so the
 * per-isolate fallback counts — one shared bucket would throttle the file.
 */
let props: { test: string } = { test: "init" };
beforeEach(() => {
  props = { test: crypto.randomUUID() };
});
const auth = () => (exports as any).AuthService({ props });

/** authChallenge + authenticate over the binding; returns the session STUB. */
async function sessionOver(creds: Creds, extra: Record<string, unknown> = {}) {
  const { challenge } = await auth().authChallenge(creds.identity);
  return auth().authenticate({
    mtlsCert: creds.mtlsCert,
    signingCert: creds.signingCert,
    challenge,
    proofs: await popProofs(creds, challenge),
    ...extra,
  });
}

/** Audit lines the session wrote (the entrypoint runs in this isolate). */
function captureAudit() {
  const lines: any[] = [];
  vi.spyOn(console, "log").mockImplementation((l: unknown) => {
    try {
      lines.push(JSON.parse(String(l)));
    } catch {
      /* not an audit line */
    }
  });
  return lines;
}

/**
 * The message an RPC call over the binding is refused with ("" if it was not).
 *
 * A refused workerd stub call leaves a second rejected promise behind, which
 * vitest reports as an unhandled error and fails the run on while every test
 * passes (see expectRpcRefusesCryptoKey in rpc-surface.do.test.ts). Attaching
 * a handler before awaiting gives that rejection an owner.
 */
async function refusal(call: () => unknown): Promise<string> {
  try {
    const p = call() as Promise<unknown>;
    p?.catch?.(() => {});
    await p;
  } catch (e) {
    return String((e as Error)?.message ?? e);
  }
  return "";
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("AuthService session over a real service binding (notme-153f03)", () => {
  it("auth.session.proxy — authenticate, then session.proxy() reaches the destination as the proven identity", async () => {
    const fetchSpy = vi.fn(async () => new Response("pong", { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);
    const audit = captureAudit();
    const creds = await realCreds();

    const session = await sessionOver(creds);
    const res = await session.proxy({ url: PROXY_DEST, headers: { host: "evil.example", "x-ok": "1" } });

    expect(res).toMatchObject({ status: 200, body: "pong" });
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    // Every gate still runs on the session: header stripping, for one.
    const sent = (fetchSpy.mock.calls[0] as unknown as [string, RequestInit])[1];
    const headers = new Headers(sent.headers);
    expect(headers.get("host")).toBeNull();
    expect(headers.get("x-ok")).toBe("1");
    expect(audit.find((l) => l.type === "proxy")).toMatchObject({
      allowed: true,
      identity: creds.identity,
      response_status: 200,
    });
    // And the allowlist: an unlisted host is refused and audited as such.
    expect(await refusal(() => session.proxy({ url: "https://evil.example/" }))).toMatch(/not allowed/);
    expect(audit.filter((l) => l.type === "proxy").at(-1)).toMatchObject({
      allowed: false,
      reason: "destination_not_allowed",
      identity: creds.identity,
    });
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    session[Symbol.dispose]();
  });

  it("auth.session.sign — session.sign() calls back to the agent's signer over the binding; the key never leaves the agent", async () => {
    const audit = captureAudit();
    const creds = await realCreds("binding-signer", ["bridgeCert", "sign:git"]);
    const session = await sessionOver(creds);

    const payload = new TextEncoder().encode("tree abc\n\ncommit");
    const seen: Uint8Array[] = [];
    // A function crosses the binding as a stub; calling it runs HERE, in the
    // caller, with the caller's key (Workers RPC, "Send functions as
    // parameters of RPC methods").
    const signer = async (bytes: ArrayBuffer) => {
      seen.push(new Uint8Array(bytes));
      return crypto.subtle.sign({ name: "Ed25519" }, creds.signingKey, bytes);
    };
    const signed = await session.sign(payload.buffer, "git-commit", signer);

    // The signer was asked to sign exactly the payload, once.
    expect(seen).toHaveLength(1);
    expect([...seen[0]!]).toEqual([...payload]);
    expect(signed.identity).toBe(creds.identity);
    expect(signed.certificate).toBe(creds.signingCert);
    expect(
      await crypto.subtle.verify({ name: "Ed25519" }, creds.signingPublicKey, signed.signature, payload),
    ).toBe(true);
    expect(audit.filter((l) => l.type === "sign").at(-1)).toMatchObject({
      allowed: true,
      identity: creds.identity,
      claimed_format: "git-commit",
    });
    session[Symbol.dispose]();
  });

  it("auth.session.sign.wrong-key — a signer that signs with a key other than the cert's is refused and audited", async () => {
    const audit = captureAudit();
    const creds = await realCreds("binding-mismatch", ["bridgeCert", "sign:attestation"]);
    const other = await realCreds("binding-mismatch-other");
    const session = await sessionOver(creds);
    const payload = new TextEncoder().encode("hello");

    const message = await refusal(() =>
      session.sign(payload.buffer, "raw", (bytes: ArrayBuffer) =>
        crypto.subtle.sign({ name: "Ed25519" }, other.signingKey, bytes),
      ),
    );

    expect(message).toMatch(/signature does not verify/);
    expect(audit.filter((l) => l.type === "sign").at(-1)).toMatchObject({
      allowed: false,
      reason: "signature_invalid",
      identity: creds.identity,
    });
    session[Symbol.dispose]();
  });

  it("auth.session.sign.signer-throws — a signer that throws is refused and audited", async () => {
    const audit = captureAudit();
    const creds = await realCreds("binding-signer-throws", ["bridgeCert", "sign:attestation"]);
    const session = await sessionOver(creds);

    const message = await refusal(() =>
      session.sign(new TextEncoder().encode("x").buffer, "raw", () => {
        throw new Error("hsm unplugged");
      }),
    );

    expect(message).toMatch(/signer failed/);
    expect(audit.filter((l) => l.type === "sign").at(-1)).toMatchObject({
      allowed: false,
      reason: "signer_failed",
      identity: creds.identity,
    });
    session[Symbol.dispose]();
  });

  it("auth.session.disposed — a disposed session stub cannot be used", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("pong")));
    const creds = await realCreds("binding-disposed");
    const session = await sessionOver(creds);
    expect((await session.identity()).identity).toBe(creds.identity);

    session[Symbol.dispose]();

    expect(await refusal(() => session.identity())).toMatch(/dispos/i);
    expect(await refusal(() => session.proxy({ url: PROXY_DEST }))).toMatch(/dispos/i);
  });

  it("auth.session.isolation — a session acts only as the identity it proved, whatever else authenticates", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("pong")));
    const audit = captureAudit();
    const alice = await realCreds("binding-alice", ["bridgeCert", "sign:attestation"]);
    const bob = await realCreds("binding-bob", ["bridgeCert", "sign:git"]);
    const carol = await realCreds("binding-carol", ["bridgeCert"]);

    const a = await sessionOver(alice);
    const b = await sessionOver(bob);
    const c = await sessionOver(carol);
    const signerFor = (key: CryptoKey) => (bytes: ArrayBuffer) => crypto.subtle.sign({ name: "Ed25519" }, key, bytes);

    // A, after B authenticated, is still A — in identity, audit and signature.
    expect((await a.identity()).identity).toBe(alice.identity);
    expect((await a.identity()).scopes).toEqual(["bridgeCert", "sign:attestation"]);
    expect((await b.identity()).identity).toBe(bob.identity);

    await a.proxy({ url: PROXY_DEST });
    expect(audit.filter((l) => l.type === "proxy").at(-1)).toMatchObject({ identity: alice.identity });

    const payload = new TextEncoder().encode("hello");
    const signed = await a.sign(payload.buffer, "raw", signerFor(alice.signingKey));
    expect(signed.identity).toBe(alice.identity);
    expect(signed.certificate).toBe(alice.signingCert);
    expect(await crypto.subtle.verify({ name: "Ed25519" }, alice.signingPublicKey, signed.signature, payload)).toBe(true);
    expect(await crypto.subtle.verify({ name: "Ed25519" }, bob.signingPublicKey, signed.signature, payload)).toBe(false);

    // A cannot be made to sign as B: B's key behind A's session does not verify
    // under A's cert, so nothing is returned that a verifier would attribute to A.
    expect(await refusal(() => a.sign(payload.buffer, "raw", signerFor(bob.signingKey)))).toMatch(
      /signature does not verify/,
    );
    // C cannot borrow A's or B's scope: C holds no sign:* scope, so even raw
    // signing with C's own key is refused, however many signers are around.
    expect(await refusal(() => c.sign(payload.buffer, "raw", signerFor(carol.signingKey)))).toMatch(
      /scope insufficient/,
    );

    a[Symbol.dispose]();
    b[Symbol.dispose]();
    c[Symbol.dispose]();
  });

  it("auth.session.no-top-level — the entrypoint no longer offers proxy/sign/identity to hold state it cannot keep", async () => {
    const stub = auth();
    for (const name of ["proxy", "sign", "identity"]) {
      const message = await refusal(() => stub[name]({ url: PROXY_DEST }));
      expect(message, `${name} must not be callable on AuthService`).toMatch(/does not implement/);
    }
  });

  it("auth.session.challenge-throttled — over a binding with no CERT_LIMITER, authChallenge() is still bounded per binding props", async () => {
    // This pool binds no rate limiter, as a self-hosted workerd config does
    // not: the per-isolate fallback is what answers.
    const granted: string[] = [];
    let refused = "";
    for (let i = 0; i < 20 && !refused; i++) {
      const m = await refusal(async () => granted.push((await auth().authChallenge(`wimse://notme.bot/principal/flood-${i}`)).challenge));
      if (m) refused = m;
    }
    expect(granted).toHaveLength(10);
    expect(refused).toMatch(/rate limited/);
    // A binding with other props has its own budget.
    props = { test: crypto.randomUUID() };
    expect(await refusal(() => auth().authChallenge("wimse://notme.bot/principal/other"))).toBe("");
  });
});

describe("AuthService PoP over a real service binding (notme-fbbfbc)", () => {
  it("auth.binding.pop — certs alone are refused over the binding; a spent challenge is refused", async () => {
    const creds = await realCreds();
    expect(
      await refusal(() => auth().authenticate({ mtlsCert: creds.mtlsCert, signingCert: creds.signingCert })),
    ).toMatch(/challenge/);

    const { challenge } = await auth().authChallenge(creds.identity);
    const presented = {
      mtlsCert: creds.mtlsCert,
      signingCert: creds.signingCert,
      challenge,
      proofs: await popProofs(creds, challenge),
    };
    const session = await auth().authenticate(presented);
    session[Symbol.dispose]();
    expect(await refusal(() => auth().authenticate(presented))).toMatch(/challenge/);
  });
});
