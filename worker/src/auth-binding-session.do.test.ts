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
import { afterEach, describe, expect, it, vi } from "vitest";
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
    // What a binding caller CAN send: CryptoKey does not serialize over RPC
    // (rpc.cryptokey.isolation), PKCS#8 bytes do.
    signingKeyPkcs8: (await crypto.subtle.exportKey("pkcs8", signing.privateKey)) as ArrayBuffer,
  };
}

type Creds = Awaited<ReturnType<typeof realCreds>>;

const auth = () => (exports as any).AuthService;

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

  it("auth.session.sign — authenticate with the signing key's PKCS#8 bytes, then session.sign() signs as the cert", async () => {
    const creds = await realCreds("binding-signer", ["bridgeCert", "sign:git"]);
    const session = await sessionOver(creds, { signingKeyPkcs8: creds.signingKeyPkcs8 });

    const payload = new TextEncoder().encode("tree abc\n\ncommit");
    const signed = await session.sign(payload.buffer, "git-commit");

    expect(signed.identity).toBe(creds.identity);
    expect(signed.certificate).toBe(creds.signingCert);
    expect(
      await crypto.subtle.verify({ name: "Ed25519" }, creds.signingPublicKey, signed.signature, payload),
    ).toBe(true);
    session[Symbol.dispose]();
  });

  it("auth.session.sign.key-mismatch — a signing key that is not the signing cert's is refused at authenticate()", async () => {
    const creds = await realCreds("binding-mismatch");
    const other = await realCreds("binding-mismatch-other");
    expect(await refusal(() => sessionOver(creds, { signingKeyPkcs8: other.signingKeyPkcs8 }))).toMatch(
      /signing key does not match/,
    );
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
    const alice = await realCreds("binding-alice", ["bridgeCert"]);
    const bob = await realCreds("binding-bob", ["bridgeCert", "sign:git"]);

    const a = await sessionOver(alice, { signingKeyPkcs8: alice.signingKeyPkcs8 });
    const b = await sessionOver(bob, { signingKeyPkcs8: bob.signingKeyPkcs8 });

    // A, after B authenticated, is still A — in identity, audit and signature.
    expect((await a.identity()).identity).toBe(alice.identity);
    expect((await a.identity()).scopes).toEqual(["bridgeCert"]);
    expect((await b.identity()).identity).toBe(bob.identity);

    await a.proxy({ url: PROXY_DEST });
    expect(audit.filter((l) => l.type === "proxy").at(-1)).toMatchObject({ identity: alice.identity });

    const payload = new TextEncoder().encode("hello");
    const signed = await a.sign(payload.buffer, "raw");
    expect(signed.identity).toBe(alice.identity);
    expect(signed.certificate).toBe(alice.signingCert);
    expect(await crypto.subtle.verify({ name: "Ed25519" }, alice.signingPublicKey, signed.signature, payload)).toBe(true);
    expect(await crypto.subtle.verify({ name: "Ed25519" }, bob.signingPublicKey, signed.signature, payload)).toBe(false);

    // A cannot borrow B's scope: git-commit needs sign:git, which only B holds.
    expect(await refusal(() => a.sign(payload.buffer, "git-commit"))).toMatch(/scope insufficient/);

    a[Symbol.dispose]();
    b[Symbol.dispose]();
  });

  it("auth.session.no-top-level — the entrypoint no longer offers proxy/sign/identity to hold state it cannot keep", async () => {
    const stub = auth();
    for (const name of ["proxy", "sign", "identity"]) {
      const message = await refusal(() => stub[name]({ url: PROXY_DEST }));
      expect(message, `${name} must not be callable on AuthService`).toMatch(/does not implement/);
    }
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
