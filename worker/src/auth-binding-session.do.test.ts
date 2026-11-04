/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * auth-binding-session.do.test.ts — AuthService over a REAL service binding
 * (the loopback `exports.AuthService` workerd provides), against the real
 * SigningAuthority (notme-fbbfbc).
 *
 * Two measured facts this pins:
 *
 * 1. REACHABILITY. Each top-level call on a service binding is its own RPC
 *    session with a fresh AuthService `this`, so `#heldCerts` set by
 *    authenticate() is gone by the next call. The review's F2 attack —
 *    authenticate() with a victim's public certs, then proxy() — therefore
 *    did not chain end to end over a plain binding in this runtime. The
 *    possession check is required anyway: the design intends one session to
 *    hold its credentials, and a runtime or entrypoint change (an RpcTarget,
 *    a long-lived session) would make the gap live.
 * 2. THE PoP PATH WORKS OVER A BINDING. authChallenge() and authenticate()
 *    serialize (strings only — no CryptoKey), and the challenge is spent in
 *    the real DO, once.
 */
import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { AUTH_METHOD } from "./auth/session";
import { popProofs } from "./__tests__/helpers/mint-creds";

const IDENTITY = "wimse://notme.bot/principal/binding-session";

async function pem(key: CryptoKey) {
  const spki = (await crypto.subtle.exportKey("spki", key)) as ArrayBuffer;
  return `-----BEGIN PUBLIC KEY-----\n${btoa(String.fromCharCode(...new Uint8Array(spki))).match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
}

async function realCreds() {
  const authority: any = (env as any).SIGNING_AUTHORITY.get((env as any).SIGNING_AUTHORITY.idFromName("default"));
  const mtls = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const signing = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const r = await authority.mintBridgeCertPair({
    subject: "binding-session",
    identity: IDENTITY,
    mtlsPublicKeyPem: await pem(mtls.publicKey),
    signingPublicKeyPem: await pem(signing.publicKey),
    scopes: ["bridgeCert"],
    authMethod: AUTH_METHOD.ghaOidc,
  });
  return {
    mtlsCert: r.certificates.mtls as string,
    signingCert: r.certificates.signing as string,
    mtlsKey: mtls.privateKey,
    signingKey: signing.privateKey,
  };
}

const auth = () => (exports as any).AuthService;

describe("AuthService over a real service binding (notme-fbbfbc)", () => {
  it("auth.binding.session — held credentials do not outlive the call that set them", async () => {
    const creds = await realCreds();
    const { challenge } = await auth().authChallenge(IDENTITY);
    await auth().authenticate({
      mtlsCert: creds.mtlsCert,
      signingCert: creds.signingCert,
      challenge,
      proofs: await popProofs(creds, challenge),
    });
    // A separate call is a separate session: nothing is held.
    expect((await auth().identity()).authenticated).toBe(false);
  });

  it("auth.binding.pop — certs alone are refused over the binding; a spent challenge is refused", async () => {
    const creds = await realCreds();
    let refused = "";
    try {
      await auth().authenticate({ mtlsCert: creds.mtlsCert, signingCert: creds.signingCert });
    } catch (e) {
      refused = (e as Error).message;
    }
    expect(refused).toMatch(/challenge/);

    const { challenge } = await auth().authChallenge(IDENTITY);
    const presented = {
      mtlsCert: creds.mtlsCert,
      signingCert: creds.signingCert,
      challenge,
      proofs: await popProofs(creds, challenge),
    };
    await auth().authenticate(presented);
    let replay = "";
    try {
      await auth().authenticate(presented);
    } catch (e) {
      replay = (e as Error).message;
    }
    expect(replay).toMatch(/challenge/);
  });
});
