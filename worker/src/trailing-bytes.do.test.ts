/// <reference types="@cloudflare/vitest-plugin/types" />
/**
 * trailing-bytes.do.test.ts — a caller-supplied certificate or public key
 * whose DER carries bytes after the outer structure is refused, cleanly, on
 * every route that takes one (notme-3ee3b0).
 *
 * WHY. @peculiar/x509 3.0.0's one breaking change: "DER/BER input with
 * trailing bytes now throws". Before it (1.14.3) such a certificate parsed,
 * its signature verified (the signature covers the TBSCertificate, not what
 * follows the outer SEQUENCE), and `rawData` kept the extra bytes, so
 * authenticate() and the x509 connection proof ACCEPTED it: run against
 * 1.14.3, the authenticate() and /connections cases below fail by succeeding.
 * The library now refuses, and these tests pin that the refusal reaches the
 * caller as a 4xx or a named error, never a 500 or the library's internals.
 *
 * Public keys never pass through x509: importPublicKey hands the SPKI to
 * WebCrypto. workerd's importKey("spki") refuses trailing bytes itself (so
 * those cases passed on 1.14.3 too; Node's WebCrypto, by contrast, accepts
 * them). They are here so a key and a certificate stay held to one rule
 * whichever layer enforces it.
 */
import { runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import worker from "../worker";
import { AUTH_METHOD, createSessionCookie } from "./auth/session";
import { getPrincipal, grantCapability } from "./auth/principals";
import { popProofs } from "./__tests__/helpers/mint-creds";
import type { SigningAuthority } from "./signing-authority";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };
const TRAILING = [0x00, 0x00];

const b64 = (d: Uint8Array) => btoa(String.fromCharCode(...d));
const b64u = (d: Uint8Array) => b64(d).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const wrap = (d: Uint8Array, label: string) =>
  `-----BEGIN ${label}-----\n${b64(d).match(/.{1,64}/g)!.join("\n")}\n-----END ${label}-----`;
const unwrap = (pem: string) =>
  Uint8Array.from(atob(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "")), (c) => c.charCodeAt(0));
/** The same PEM with two zero bytes after the DER. */
const padded = (pem: string, label: string) => wrap(new Uint8Array([...unwrap(pem), ...TRAILING]), label);

const authority = () => (env as any).SIGNING_AUTHORITY.get((env as any).SIGNING_AUTHORITY.idFromName("default"));

/** No stack frames, no module paths, no library internals in what a caller sees. */
function expectClean(text: string) {
  expect(text).not.toMatch(/\n\s+at |node_modules|\.ts:\d|\.js:\d|ASN\.1/);
}

async function sessionCookie(principalId: string): Promise<string> {
  const stub = authority();
  await runInDurableObject(stub, (a) => {
    const sql = (a as SigningAuthority)["ctx"].storage.sql;
    if (!getPrincipal(sql, principalId)) return (a as SigningAuthority).createPrincipalWithCapabilities(principalId, ["bridgeCert"]);
    grantCapability(sql, principalId, "bridgeCert", "test");
  });
  return createSessionCookie({ principalId, scopes: ["bridgeCert"], authMethod: "passkey" }, await stub.getSessionSecret());
}

async function fetchNonce(cookie: string): Promise<string> {
  const res = await worker.fetch(new Request(`${ORIGIN}/cert/nonce`, { method: "POST", headers: { cookie } }), { ...env, ...LOCAL_ENV });
  expect(res.status).toBe(200);
  return ((await res.json()) as { nonce: string }).nonce;
}

/**
 * Keys + proofs for a session-bound cert pair (/cert and /cert/passkey share
 * the binding). The proofs are over the CANONICAL SPKIs, which is what the
 * route re-exports before it checks them, so the only thing wrong with a
 * padded request is the padding.
 */
async function pairRequest(nonce: string, pad: "mtls" | "signing" | null) {
  const mtls = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const signing = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const mtlsSpki = new Uint8Array((await crypto.subtle.exportKey("spki", mtls.publicKey)) as ArrayBuffer);
  const signingSpki = new Uint8Array((await crypto.subtle.exportKey("spki", signing.publicKey)) as ArrayBuffer);
  const { certPairBinding } = await import("./auth/cert-pair-binding");
  const input = await certPairBinding(mtlsSpki, signingSpki, nonce);
  const mtlsPem = wrap(mtlsSpki, "PUBLIC KEY");
  const signingPem = wrap(signingSpki, "PUBLIC KEY");
  return {
    nonce,
    public_keys: {
      mtls: pad === "mtls" ? padded(mtlsPem, "PUBLIC KEY") : mtlsPem,
      signing: pad === "signing" ? padded(signingPem, "PUBLIC KEY") : signingPem,
    },
    proofs: {
      mtls: b64u(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, mtls.privateKey, input))),
      signing: b64u(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, signing.privateKey, input))),
    },
  };
}

function post(path: string, body: unknown, cookie?: string) {
  return worker.fetch(
    new Request(`${ORIGIN}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(cookie ? { cookie } : {}) },
      body: JSON.stringify(body),
    }),
    { ...env, ...LOCAL_ENV },
  );
}

async function realCreds(name: string) {
  const mtls = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const signing = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const spkiPem = async (k: CryptoKey) => wrap(new Uint8Array((await crypto.subtle.exportKey("spki", k)) as ArrayBuffer), "PUBLIC KEY");
  const identity = `wimse://notme.bot/principal/${name}`;
  const r = await authority().mintBridgeCertPair({
    subject: name,
    identity,
    mtlsPublicKeyPem: await spkiPem(mtls.publicKey),
    signingPublicKeyPem: await spkiPem(signing.publicKey),
    scopes: ["bridgeCert"],
    authMethod: AUTH_METHOD.ghaOidc,
  });
  return {
    identity,
    mtlsCert: r.certificates.mtls as string,
    signingCert: r.certificates.signing as string,
    mtlsKey: mtls.privateKey,
    signingKey: signing.privateKey,
  };
}

/** The message an RPC call is refused with ("" if it was not); see auth-binding-session.do.test.ts. */
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

describe("trailing bytes after a caller's DER (notme-3ee3b0)", () => {
  it("the library refuses a certificate with trailing bytes (the x509 3.0.0 change itself)", async () => {
    const { X509Certificate } = await import("@peculiar/x509");
    const { signingCert } = await realCreds("trailing-lib");
    expect(() => new X509Certificate(signingCert)).not.toThrow();
    expect(() => new X509Certificate(padded(signingCert, "CERTIFICATE"))).toThrow(/trailing bytes/);
  });

  describe("AuthSession authenticate()", () => {
    let props = { test: "" };
    const auth = () => (exports as any).AuthService({ props });

    for (const which of ["signingCert", "mtlsCert"] as const) {
      it(`refuses a ${which} with trailing bytes, with a named error and no session`, async () => {
        props = { test: crypto.randomUUID() };
        const creds = await realCreds(`trailing-auth-${which}`);
        const { challenge } = await auth().authChallenge(creds.identity);
        const proofs = await popProofs(creds as any, challenge);
        const msg = await refusal(() =>
          auth().authenticate({
            mtlsCert: creds.mtlsCert,
            signingCert: creds.signingCert,
            [which]: padded(creds[which], "CERTIFICATE"),
            challenge,
            proofs,
          }),
        );
        const what = which === "signingCert" ? "signing" : "mTLS";
        expect(msg).toBe(`${what} cert is not a well-formed DER certificate`);
        expectClean(msg);
        // The challenge was not spent by the refused attempt: the same proofs
        // over the clean certs still authenticate.
        const session = await auth().authenticate({ mtlsCert: creds.mtlsCert, signingCert: creds.signingCert, challenge, proofs });
        expect(await session.identity()).toMatchObject({ identity: creds.identity });
      });
    }
  });

  it("POST /connections refuses an x509 proof with trailing bytes (401, constant body)", async () => {
    const cookie = await sessionCookie("trailing-connections");
    // A cert the authority itself issued, at its current epoch: only the
    // padding is wrong.
    const { signingCert } = await realCreds("trailing-conn-subject");
    const ok = await post("/connections", { proof: { type: "x509", cert: signingCert } }, cookie);
    expect(ok.status).toBe(200);
    const res = await post("/connections", { proof: { type: "x509", cert: padded(signingCert, "CERTIFICATE") } }, cookie);
    expect(res.status).toBe(401);
    const text = await res.text();
    expect(JSON.parse(text)).toEqual({ error: "proof verification failed" });
    expectClean(text);
  });

  for (const route of ["/cert", "/cert/passkey"] as const) {
    for (const pad of ["mtls", "signing"] as const) {
      it(`POST ${route} refuses a ${pad} public key with trailing bytes (400, constant body)`, async () => {
        const cookie = await sessionCookie(`trailing${route.replace(/\//g, "-")}-${pad}`);
        const body = (b: object) => (route === "/cert" ? { proof: { type: "session" }, ...b } : b);
        // Control: the same request, unpadded, mints.
        const good = await post(route, body(await pairRequest(await fetchNonce(cookie), null)), cookie);
        expect(good.status).toBe(200);
        const res = await post(route, body(await pairRequest(await fetchNonce(cookie), pad)), cookie);
        expect(res.status).toBe(400);
        const text = await res.text();
        expect(JSON.parse(text)).toEqual({ error: "invalid public key" });
        expectClean(text);
      });
    }
  }

  it("tier enrolment refuses a public key with trailing bytes (400), at start and at renewal", async () => {
    const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const pem = wrap(new Uint8Array((await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer), "PUBLIC KEY");

    const good = await post("/cert/issuing-ca/device", { public_key: pem });
    expect(good.status).toBe(200);
    const start = await post("/cert/issuing-ca/device", { public_key: padded(pem, "PUBLIC KEY") });
    expect(start.status).toBe(400);
    const startText = await start.text();
    expect(JSON.parse(startText)).toEqual({ error: "public_key must be an Ed25519 SPKI PEM" });
    expectClean(startText);

    // Renewal names the key the same way; a padded one is not a key it knows.
    const renew = await post("/cert/issuing-ca/renew", {
      public_key: padded(pem, "PUBLIC KEY"),
      iat: Math.floor(Date.now() / 1000),
      proof: "AAAA",
    });
    expect(renew.status).toBe(400);
    const renewText = await renew.text();
    expect(JSON.parse(renewText)).toEqual({ error: "invalid_key" });
    expectClean(renewText);
  });

  it("the DO refuses a padded enrolment key directly, not only through the route", async () => {
    const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const pem = wrap(new Uint8Array((await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer), "PUBLIC KEY");
    const r = await authority().startTierEnrolment({ publicKeyPem: padded(pem, "PUBLIC KEY"), requestedScopes: ["bridgeCert"] });
    expect(r).toEqual({ ok: false, reason: "invalid_key" });
  });
});
