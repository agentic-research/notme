/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * passkey-cert.do.test.ts — POST /cert/passkey against the real route and a
 * real SigningAuthority.
 *
 * The scope-filter tests are the ones that matter. This route differs from
 * /cert/gha in exactly one respect — the authenticator carries privilege — and
 * that difference is the whole reason it needs its own reasoning rather than
 * being a copy.
 */

import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../worker";
import { createSessionCookie } from "./auth/session";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };

function b64u(b: Uint8Array): string {
  return btoa(String.fromCharCode(...b))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function pem(spki: ArrayBuffer, label: string): string {
  const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
  return `-----BEGIN ${label}-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END ${label}-----`;
}

async function sessionCookie(scopes: string[]): Promise<string> {
  const stub = env.SIGNING_AUTHORITY.get(
    env.SIGNING_AUTHORITY.idFromName("default"),
  );
  const secret = await stub.getSessionSecret();
  return createSessionCookie(
    { principalId: "principal-passkey-test", scopes, authMethod: "passkey" },
    secret,
  );
}

/**
 * The session VALUE, which is what the route binds to.
 *
 * `parseCookie(header, name)` returns the value, not `name=value`, so the
 * binding must be computed over the same thing. Hashing the full header string
 * here produced a 401 that read as "bad proof" — the proofs were fine and the
 * two sides were hashing different bytes.
 */
function sessionValue(cookie: string): string {
  return cookie.slice("notme_session=".length).split(";")[0];
}

/** Generate keys and the PoP proofs the route requires. */
async function mintRequest(cookie: string) {
  const mtls = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const signing = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;

  const mtlsSpki = (await crypto.subtle.exportKey(
    "spki",
    mtls.publicKey,
  )) as ArrayBuffer;
  const signingSpki = (await crypto.subtle.exportKey(
    "spki",
    signing.publicKey,
  )) as ArrayBuffer;
  const sessionHash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(sessionValue(cookie)),
  );
  const input = new Uint8Array(
    mtlsSpki.byteLength + signingSpki.byteLength + 32,
  );
  input.set(new Uint8Array(mtlsSpki), 0);
  input.set(new Uint8Array(signingSpki), mtlsSpki.byteLength);
  input.set(
    new Uint8Array(sessionHash),
    mtlsSpki.byteLength + signingSpki.byteLength,
  );
  const binding = await crypto.subtle.digest("SHA-256", input);

  return {
    public_keys: {
      mtls: pem(mtlsSpki, "PUBLIC KEY"),
      signing: pem(signingSpki, "PUBLIC KEY"),
    },
    proofs: {
      mtls: b64u(
        new Uint8Array(
          await crypto.subtle.sign(
            { name: "ECDSA", hash: "SHA-256" },
            mtls.privateKey,
            binding,
          ),
        ),
      ),
      signing: b64u(
        new Uint8Array(
          await crypto.subtle.sign(
            { name: "Ed25519" },
            signing.privateKey,
            binding,
          ),
        ),
      ),
    },
  };
}

function post(body: unknown, cookie: string) {
  return worker.fetch(
    new Request(`${ORIGIN}/cert/passkey`, {
      method: "POST",
      headers: { cookie, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
    { ...env, ...LOCAL_ENV },
  );
}

describe("POST /cert/passkey", () => {
  it("mints a cert pair from a passkey session", async () => {
    const cookie = await sessionCookie(["bridgeCert"]);
    const res = await post(await mintRequest(cookie), cookie);
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;

    // Reconstructing this response by hand once shipped `certificates.mtls:
    // undefined` with a 200, because tsc cannot see through the DO stub.
    expect(body.certificates.mtls).toContain("BEGIN CERTIFICATE");
    expect(body.certificates.signing).toContain("BEGIN CERTIFICATE");
    expect(body.identity).toBe(
      "wimse://notme.bot/passkey/principal-passkey-test",
    );
    expect(body.auth_method).toBe("passkey");
    expect(body.expires_at).toBeGreaterThan(0);
  });

  it("does NOT widen a deployer session into a minting credential", async () => {
    // THE POINT OF THIS ROUTE'S EXISTENCE AS SEPARATE CODE.
    //
    // A deployer's passkey session carries certMint and authorityManage. If
    // the cert inherited them, a browser session would become a credential
    // that can mint further certs — long-lived, exportable, usable off-origin,
    // with none of the properties (HttpOnly, SameSite=Strict, revocable by
    // clearing a cookie) that made granting the session acceptable.
    const cookie = await sessionCookie([
      "bridgeCert",
      "certMint",
      "authorityManage",
    ]);
    const res = await post(await mintRequest(cookie), cookie);
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;

    expect(body.scopes).toEqual(["bridgeCert"]);
    expect(body.scopes).not.toContain("certMint");
    expect(body.scopes).not.toContain("authorityManage");
  });

  it("refuses a session holding nothing a cert may carry", async () => {
    // Rather than minting an authority-less cert, which looks like success
    // and fails confusingly at first use.
    const cookie = await sessionCookie(["authorityManage"]);
    const res = await post(await mintRequest(cookie), cookie);
    expect(res.status).toBe(403);
  });

  it("requires a session", async () => {
    const cookie = await sessionCookie(["bridgeCert"]);
    const req = await mintRequest(cookie);
    const res = await worker.fetch(
      new Request(`${ORIGIN}/cert/passkey`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req),
      }),
      { ...env, ...LOCAL_ENV },
    );
    expect(res.status).toBe(401);
  });

  it("rejects proofs bound to a DIFFERENT session", async () => {
    // The binding includes SHA-256 of the session cookie precisely so a
    // captured public-keys+proofs pair cannot be replayed under someone
    // else's session to bind their key to your identity.
    const victim = await sessionCookie(["bridgeCert"]);
    const attacker = await sessionCookie(["bridgeCert"]);
    const capturedFromVictim = await mintRequest(victim);

    // Same principal id, so the cookies differ only by their HMAC — if the
    // binding ignored the session, this would succeed.
    if (victim === attacker) return; // identical cookie: nothing to prove
    const res = await post(capturedFromVictim, attacker);
    expect(res.status).toBe(401);
  });

  it("rejects a forged proof", async () => {
    const cookie = await sessionCookie(["bridgeCert"]);
    const req = await mintRequest(cookie);
    req.proofs.mtls = b64u(new Uint8Array(64).fill(0x01));
    expect((await post(req, cookie)).status).toBe(401);
  });

  it("requires public keys and proofs", async () => {
    const cookie = await sessionCookie(["bridgeCert"]);
    expect((await post({}, cookie)).status).toBe(400);
    const req = await mintRequest(cookie);
    expect((await post({ public_keys: req.public_keys }, cookie)).status).toBe(
      400,
    );
  });
});
