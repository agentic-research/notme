/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * issuing-ca.do.test.ts — POST /cert/issuing-ca mints the MIDDLE tier, and
 * only for a session that holds certMint (notme-acc822, ADR-019 D4).
 *
 * This route is what makes the tier a production capability rather than a
 * function only tests call — the repo's own recorded anti-pattern. It is also
 * the first surface where `certMint` is enforced ANYWHERE: until now the
 * scope was granted at bootstrap and checked by nothing.
 *
 * The narrowing story mirrors the leaf routes: the tier's scopes come from
 * narrowScopes(session, requested) ∩ CERT_ELIGIBLE_SCOPES, because an
 * Issuing CA certificate is as long-lived and exportable as any leaf — MORE
 * consequential, since its scopes bound every task cert below it.
 */
import { env } from "cloudflare:test";
import {
  BasicConstraintsExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  X509Certificate,
} from "@peculiar/x509";
import { describe, expect, it } from "vitest";
import worker from "../worker";
import { createSessionCookie } from "./auth/session";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };

async function sessionFor(scopes: string[]): Promise<string> {
  const stub = env.SIGNING_AUTHORITY.get(
    env.SIGNING_AUTHORITY.idFromName("default"),
  );
  const secret = await stub.getSessionSecret();
  return createSessionCookie(
    { principalId: "principal-issuing-test", scopes, authMethod: "passkey" },
    secret,
  );
}

function cookieValue(setCookie: string): string {
  return setCookie.split(";")[0].split("=").slice(1).join("=");
}

function pem(spki: ArrayBuffer): string {
  const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
  return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
}

/** Binding = spki || SHA-256(session cookie value) — pre-image, never digest. */
async function issuingRequest(cookie: string, opts?: { signDigest?: boolean }) {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const spki = (await crypto.subtle.exportKey(
    "spki",
    kp.publicKey,
  )) as ArrayBuffer;
  const cookieHash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(cookieValue(cookie)),
  );
  const binding = new Uint8Array(spki.byteLength + 32);
  binding.set(new Uint8Array(spki), 0);
  binding.set(new Uint8Array(cookieHash), spki.byteLength);
  const toSign = opts?.signDigest
    ? await crypto.subtle.digest("SHA-256", binding)
    : binding;
  const sig = await crypto.subtle.sign(
    { name: "Ed25519" },
    kp.privateKey,
    toSign,
  );
  return {
    public_key: pem(spki),
    proof: btoa(String.fromCharCode(...new Uint8Array(sig))),
  };
}

function post(body: unknown, cookie?: string) {
  return worker.fetch(
    new Request(`${ORIGIN}/cert/issuing-ca`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(cookie ? { cookie } : {}),
      },
      body: JSON.stringify(body),
    }),
    { ...env, ...LOCAL_ENV },
  );
}

describe("POST /cert/issuing-ca", () => {
  it("requires a session", async () => {
    const res = await post({});
    expect(res.status).toBe(401);
  });

  it("requires certMint — the scope's first enforcement site", async () => {
    const cookie = await sessionFor(["bridgeCert", "authorityManage"]);
    const res = await post(await issuingRequest(cookie), cookie);
    expect(res.status).toBe(403);
  });

  it("rejects a proof over the binding DIGEST — no legacy window here", async () => {
    const cookie = await sessionFor(["bridgeCert", "certMint"]);
    const res = await post(
      await issuingRequest(cookie, { signDigest: true }),
      cookie,
    );
    expect(res.status).toBe(401);
  });

  it("mints CA=true/pathlen=0/keyCertSign, scopes narrowed from the session", async () => {
    const cookie = await sessionFor([
      "bridgeCert",
      "certMint",
      "authorityManage",
    ]);
    const res = await post(
      { ...(await issuingRequest(cookie)), scopes: ["bridgeCert", "authorityManage"] },
      cookie,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      certificate: string;
      scopes: string[];
      principal_id: string;
    };
    expect(body.principal_id).toBe("principal-issuing-test");
    // authorityManage was requested AND held — but a certificate may not
    // carry it, same rule as every leaf route.
    expect(body.scopes).toEqual(["bridgeCert"]);

    const cert = new X509Certificate(body.certificate);
    const bc = cert.getExtension(BasicConstraintsExtension);
    expect(bc?.ca).toBe(true);
    expect(bc?.pathLength).toBe(0);
    const ku = cert.getExtension(KeyUsagesExtension);
    expect(ku!.usages & KeyUsageFlags.keyCertSign).toBeTruthy();
    expect(ku!.usages & KeyUsageFlags.digitalSignature).toBeFalsy();
  });

  it("refuses a P-256 key — the chain is Ed25519 end-to-end", async () => {
    const cookie = await sessionFor(["bridgeCert", "certMint"]);
    const kp = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const spki = (await crypto.subtle.exportKey(
      "spki",
      kp.publicKey,
    )) as ArrayBuffer;
    const good = await issuingRequest(cookie);
    const res = await post({ ...good, public_key: pem(spki) }, cookie);
    expect(res.status).toBe(400);
  });
});
