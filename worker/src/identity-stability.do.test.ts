/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * identity-stability.do.test.ts — one principal, one identity, whatever the
 * ceremony (notme-77438b, ADR-019 D2; Goal Zero criterion B's code half).
 *
 * THE INVERSION THIS FIXES. SPIFFE keeps a STABLE identity and an EPHEMERAL
 * credential. notme had the ephemeral half right (5-minute certs) but
 * advertised `wimse://<domain>/<authMethod>/<id>` as the identity — so one
 * human signing in by passkey and by invite got two "identities", while the
 * stable principal sat unadvertised in the cert subject.
 *
 * WHAT MUST NOT REGRESS. notme-ebc9af fixed a cert that claimed "passkey"
 * when an invite had authorized it. That fix was right and its property is
 * preserved here — provenance is still derived, still honest, still refused
 * when absent. It moves from the URI, where it made the identity unstable,
 * to the extension, where a verifier reads it deliberately. Both halves are
 * asserted together below, because keeping one without the other is how this
 * gets re-broken.
 */
import { env } from "cloudflare:test";
import { X509Certificate } from "@peculiar/x509";
import { describe, expect, it } from "vitest";
import worker from "../worker";
import { createSessionCookie } from "./auth/session";
import { certPrincipalKind, principalIdentity } from "./cert-authority";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };
const TRUST_DOMAIN = "localhost:8788";
const PRINCIPAL = "principal-identity-test";

const authority = () =>
  env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));

async function sessionCookie(authMethod: string) {
  const secret = await authority().getSessionSecret();
  return createSessionCookie(
    { principalId: PRINCIPAL, scopes: ["bridgeCert"], authMethod },
    secret,
  );
}

function pem(spki: ArrayBuffer): string {
  const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
  return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
}

/** A /cert/passkey mint request bound to the given session cookie. */
async function mintRequest(cookie: string) {
  const mtls = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
  )) as CryptoKeyPair;
  const signing = (await crypto.subtle.generateKey(
    { name: "Ed25519" }, true, ["sign", "verify"],
  )) as CryptoKeyPair;
  const mtlsSpki = (await crypto.subtle.exportKey("spki", mtls.publicKey)) as ArrayBuffer;
  const signingSpki = (await crypto.subtle.exportKey("spki", signing.publicKey)) as ArrayBuffer;
  // The route hashes the cookie VALUE, not the Set-Cookie string.
  const value = cookie.slice("notme_session=".length).split(";")[0]!;
  const cookieHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  const binding = new Uint8Array(mtlsSpki.byteLength + signingSpki.byteLength + 32);
  binding.set(new Uint8Array(mtlsSpki), 0);
  binding.set(new Uint8Array(signingSpki), mtlsSpki.byteLength);
  binding.set(new Uint8Array(cookieHash), mtlsSpki.byteLength + signingSpki.byteLength);
  const b64 = (b: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(b)));
  return {
    public_keys: { mtls: pem(mtlsSpki), signing: pem(signingSpki) },
    proofs: {
      mtls: b64(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, mtls.privateKey, binding)),
      signing: b64(await crypto.subtle.sign({ name: "Ed25519" }, signing.privateKey, binding)),
    },
  };
}

function post(path: string, body: unknown, cookie: string) {
  return worker.fetch(
    new Request(`${ORIGIN}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", cookie },
      body: JSON.stringify(body),
    }),
    { ...env, ...LOCAL_ENV },
  );
}

describe("the identity is stable across ceremonies (notme-77438b)", () => {
  it("passkey and invite sessions for ONE principal mint the SAME identity", async () => {
    const viaPasskey = await sessionCookie("passkey");
    const viaInvite = await sessionCookie("invite");

    const a = await post("/cert/passkey", await mintRequest(viaPasskey), viaPasskey);
    const b = await post("/cert/passkey", await mintRequest(viaInvite), viaInvite);
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    const bodyA = (await a.json()) as { identity: string; auth_method: string };
    const bodyB = (await b.json()) as { identity: string; auth_method: string };

    // The identity names the principal, not the door it came through.
    expect(bodyA.identity).toBe(`wimse://${TRUST_DOMAIN}/principal/${PRINCIPAL}`);
    expect(bodyB.identity).toBe(bodyA.identity);

    // notme-ebc9af's property, preserved: provenance is still derived and
    // still honest — it just lives where a verifier reads it deliberately.
    expect(bodyA.auth_method).toBe("passkey");
    expect(bodyB.auth_method).toBe("invite");
  });

  it("the ceremony is readable from the CERTIFICATE, not just the response", async () => {
    const cookie = await sessionCookie("invite");
    const res = await post("/cert/passkey", await mintRequest(cookie), cookie);
    const body = (await res.json()) as { certificates: { signing: string } };
    const cert = new X509Certificate(body.certificates.signing);
    // OID_AUTH_METHOD carries it; a consumer never has to split the URI.
    const ext = cert.getExtension("1.3.6.1.4.1.99999.1.5");
    expect(ext).not.toBeNull();
    expect(new TextDecoder().decode(new Uint8Array(ext!.value))).toContain("invite");
  });

  it("carries principal_kind as its own claim — kind and mechanism are different axes", async () => {
    const cookie = await sessionCookie("passkey");
    const res = await post("/cert/passkey", await mintRequest(cookie), cookie);
    const body = (await res.json()) as { certificates: { signing: string } };
    expect(certPrincipalKind(new X509Certificate(body.certificates.signing))).toBe("human");
  });

  it("the URI and the SUBJECT name the same principal — the inversion is gone", async () => {
    const cookie = await sessionCookie("passkey");
    const res = await post("/cert/passkey", await mintRequest(cookie), cookie);
    const body = (await res.json()) as { certificates: { signing: string }; identity: string };
    const cert = new X509Certificate(body.certificates.signing);
    const cn = cert.subjectName.getField("CN")?.[0];
    expect(body.identity.endsWith(`/${cn}`)).toBe(true);
  });
});

describe("principalIdentity — the one builder", () => {
  it("percent-encodes the id so an odd subject cannot invent segments", () => {
    expect(principalIdentity("notme.bot", "repo:o/r:ref:refs/heads/main")).toBe(
      "wimse://notme.bot/principal/repo%3Ao%2Fr%3Aref%3Arefs%2Fheads%2Fmain",
    );
  });

  it("refuses an empty principal rather than minting a headless identity", () => {
    expect(() => principalIdentity("notme.bot", "")).toThrow(/principal/i);
  });
});
