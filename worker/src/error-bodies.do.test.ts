/// <reference types="@cloudflare/vitest-plugin/types" />
/**
 * error-bodies.do.test.ts — internal error text stays on the server
 * (notme-b567c9).
 *
 * The invite and passkey paths were made to return constant bodies after a
 * challenge leak (review M1 of notme-3dfe15): @simplewebauthn named the
 * expected challenge in its message, and the route handed it back. Other
 * routes still concatenated `e.message` into the response — a Durable Object
 * error from the cert exchange, a verifier's "wrong audience: <expected>",
 * a key-import library's parse error. Same class: text written for an
 * operator, delivered to whoever sent the request.
 *
 * Each failure class now answers one fixed string; the detail is logged.
 */
import { env } from "cloudflare:test";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import worker from "../worker";
import { handleCertExchange } from "./cert-exchange";
import { type GhaSigner, ghaPopBody, installGhaSigner } from "./__tests__/helpers/gha-token";

const ORIGIN = "http://localhost:8788";
const OWNER = "agentic-research";
const LOCAL_ENV = {
  SITE_URL: ORIGIN,
  SIGNET_AUTHORITY_URL: ORIGIN,
  GHA_ALLOWED_OWNERS: OWNER,
  GHA_CERT_AUDIENCE: "notme.bot",
};

/** Text that only an internal error would contain. Must never reach a client. */
const SECRET = "SQLITE_ERROR: no such table: kek_secret_material_7f3a";

let gha: GhaSigner;
beforeAll(async () => {
  gha = await installGhaSigner({ owner: OWNER, repo: "notme", audience: "notme.bot" });
});
afterAll(() => gha.restore());
afterEach(() => vi.restoreAllMocks());

/**
 * An env whose authority throws `SECRET` from the mint calls, the way a DO
 * error crosses RPC: a bootstrap proof reaches the mint without any real
 * state, so the only thing under test is what the route does with the throw.
 */
function throwingEnv() {
  const fake = {
    consumeBootstrapCode: async () => true,
    createPrincipalWithCapabilities: async () => {},
    mintRedirectToken: async () => {
      throw new Error(SECRET);
    },
    mintBridgeCertPair: async () => {
      throw new Error(SECRET);
    },
  };
  return { ...env, SIGNING_AUTHORITY: { idFromName: () => "x", get: () => fake } };
}

/** Two keys + PoP proofs over the keys-only binding a bootstrap proof uses. */
async function keysOnlyPop() {
  const mtls = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const signing = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const m = new Uint8Array((await crypto.subtle.exportKey("spki", mtls.publicKey)) as ArrayBuffer);
  const s = new Uint8Array((await crypto.subtle.exportKey("spki", signing.publicKey)) as ArrayBuffer);
  const binding = new Uint8Array(m.length + s.length);
  binding.set(m, 0);
  binding.set(s, m.length);
  const b64 = (b: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(b)));
  const pem = (spki: Uint8Array) =>
    `-----BEGIN PUBLIC KEY-----\n${b64(spki).match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
  return {
    public_keys: { mtls: pem(m), signing: pem(s) },
    proofs: {
      mtls: b64(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, mtls.privateKey, binding)),
      signing: b64(await crypto.subtle.sign({ name: "Ed25519" }, signing.privateKey, binding)),
    },
  };
}

const certPost = (body: unknown) =>
  new Request(`${ORIGIN}/cert`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });

describe("POST /cert: a Durable Object error is not the response body (notme-b567c9)", () => {
  it("errors.cert-exchange.token-mint — a DO throw while minting the token answers a constant body and logs the detail", async () => {
    const logged = vi.spyOn(console, "error").mockImplementation(() => {});
    const res = await handleCertExchange(certPost({ proof: { type: "bootstrap", code: "x" } }), throwingEnv());
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "token minting failed" });
    expect(JSON.stringify(logged.mock.calls)).toContain(SECRET);
  });

  it("errors.cert-exchange.cert-mint — a DO throw while minting the cert pair answers a constant body and logs the detail", async () => {
    const logged = vi.spyOn(console, "error").mockImplementation(() => {});
    const res = await handleCertExchange(
      certPost({ proof: { type: "bootstrap", code: "x" }, ...(await keysOnlyPop()) }),
      throwingEnv(),
    );
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "cert minting failed" });
    expect(JSON.stringify(logged.mock.calls)).toContain(SECRET);
  });

  it("errors.cert-exchange.public-key — an unparseable public key answers a constant body", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const res = await handleCertExchange(
      certPost({
        proof: { type: "bootstrap", code: "x" },
        public_keys: { mtls: "-----BEGIN PUBLIC KEY-----\nnot-a-key\n-----END PUBLIC KEY-----", signing: "x" },
        proofs: { mtls: "x", signing: "x" },
      }),
      throwingEnv(),
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid public key" });
  });

  it("errors.cert-exchange.oidc — a rejected OIDC token answers a constant body, not the verifier's reason", async () => {
    const logged = vi.spyOn(console, "warn").mockImplementation(() => {});
    const token = await gha.token({ aud: "someone-else.example" });
    const res = await worker.fetch(certPost({ proof: { type: "oidc", token } }), { ...env, ...LOCAL_ENV });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid token" });
    expect(JSON.stringify(logged.mock.calls)).toMatch(/wrong audience/);
  });
});

describe("verifier text stays out of OIDC-accepting routes (notme-b567c9)", () => {
  it("errors.cert-gha.invalid-token — /cert/gha answers 'invalid token' whatever the verifier said", async () => {
    const logged = vi.spyOn(console, "warn").mockImplementation(() => {});
    const token = await gha.token({ aud: "someone-else.example" });
    const res = await worker.fetch(
      new Request(`${ORIGIN}/cert/gha`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
        body: JSON.stringify(await ghaPopBody(token)),
      }),
      { ...env, ...LOCAL_ENV },
    );
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid token" });
    expect(JSON.stringify(logged.mock.calls)).toMatch(/wrong audience/);
  });

  it("errors.oidc-login.invalid-token — /auth/oidc/login answers a constant body for a bad token", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const token = await gha.token({ aud: "someone-else.example" });
    const res = await worker.fetch(
      new Request(`${ORIGIN}/auth/oidc/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token }),
      }),
      { ...env, ...LOCAL_ENV },
    );
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid oidc proof" });
  });
});
