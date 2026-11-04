/// <reference types="@cloudflare/vitest-plugin/types" />
/**
 * pre-do-limits.do.test.ts — an unauthenticated request that is going to be
 * refused must be refused BEFORE it costs the SigningAuthority anything
 * (notme-ed6114).
 *
 * There is one SigningAuthority, and it serialises issuance. Every RPC to it
 * is billed and queues behind honest mints, so "refused, but only after a DO
 * call" is still a flood that reaches the singleton. Each test counts the
 * RPCs made on the stub rather than inferring them from a status code: a 429
 * says the limiter refused, not that it refused first.
 */
import { env } from "cloudflare:test";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import worker from "../worker";
import { createSessionCookie } from "./auth/session";
import { precheckRenewalProof } from "./auth/renewal-precheck";
import { tierRenewalBinding, tierRenewalBindingV2, tierRenewalBindingV3 } from "./auth/tier-enrolment-binding";
import { ED25519 } from "./platform";
import { type GhaSigner, ghaPopBody, installGhaSigner } from "./__tests__/helpers/gha-token";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN, GHA_ALLOWED_OWNERS: "agentic-research" };

/**
 * The SIGNING_AUTHORITY namespace, with every RPC on every stub it hands out
 * recorded by method name. Getting a stub is not an RPC; calling a method on
 * one is, so that is what is counted.
 */
function spiedAuthority() {
  const calls: string[] = [];
  const ns = env.SIGNING_AUTHORITY;
  const binding = {
    idFromName: (name: string) => ns.idFromName(name),
    get: (id: DurableObjectId) => {
      const stub = ns.get(id);
      return new Proxy(stub, {
        get(target, prop) {
          const value = Reflect.get(target, prop);
          if (typeof prop !== "string" || prop === "then" || typeof value !== "function") return value;
          return (...args: unknown[]) => {
            calls.push(prop);
            // Called through the stub, not via .apply: on an RPC stub `apply` is
            // itself looked up as a remote method.
            return (target as unknown as Record<string, (...a: unknown[]) => unknown>)[prop]!(...args);
          };
        },
      });
    },
  };
  return { calls, binding };
}

/** A stand-in for a rate-limit binding, which has no test constructor. */
function limiter(allow: (key: string) => boolean) {
  const keys: string[] = [];
  return {
    keys,
    binding: {
      limit: async ({ key }: { key: string }) => {
        keys.push(key);
        return { success: allow(key) };
      },
    },
  };
}

// ONE GitHub signer for the file: validateGHAToken caches the JWKS at module
// scope, so a second keypair would be checked against the first one's key.
let signer: GhaSigner;
beforeAll(async () => {
  signer = await installGhaSigner({ owner: "agentic-research", repo: "pre-do-limits", audience: "notme.bot" });
});
afterAll(() => signer.restore());

const call = (req: Request, extra: Record<string, unknown>) =>
  worker.fetch(req, { ...env, ...LOCAL_ENV, ...extra } as never);

describe("POST /token is limited before any SigningAuthority RPC", () => {
  const tokenReq = (headers: Record<string, string>, body: string) =>
    new Request(`${ORIGIN}/token`, {
      method: "POST",
      headers: { DPoP: "placeholder.validated.after-the-limiter", "cf-connecting-ip": "198.51.100.7", ...headers },
      body,
    });
  const sessionReq = (cookie: string) =>
    tokenReq(
      { "content-type": "application/json", cookie },
      JSON.stringify({ audience: "https://notme.bot" }),
    );

  it("a limited request carrying a forged session cookie makes no RPC at all", async () => {
    // The flood shape: any value in notme_session used to buy a
    // getSessionSecret() before the limiter could run, because the limiter
    // keyed on a principal only the DO's secret can establish.
    const spy = spiedAuthority();
    const rl = limiter(() => false);
    const res = await call(sessionReq("notme_session=forged.value"), {
      SIGNING_AUTHORITY: spy.binding,
      TOKEN_LIMITER: rl.binding,
    });
    expect(res.status).toBe(429);
    expect(spy.calls).toEqual([]);
  });

  it("the pre-DO bucket is the IPv6 /64, and a request with no address gets its own", async () => {
    // Review F4: per-/128 keying gave one IPv6 subscriber 2^64 buckets.
    const rl = limiter(() => false);
    const forged = (ip?: string) =>
      new Request(`${ORIGIN}/token`, {
        method: "POST",
        headers: {
          DPoP: "placeholder",
          "content-type": "application/json",
          cookie: "notme_session=forged.value",
          ...(ip ? { "cf-connecting-ip": ip } : {}),
        },
        body: JSON.stringify({ audience: "https://notme.bot" }),
      });
    for (const ip of ["2001:db8:1:2::1", "2001:db8:1:2:ffff:ffff:ffff:ffff", "203.0.113.9", undefined]) {
      await call(forged(ip), { SIGNING_AUTHORITY: spiedAuthority().binding, TOKEN_LIMITER: rl.binding });
    }
    expect(rl.keys).toEqual([
      "token-ip:2001:db8:1:2::/64",
      "token-ip:2001:db8:1:2::/64",
      "token-ip:203.0.113.9",
      "token-ip:none",
    ]);
  });

  it("a principal over its budget is refused before its live scopes are read", async () => {
    const stub = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
    const cookie = await createSessionCookie(
      { principalId: "over-budget", scopes: ["bridgeCert"], authMethod: "passkey" },
      await stub.getSessionSecret(),
    );
    const spy = spiedAuthority();
    const rl = limiter((key) => !key.startsWith("token:"));
    const res = await call(sessionReq(cookie), { SIGNING_AUTHORITY: spy.binding, TOKEN_LIMITER: rl.binding });
    expect(res.status).toBe(429);
    // The secret is needed to learn WHO is asking; nothing after that is.
    expect(spy.calls).toEqual(["getSessionSecret"]);
    expect(rl.keys).toContain("token:over-budget");
  });

  describe("token exchange", () => {
    it("a limited exchange makes no RPC: the GitHub subject is known without the DO", async () => {
      const spy = spiedAuthority();
      const rl = limiter(() => false);
      const form = new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        subject_token: await signer.token(),
        subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
        audience: "https://rosary.bot",
      });
      const res = await call(tokenReq({ "content-type": "application/x-www-form-urlencoded" }, form.toString()), {
        SIGNING_AUTHORITY: spy.binding,
        TOKEN_LIMITER: rl.binding,
      });
      expect(res.status).toBe(429);
      expect(spy.calls).toEqual([]);
    });
  });
});

describe("POST /cert/gha is limited before any SigningAuthority RPC", () => {
  it("a limited request does not publish the CA bundle on the way to its 429", async () => {
    // The handler used to ensure the KV-published bundle FIRST — before the
    // bearer token was even read — so on a KV miss every request, limited or
    // anonymous, paid a generateBundle() on the singleton.
    await env.CA_BUNDLE_CACHE.delete("bundle:current");
    const spy = spiedAuthority();
    const rl = limiter(() => false);
    const token = await signer.token();
    const res = await call(
      new Request(`${ORIGIN}/cert/gha`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
        body: JSON.stringify(await ghaPopBody(token)),
      }),
      { SIGNING_AUTHORITY: spy.binding, CERT_LIMITER: rl.binding, GHA_CERT_AUDIENCE: "notme.bot" },
    );
    expect(res.status).toBe(429);
    expect(spy.calls).toEqual([]);
  });

  it("an anonymous request makes no RPC either", async () => {
    await env.CA_BUNDLE_CACHE.delete("bundle:current");
    const spy = spiedAuthority();
    const res = await call(new Request(`${ORIGIN}/cert/gha`, { method: "POST", body: "{}" }), {
      SIGNING_AUTHORITY: spy.binding,
    });
    expect(res.status).toBe(401);
    expect(spy.calls).toEqual([]);
  });
});

describe("POST /cert/issuing-ca/renew rejects a forged proof before the DO", () => {
  // The renewal bindings are request-only — tag || SPKI || iat [|| generation],
  // every byte from the body — so the stateless front Worker can check the
  // proof itself. The DO still verifies (defence in depth); this only stops a
  // forgery costing the singleton a row read and an Ed25519 verify.
  const b64u = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  async function machine() {
    const kp = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
    const spki = new Uint8Array((await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer);
    const pem = `-----BEGIN PUBLIC KEY-----\n${btoa(String.fromCharCode(...spki)).match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
    return { kp, spki, pem };
  }
  const sign = async (key: CryptoKey, binding: Uint8Array) =>
    b64u(new Uint8Array(await crypto.subtle.sign(ED25519, key, binding)));
  const renew = (body: unknown, spy: ReturnType<typeof spiedAuthority>) =>
    call(
      new Request(`${ORIGIN}/cert/issuing-ca/renew`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      }),
      { SIGNING_AUTHORITY: spy.binding },
    );
  const now = () => Math.floor(Date.now() / 1000);
  const hex64 = () =>
    Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) => b.toString(16).padStart(2, "0")).join("");
  const unhex = (h: string) => Uint8Array.from(h.match(/../g)!, (x) => parseInt(x, 16));
  const errorOf = async (res: Response) => ((await res.json()) as { error: string }).error;

  it("v2: a proof signed by another key is 401 invalid_proof with no RPC", async () => {
    const m = await machine();
    const thief = await machine();
    const iat = now();
    const spy = spiedAuthority();
    const res = await renew(
      { public_key: m.pem, iat, generation: 0, proof: await sign(thief.kp.privateKey, tierRenewalBindingV2(m.spki, iat, 0)) },
      spy,
    );
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("invalid_proof");
    expect(spy.calls).toEqual([]);
  });

  it("v1: a proof signed by another key is 401 invalid_proof with no RPC", async () => {
    const m = await machine();
    const thief = await machine();
    const iat = now();
    const spy = spiedAuthority();
    const res = await renew({ public_key: m.pem, iat, proof: await sign(thief.kp.privateKey, tierRenewalBinding(m.spki, iat)) }, spy);
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("invalid_proof");
    expect(spy.calls).toEqual([]);
  });

  it("a v1 proof presented as v2 is refused: the tags differ", async () => {
    const m = await machine();
    const iat = now();
    const spy = spiedAuthority();
    const res = await renew(
      { public_key: m.pem, iat, generation: 0, proof: await sign(m.kp.privateKey, tierRenewalBinding(m.spki, iat)) },
      spy,
    );
    expect(res.status).toBe(401);
    expect(spy.calls).toEqual([]);
  });

  it("v3: a proof signed by another key is 401 invalid_proof with no RPC", async () => {
    const m = await machine();
    const thief = await machine();
    const iat = now();
    const id = hex64();
    const spy = spiedAuthority();
    const res = await renew(
      {
        public_key: m.pem,
        iat,
        generation: 0,
        enrollment_id: id,
        proof: await sign(thief.kp.privateKey, tierRenewalBindingV3(m.spki, iat, 0, unhex(id))),
      },
      spy,
    );
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("invalid_proof");
    expect(spy.calls).toEqual([]);
  });

  it("parity: every refusal the pre-check gives is the one the DO gives for the same request", async () => {
    // The pre-check mirrors renewTier's stateless prefix; this pins it. Each
    // case goes to BOTH: the pre-check, and the real DO directly.
    const m = await machine();
    const thief = await machine();
    const iat = now();
    const id = hex64();
    const v2 = tierRenewalBindingV2(m.spki, iat, 0);
    const v3 = tierRenewalBindingV3(m.spki, iat, 0, unhex(id));
    // A real P-256 SPKI: importPublicKey accepts it, so this reaches the
    // algorithm check on both sides rather than failing the import (F7).
    const p256 = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const p256Spki = new Uint8Array((await crypto.subtle.exportKey("spki", p256.publicKey)) as ArrayBuffer);
    const p256Pem = `-----BEGIN PUBLIC KEY-----\n${btoa(String.fromCharCode(...p256Spki)).match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
    const cases: Array<{ publicKeyPem: string; iat: number; proof: string; generation?: number; enrollmentId?: string }> = [
      { publicKeyPem: "junk", iat, proof: "x" },
      { publicKeyPem: p256Pem, iat, proof: "x" },
      { publicKeyPem: p256Pem, iat, proof: "x", generation: 0 },
      { publicKeyPem: m.pem, iat: -1, proof: "x" },
      { publicKeyPem: m.pem, iat: 1.5, proof: "x" },
      { publicKeyPem: m.pem, iat: NaN, proof: "x" },
      { publicKeyPem: m.pem, iat: -1, proof: "x", generation: 0 },
      { publicKeyPem: m.pem, iat, proof: "x", generation: -1 },
      { publicKeyPem: m.pem, iat, proof: "x", generation: 1.5 },
      { publicKeyPem: m.pem, iat, proof: "x", generation: 0, enrollmentId: "" },
      { publicKeyPem: m.pem, iat, proof: "x", generation: 0, enrollmentId: "AB".repeat(32) },
      { publicKeyPem: m.pem, iat, proof: "x", enrollmentId: id },
      { publicKeyPem: m.pem, iat, proof: await sign(thief.kp.privateKey, tierRenewalBinding(m.spki, iat)) },
      { publicKeyPem: m.pem, iat, proof: await sign(thief.kp.privateKey, v2), generation: 0 },
      { publicKeyPem: m.pem, iat, proof: await sign(m.kp.privateKey, v2), generation: 0, enrollmentId: id },
      { publicKeyPem: m.pem, iat, proof: await sign(m.kp.privateKey, v3), generation: 0 },
      { publicKeyPem: m.pem, iat, proof: "", generation: 0 },
    ];
    const stub = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
    for (const c of cases) {
      const pre = await precheckRenewalProof(c);
      expect(pre.ok, JSON.stringify(c)).toBe(false);
      const r = await stub.renewTier(c);
      expect(r.ok).toBe(false);
      expect(pre.ok ? undefined : pre.reason, JSON.stringify(c)).toBe(r.ok ? undefined : r.reason);
    }
    // And a valid proof under each binding is admitted: what happens next
    // depends on the row, so only the DO can judge it (here: unknown key).
    const valids = [
      { publicKeyPem: m.pem, iat, proof: await sign(m.kp.privateKey, tierRenewalBinding(m.spki, iat)) },
      { publicKeyPem: m.pem, iat, proof: await sign(m.kp.privateKey, v2), generation: 0 },
      { publicKeyPem: m.pem, iat, proof: await sign(m.kp.privateKey, v3), generation: 0, enrollmentId: id },
    ];
    for (const valid of valids) {
      expect(await precheckRenewalProof(valid), JSON.stringify(valid)).toEqual({ ok: true });
      const r = await stub.renewTier(valid);
      expect(r.ok ? "ok" : r.reason).toBe("unknown_key");
    }
  });

  it("a key that is not an Ed25519 SPKI is 400 invalid_key with no RPC", async () => {
    const spy = spiedAuthority();
    const res = await renew({ public_key: "not a key", iat: now(), generation: 0, proof: "x" }, spy);
    expect(res.status).toBe(400);
    expect(await errorOf(res)).toBe("invalid_key");
    expect(spy.calls).toEqual([]);
  });

  it("control: a VALID proof still reaches the DO, which decides (here: unknown key)", async () => {
    // The front check refuses only what is wrong for every enrollment state;
    // anything that depends on the row stays the DO's call.
    const m = await machine();
    const iat = now();
    const spy = spiedAuthority();
    const res = await renew(
      { public_key: m.pem, iat, generation: 0, proof: await sign(m.kp.privateKey, tierRenewalBindingV2(m.spki, iat, 0)) },
      spy,
    );
    expect(res.status).toBe(404);
    expect(spy.calls).toEqual(["renewTier"]);
  });
});
