/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * oidc-jti-cross-route.do.test.ts — one GitHub Actions token, one spend,
 * across /cert/gha, /cert (oidc proof) and the /token exchange, WITHOUT
 * leaning on KV (notme-b0d10f).
 *
 * These three routes spent a token's jti in KV `jti:<jti>` only. KV is
 * eventually consistent: a write at one edge is not yet visible at another,
 * so the same token presented at two of them inside the propagation window
 * was accepted twice. /join, /auth/oidc/login and the AUTH binding already
 * spent it atomically in the SigningAuthority DO (`oidc:<iss>#<jti>`); now
 * these routes spend the same DO key, and KV stays as the cross-check.
 *
 * The routes here run against a LAGGING KV: every `jti:` read misses and
 * every `jti:` write is recorded but never becomes visible. That is the
 * propagation window held open, so a refusal below can only come from the
 * DO. Other keys (the CA bundle cache) pass through untouched.
 */
import { env } from "cloudflare:test";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import worker from "../worker";
import { GHA_ISSUER, type GhaSigner, ghaPopBody, installGhaSigner } from "./__tests__/helpers/gha-token";

const ORIGIN = "http://localhost:8788";
const OWNER = "agentic-research";
const REPO = "cross-route";
const TOKEN_URL = `${ORIGIN}/token`;
const AUDIENCE = "https://rosary.bot";
const EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";

let signer: GhaSigner;
beforeAll(async () => {
  signer = await installGhaSigner({ owner: OWNER, repo: REPO, audience: "notme.bot" });
});
afterAll(() => signer.restore());

/** KV whose `jti:` writes never propagate: reads miss, writes are only recorded. */
function laggingKv() {
  const real = env.CA_BUNDLE_CACHE;
  const jtiPuts: string[] = [];
  const kv = {
    get: (k: string, ...rest: unknown[]) =>
      k.startsWith("jti:") ? Promise.resolve(null) : (real.get as any)(k, ...rest),
    put: (k: string, v: string, o?: unknown) => {
      if (k.startsWith("jti:")) {
        jtiPuts.push(k);
        return Promise.resolve();
      }
      return (real.put as any)(k, v, o);
    },
    delete: (k: string) => real.delete(k),
    list: (o?: unknown) => (real.list as any)(o),
    getWithMetadata: (k: string, o?: unknown) => (real.getWithMetadata as any)(k, o),
  };
  return { kv, jtiPuts };
}

const lag = laggingKv();
const LOCAL_ENV = {
  SITE_URL: ORIGIN,
  SIGNET_AUTHORITY_URL: ORIGIN,
  GHA_ALLOWED_OWNERS: OWNER,
  GHA_CERT_AUDIENCE: "notme.bot",
  CA_BUNDLE_CACHE: lag.kv,
};
const routeEnv = () => ({ ...env, ...LOCAL_ENV });

const authority = () => env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
const jtiOf = (token: string) =>
  (JSON.parse(atob(token.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/"))) as { jti: string; sub: string });

// ── the three routes ──

async function certGha(token: string) {
  return worker.fetch(
    new Request(`${ORIGIN}/cert/gha`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify(await ghaPopBody(token)),
    }),
    routeEnv(),
  );
}

async function certOidc(token: string) {
  return worker.fetch(
    new Request(`${ORIGIN}/cert`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ proof: { type: "oidc", token }, ...(await ghaPopBody(token)) }),
    }),
    routeEnv(),
  );
}

const b64url = (b: Uint8Array) =>
  btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
async function dpopProof() {
  const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as JsonWebKey;
  const enc = (o: unknown) => b64url(new TextEncoder().encode(JSON.stringify(o)));
  const input = `${enc({ typ: "dpop+jwt", alg: "ES256", jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } })}.${enc({
    jti: crypto.randomUUID(), htm: "POST", htu: TOKEN_URL, iat: Math.floor(Date.now() / 1000),
  })}`;
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, new TextEncoder().encode(input)));
  return `${input}.${b64url(sig)}`;
}

async function tokenExchange(token: string) {
  const form = new URLSearchParams({
    grant_type: EXCHANGE,
    subject_token: token,
    subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
    audience: AUDIENCE,
  });
  return worker.fetch(
    new Request(TOKEN_URL, {
      method: "POST",
      headers: { DPoP: await dpopProof(), "content-type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    }),
    routeEnv(),
  );
}

type Route = { name: string; present: (token: string) => Promise<Response>; refused: (r: Response) => Promise<void> };
const ROUTES: Route[] = [
  {
    name: "/cert/gha",
    present: certGha,
    refused: async (r) => {
      expect(r.status).toBe(401);
      expect(await r.json()).toMatchObject({ error: "token already used" });
    },
  },
  {
    name: "/cert",
    present: certOidc,
    refused: async (r) => {
      expect(r.status).toBe(401);
      expect(await r.json()).toMatchObject({ error: "token already used" });
    },
  },
  {
    name: "/token",
    present: tokenExchange,
    refused: async (r) => {
      expect(r.status).toBe(400);
      expect(await r.json()).toMatchObject({ error: "invalid_grant" });
    },
  },
];

/** A fresh token whose subject is LINKED, so /cert's oidc proof resolves it. */
async function linkedToken(): Promise<string> {
  const sub = `repo:${OWNER}/${REPO}:ref:refs/heads/x-${crypto.randomUUID()}`;
  const pid = `principal-xr-${crypto.randomUUID()}`;
  await authority().createPrincipalWithCapabilities(pid, ["bridgeCert"]);
  await authority().linkFederatedId(pid, GHA_ISSUER, sub);
  return signer.token({ sub });
}

describe("one OIDC token, one spend, across the KV-only routes — with KV lagging (notme-b0d10f)", () => {
  for (const first of ROUTES) {
    for (const second of ROUTES) {
      it(`oidc-jti.cross-route — spent at ${first.name}, refused at ${second.name}`, async () => {
        const token = await linkedToken();
        const r1 = await first.present(token);
        expect(r1.status, await r1.clone().text()).toBe(200);
        // KV is kept as the cross-check: the first route still wrote it.
        expect(lag.jtiPuts).toContain(`jti:${jtiOf(token).jti}`);
        await second.refused(await second.present(token));
      });
    }
  }

  // The DO legs (/auth/oidc/login, and /join through the same key) and the
  // formerly KV-only routes now share one key, so the window closes in both
  // directions between them too.
  const login = (token: string) =>
    worker.fetch(
      new Request(`${ORIGIN}/auth/oidc/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token }),
      }),
      routeEnv(),
    );

  it("oidc-jti.cross-route.do-leg — spent at /cert/gha, refused at /auth/oidc/login", async () => {
    const token = await linkedToken();
    expect((await certGha(token)).status).toBe(200);
    const res = await login(token);
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: "token already used" });
  });

  it("oidc-jti.cross-route.do-leg — spent at /auth/oidc/login, refused at /cert/gha, /cert and /token", async () => {
    for (const route of ROUTES) {
      const token = await linkedToken();
      expect((await login(token)).status).toBe(200);
      await route.refused(await route.present(token));
    }
  });

  // /bootstrap/claim spent in KV only too, so it shares the DO key now.
  const bootstrapClaim = (token: string) =>
    worker.fetch(
      new Request(`${ORIGIN}/bootstrap/claim`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
        body: JSON.stringify({ code: "not-a-live-claim-code" }),
      }),
      routeEnv(),
    );

  it("oidc-jti.cross-route.bootstrap-claim — spent at /cert/gha, refused at /bootstrap/claim, and back", async () => {
    const a = await linkedToken();
    expect((await certGha(a)).status).toBe(200);
    const refused = await bootstrapClaim(a);
    expect(refused.status).toBe(401);
    expect(await refused.json()).toMatchObject({ error: "token already used" });

    // /bootstrap/claim spends before the DO judges the claim code (unchanged
    // ordering), so even its refusal spends the token.
    const b = await linkedToken();
    const claimed = await bootstrapClaim(b);
    expect(claimed.status).not.toBe(401);
    await ROUTES[0]!.refused(await certGha(b));
  });

  it("oidc-jti.cross-route.refusal-spends-nothing — an owner refused at /cert/gha and /token is still spendable", async () => {
    // The ordering rule: what can be decided before the spend (signature,
    // audience, owner allowlist, claims) is decided before it.
    const sub = `repo:someone-else/${REPO}:ref:refs/heads/main`;
    const token = await signer.token({ repository_owner: "someone-else", repository: `someone-else/${REPO}`, sub });
    expect((await certGha(token)).status).toBe(403);
    expect((await tokenExchange(token)).status).toBe(400);
    // Not spent in the DO: linked under /cert (which has no owner allowlist),
    // the same token still buys its one cert pair.
    const pid = `principal-xr-${crypto.randomUUID()}`;
    await authority().createPrincipalWithCapabilities(pid, ["bridgeCert"]);
    await authority().linkFederatedId(pid, GHA_ISSUER, sub);
    const ok = await certOidc(token);
    expect(ok.status, await ok.clone().text()).toBe(200);
  });
});
