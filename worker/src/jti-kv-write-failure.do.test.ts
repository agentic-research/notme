/// <reference types="@cloudflare/vitest-plugin/types" />
/**
 * jti-kv-write-failure.do.test.ts — a failed KV write of an OIDC token's
 * `jti:` key, AFTER the SigningAuthority spent it, does not turn the request
 * into a 500 (notme-a3804c, overnight review L4).
 *
 * Since notme-b0d10f the authoritative spend is the DO's `oidc:<iss>#<jti>`;
 * the KV `jti:` key is a cross-check written afterwards. A throw from that
 * put escaped as a 500 with the token already burnt: the caller had spent
 * its one presentation and got nothing for it. Now each route logs
 * `jti.kv_write_failed` and finishes.
 *
 * The KV here THROWS on every `jti:` put (reads miss). The DO still refuses
 * a second presentation, so the cross-check failing loses no replay
 * protection: the last case in each route proves it.
 */
import { env } from "cloudflare:test";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import worker from "../worker";
import { ADMIN_SCOPES } from "./auth/admin-scopes";
import { GHA_ISSUER, type GhaSigner, ghaPopBody, installGhaSigner } from "./__tests__/helpers/gha-token";

const ORIGIN = "http://localhost:8788";
const OWNER = "agentic-research";
const REPO = "jti-kv-fail";
const TOKEN_URL = `${ORIGIN}/token`;

let signer: GhaSigner;
beforeAll(async () => {
  signer = await installGhaSigner({ owner: OWNER, repo: REPO, audience: "notme.bot" });
});
afterAll(() => signer.restore());

/** KV whose `jti:` writes throw, as a KV outage or a write-rate refusal does. */
function failingKv() {
  const real = env.CA_BUNDLE_CACHE;
  const failedPuts: string[] = [];
  const kv = {
    get: (k: string, ...rest: unknown[]) =>
      k.startsWith("jti:") ? Promise.resolve(null) : (real.get as any)(k, ...rest),
    put: (k: string, v: string, o?: unknown) => {
      if (k.startsWith("jti:")) {
        failedPuts.push(k);
        return Promise.reject(new Error("KV PUT failed: 429 Too Many Requests"));
      }
      return (real.put as any)(k, v, o);
    },
    delete: (k: string) => real.delete(k),
    list: (o?: unknown) => (real.list as any)(o),
    getWithMetadata: (k: string, o?: unknown) => (real.getWithMetadata as any)(k, o),
  };
  return { kv, failedPuts };
}

const failing = failingKv();
const routeEnv = () => ({
  ...env,
  SITE_URL: ORIGIN,
  SIGNET_AUTHORITY_URL: ORIGIN,
  GHA_ALLOWED_OWNERS: OWNER,
  GHA_CERT_AUDIENCE: "notme.bot",
  CA_BUNDLE_CACHE: failing.kv,
});
const authority = () => env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
const post = (path: string, init: RequestInit) => worker.fetch(new Request(`${ORIGIN}${path}`, { method: "POST", ...init }), routeEnv());
const json = { "content-type": "application/json" };

/** A fresh token whose subject is LINKED to a principal (for /cert oidc and /auth/oidc/login). */
async function linkedToken(): Promise<string> {
  const sub = `repo:${OWNER}/${REPO}:ref:refs/heads/x-${crypto.randomUUID()}`;
  const pid = `principal-jti-kv-${crypto.randomUUID()}`;
  await authority().createPrincipalWithCapabilities(pid, ["bridgeCert"]);
  await authority().linkFederatedId(pid, GHA_ISSUER, sub);
  return signer.token({ sub });
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

type Route = {
  name: string;
  token: () => Promise<string>;
  present: (token: string) => Promise<Response>;
  ok: number;
  /** What the SECOND presentation of the same token gets: the DO's refusal. */
  replay: (r: Response) => Promise<void>;
  /** Where the second presentation goes, when not the same route. */
  replayAt?: (token: string) => Promise<Response>;
};

const alreadyUsed = async (r: Response) => {
  expect(r.status).toBe(401);
  expect(await r.json()).toMatchObject({ error: "token already used" });
};

const BOOTSTRAP_SUB = "repo:agentic-research/notme:ref:refs/heads/main";

const certGha = async (t: string) =>
  post("/cert/gha", { headers: { ...json, authorization: `Bearer ${t}` }, body: JSON.stringify(await ghaPopBody(t)) });

const ROUTES: Route[] = [
  {
    // A well-formed code with no such claim: the DO spends the token, then
    // answers 404 (oidc-jti-cross-route.do.test.ts). The KV put sits between.
    name: "/bootstrap/claim",
    token: () => signer.token({ sub: BOOTSTRAP_SUB }),
    present: (t) => post("/bootstrap/claim", { headers: { ...json, authorization: `Bearer ${t}` }, body: JSON.stringify({ code: "BBBB-BBBB" }) }),
    ok: 404,
    replay: alreadyUsed,
  },
  {
    name: "/cert/gha",
    token: () => signer.token({ sub: `repo:${OWNER}/${REPO}:ref:refs/heads/${crypto.randomUUID()}` }),
    present: certGha,
    ok: 200,
    replay: alreadyUsed,
  },
  {
    name: "/cert (oidc proof)",
    token: linkedToken,
    present: async (t) => post("/cert", { headers: json, body: JSON.stringify({ proof: { type: "oidc", token: t }, ...(await ghaPopBody(t)) }) }),
    ok: 200,
    replay: alreadyUsed,
  },
  {
    name: "/token (exchange)",
    token: linkedToken,
    present: async (t) =>
      post("/token", {
        headers: { DPoP: await dpopProof(), "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
          subject_token: t,
          subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
          audience: "https://rosary.bot",
        }).toString(),
      }),
    ok: 200,
    replay: async (r) => {
      expect(r.status).toBe(400);
      expect(await r.json()).toMatchObject({ error: "invalid_grant" });
    },
  },
  {
    name: "/auth/oidc/login",
    token: linkedToken,
    present: (t) => post("/auth/oidc/login", { headers: json, body: JSON.stringify({ token: t }) }),
    ok: 200,
    replay: alreadyUsed,
  },
  {
    name: "/join",
    token: () => signer.token({ sub: `repo:${OWNER}/${REPO}:ref:refs/heads/join-${crypto.randomUUID()}` }),
    present: async (t) => {
      // An administrator invites; created here, AFTER /bootstrap/claim ran,
      // which must find no administrator (else it answers a governed 409).
      await authority().createPrincipalWithCapabilities("jti-kv-inviter", [...ADMIN_SCOPES]);
      const inv = (await authority().createInviteToken("jti-kv-inviter", ["bridgeCert"], 3600)).token;
      return post("/join", { headers: json, body: JSON.stringify({ token: inv, proof: { type: "oidc", token: t } }) });
    },
    ok: 200,
    // A second /join with the now-linked identity is refused as already
    // linked before the jti is looked at; /cert/gha shows the DO spend.
    replayAt: certGha,
    replay: alreadyUsed,
  },
];

describe("a failed jti KV write after the DO spend is logged, not a 500 (notme-a3804c, review L4)", () => {
  for (const route of ROUTES) {
    it(`jti.kv-write-failure — ${route.name}: the request completes, the failure is logged, and the DO still refuses a replay`, async () => {
      const errors = vi.spyOn(console, "error");
      try {
        const token = await route.token();
        const before = failing.failedPuts.length;
        const res = await route.present(token);
        expect(res.status, await res.clone().text()).toBe(route.ok);
        // The put really was attempted, and really failed.
        expect(failing.failedPuts.length).toBe(before + 1);
        expect(errors.mock.calls.some(([e]) => (e as { event?: string })?.event === "jti.kv_write_failed")).toBe(true);
        // Replay protection is the DO's, and held.
        await route.replay(await (route.replayAt ?? route.present)(token));
      } finally {
        errors.mockRestore();
      }
    });
  }
});
