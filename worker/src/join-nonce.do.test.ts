/// <reference types="@cloudflare/vitest-plugin/types" />
/**
 * join-nonce.do.test.ts — /join binds an OIDC proof to its invite through a
 * challenge audience (ADR-023, notme-e3dede).
 *
 * D1  POST /join/challenge returns `<authority>/join/<nonce>`; a token minted
 *     for it joins that invite.
 * D2  the nonce is bound to the invite: a challenge for A does not join B.
 * D3  a challenge-audience token is refused at every other OIDC route.
 * D4  /challenge answers a garbage invite exactly as a live one.
 * D5  plain `notme.bot` still joins while JOIN_REQUIRE_NONCE is off, and is
 *     counted; with the flag on it is refused and spends nothing.
 */
import { env } from "cloudflare:test";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import worker from "../worker";
import { GHA_ISSUER, type GhaSigner, ghaPopBody, installGhaSigner } from "./__tests__/helpers/gha-token";
import { ADMIN_SCOPES } from "./auth/admin-scopes";

const ORIGIN = "http://localhost:8788";
const OWNER = "agentic-research";
const TOKEN_URL = `${ORIGIN}/token`;
const LOCAL_ENV = {
  SITE_URL: ORIGIN,
  SIGNET_AUTHORITY_URL: ORIGIN,
  GHA_ALLOWED_OWNERS: OWNER,
  GHA_CERT_AUDIENCE: "notme.bot",
};

let signer: GhaSigner;
beforeAll(async () => {
  signer = await installGhaSigner({ owner: OWNER, repo: "join-nonce", audience: "notme.bot" });
  // An invite is live only while its creator exists and holds what it grants.
  await authority().createPrincipalWithCapabilities("inviter-join-nonce", [...ADMIN_SCOPES]);
});
afterAll(() => signer.restore());

const authority = () => env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
const invite = () => authority().createInviteToken("inviter-join-nonce", ["bridgeCert"], 3600);
/** A fresh GitHub identity per token, so one test's link cannot 409 another's. */
const fresh = (aud: string) => signer.token({ aud, sub: `repo:${OWNER}/join-nonce:ref:refs/heads/${crypto.randomUUID()}` });

function post(path: string, body: unknown, extra: Record<string, unknown> = {}) {
  return worker.fetch(
    new Request(`${ORIGIN}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }),
    { ...env, ...LOCAL_ENV, ...extra } as never,
  );
}

async function challenge(token: string): Promise<{ audience: string; expires_at: number }> {
  const res = await post("/join/challenge", { token });
  expect(res.status, await res.clone().text()).toBe(200);
  return (await res.json()) as { audience: string; expires_at: number };
}

const join = (inviteToken: string, oidc: string, extra: Record<string, unknown> = {}) =>
  post("/join", { token: inviteToken, proof: { type: "oidc", token: oidc } }, extra);

const plainCount = async () => (await authority().getAlarmHealth()).join.plainAudience.count;

describe("POST /join/challenge (ADR-023 D1, D4)", () => {
  it("join.challenge.shape — a per-deployment audience under this authority, valid for 300 s", async () => {
    const inv = await invite();
    const now = Math.floor(Date.now() / 1000);
    const c = await challenge(inv.token);
    expect(c.audience.startsWith(`${ORIGIN}/join/`)).toBe(true);
    expect(c.expires_at).toBeGreaterThanOrEqual(now + 299);
    expect(c.expires_at).toBeLessThanOrEqual(now + 301);
  });

  it("join.challenge.no-oracle — a garbage invite gets the same 200 shape as a live one", async () => {
    const c = await challenge("not-an-invite-" + crypto.randomUUID());
    expect(c.audience.startsWith(`${ORIGIN}/join/`)).toBe(true);
  });

  it("join.challenge.requires-token — no invite token is 400", async () => {
    expect((await post("/join/challenge", {})).status).toBe(400);
  });
});

describe("/join with a challenge audience (ADR-023 D1, D2)", () => {
  it("join.challenge.joins — a token minted for the challenge joins that invite, uncounted", async () => {
    const before = await plainCount();
    const inv = await invite();
    const c = await challenge(inv.token);
    const res = await join(inv.token, await fresh(c.audience));
    expect(res.status, await res.clone().text()).toBe(200);
    expect(((await res.json()) as { joined: boolean }).joined).toBe(true);
    expect(await plainCount()).toBe(before);
  });

  it("join.challenge.bound-to-invite — a challenge for invite A does not join invite B, and B stays live", async () => {
    const a = await invite();
    const b = await invite();
    const cA = await challenge(a.token);
    const refused = await join(b.token, await fresh(cA.audience));
    expect(refused.status).toBe(403);
    // B was not spent by the refusal: its own challenge joins.
    const cB = await challenge(b.token);
    expect((await join(b.token, await fresh(cB.audience))).status).toBe(200);
  });

  it("join.challenge.other-deployment — another authority's challenge audience is refused (F3)", async () => {
    const inv = await invite();
    const c = await challenge(inv.token);
    const foreign = c.audience.replace(ORIGIN, "https://staging.example.test");
    expect((await join(inv.token, await fresh(foreign))).status).toBe(403);
  });
});

describe("a challenge-audience token is useless at every other route (ADR-023 D3)", () => {
  async function challengeToken() {
    const c = await challenge((await invite()).token);
    return fresh(c.audience);
  }
  const certGha = async (t: string) =>
    worker.fetch(
      new Request(`${ORIGIN}/cert/gha`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${t}` },
        body: JSON.stringify(await ghaPopBody(t)),
      }),
      { ...env, ...LOCAL_ENV } as never,
    );
  const certOidc = async (t: string) => post("/cert", { proof: { type: "oidc", token: t }, ...(await ghaPopBody(t)) });
  const oidcLogin = (t: string) => post("/auth/oidc/login", { token: t });
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
  const tokenExchange = async (t: string) =>
    worker.fetch(
      new Request(TOKEN_URL, {
        method: "POST",
        headers: { DPoP: await dpopProof(), "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
          subject_token: t,
          subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
          audience: "https://rosary.bot",
        }).toString(),
      }),
      { ...env, ...LOCAL_ENV } as never,
    );

  it("join.challenge.refused-cert-gha — /cert/gha refuses it; control: a plain token gets a cert", async () => {
    expect((await certGha(await challengeToken())).status).toBe(401);
    expect((await certGha(await fresh("notme.bot"))).status).toBe(200);
  });

  it("join.challenge.refused-cert-oidc — /cert refuses it; control: a plain token is not refused for its audience", async () => {
    const r = await certOidc(await challengeToken());
    expect(r.status).toBe(401);
    const ctl = await certOidc(await fresh("notme.bot"));
    // An unlinked identity is refused for that reason, after the audience passed.
    expect(await ctl.text()).not.toBe(await r.clone().text());
  });

  it("join.challenge.refused-oidc-login — /auth/oidc/login refuses it as an invalid proof; control: a plain token reaches the identity check", async () => {
    const r = await oidcLogin(await challengeToken());
    expect(r.status).toBe(401);
    expect(await r.json()).toMatchObject({ error: "invalid oidc proof" });
    const ctl = await oidcLogin(await fresh("notme.bot"));
    expect(ctl.status).toBe(403); // unknown identity: verification passed
  });

  it("join.challenge.refused-token-exchange — /token refuses it as a subject token; control: a plain token is exchanged", async () => {
    const r = await tokenExchange(await challengeToken());
    expect(r.status).not.toBe(200);
    expect(((await r.json()) as { error: string }).error).toBe("invalid_grant");
    expect((await tokenExchange(await fresh("notme.bot"))).status).toBe(200);
  });
});

describe("plain notme.bot at /join (ADR-023 D5)", () => {
  it("join.plain.counted — still joins while JOIN_REQUIRE_NONCE is off, and is counted with its issuer", async () => {
    const before = await plainCount();
    const inv = await invite();
    const res = await join(inv.token, await fresh("notme.bot"));
    expect(res.status, await res.clone().text()).toBe(200);
    const h = (await authority().getAlarmHealth()).join.plainAudience;
    expect(h.count).toBe(before + 1);
    expect(h.lastIssuer).toBe(GHA_ISSUER);
    expect(h.lastAt).toBeGreaterThan(0);
  });

  it("join.plain.refused-when-required — JOIN_REQUIRE_NONCE refuses it with the constant 403 and spends nothing", async () => {
    const inv = await invite();
    const plain = await fresh("notme.bot");
    const refused = await join(inv.token, plain, { JOIN_REQUIRE_NONCE: "true" });
    expect(refused.status).toBe(403);
    expect(await refused.json()).toMatchObject({ error: "invalid oidc proof" });
    // Nothing spent: the invite joins under the flag through a challenge.
    const c = await challenge(inv.token);
    expect((await join(inv.token, await fresh(c.audience), { JOIN_REQUIRE_NONCE: "true" })).status).toBe(200);
  });
});
