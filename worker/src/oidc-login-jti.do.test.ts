/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * oidc-login-jti.do.test.ts — an OIDC token presented at POST
 * /auth/oidc/login is single-use, keyed by its `jti` (review F1 of the
 * notme-3dfe15 part 1 fix).
 *
 * The defect: /auth/oidc/login verified an aud-`notme.bot` token and minted
 * a 24h session for the linked principal, checking and spending no jti. So
 * any unexpired token for a linked identity — one already spent at
 * /cert/gha, /cert, /token or /join, or one read out of a log — became a
 * 24h session, any number of times. Strictly worse than the /join squat: it
 * needs neither a never-linked identity nor an invite. Its 401 also echoed
 * the verifier's message (the oracle /join removed in review L4).
 *
 * The rule now, /join's: no jti is 400; a jti spent in the shared
 * `jti:<jti>` keyspace is refused; the authority DO consumes
 * `oidc-login:<issuer>#<jti>` in the same synchronous block that resolves
 * the principal and reads its scopes, kept past `exp` (review F2); a
 * successful login writes `jti:<jti>`; a refused login (unknown identity)
 * spends nothing; the rejection body is constant.
 */
import { env } from "cloudflare:test";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import worker from "../worker";
import { GHA_ISSUER, type GhaSigner, ghaPopBody, installGhaSigner } from "./__tests__/helpers/gha-token";
import { ADMIN_SCOPES } from "./auth/admin-scopes";

const ORIGIN = "http://localhost:8788";
const OWNER = "example";
const LOCAL_ENV = {
  SITE_URL: ORIGIN,
  SIGNET_AUTHORITY_URL: ORIGIN,
  GHA_ALLOWED_OWNERS: OWNER,
  GHA_CERT_AUDIENCE: "notme.bot",
};

const authority = () =>
  env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));

const call = (path: string, init: RequestInit) =>
  worker.fetch(new Request(`${ORIGIN}${path}`, init), { ...env, ...LOCAL_ENV });

const postJson = (path: string, body: unknown) =>
  call(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

const login = (token: string) => postJson("/auth/oidc/login", { token });

const certGha = async (token: string) =>
  call("/cert/gha", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    body: JSON.stringify(await ghaPopBody(token)),
  });

const sub = (tag: string) => `repo:${OWNER}/login:ref:refs/heads/${tag}`;

let signer: GhaSigner;

/** Link `s` to a fresh principal through /join, with a token of its own. */
async function linked(s: string) {
  const inv = await authority().createInviteToken("inviter", ["bridgeCert"], 3600);
  const res = await postJson("/join", {
    token: inv.token,
    proof: { type: "oidc", token: await signer.token({ sub: s }) },
  });
  expect(res.status, await res.clone().text()).toBe(200);
  return ((await res.json()) as { principalId: string }).principalId;
}

const hasSession = (res: Response) => /notme_session=[^;]+/.test(res.headers.get("set-cookie") ?? "");

beforeAll(async () => {
  await authority().createPrincipalWithCapabilities("inviter", [...ADMIN_SCOPES]);
  signer = await installGhaSigner({ owner: OWNER, repo: "login", audience: "notme.bot" });
});
afterAll(() => signer.restore());

describe("an OIDC token is single-use at /auth/oidc/login (review F1)", () => {
  it("login.oidc-jti.replay — the same token logs in once; the second presentation is refused", async () => {
    const s = sub("replay");
    const principalId = await linked(s);
    const token = await signer.token({ sub: s });
    const first = await login(token);
    expect(first.status, await first.clone().text()).toBe(200);
    expect(((await first.json()) as { principalId: string }).principalId).toBe(principalId);

    const again = await login(token);
    expect(again.status).toBe(401);
    expect(hasSession(again)).toBe(false);
  });

  it("login.oidc-jti.spent-elsewhere — a token already spent at /cert/gha does not become a session", async () => {
    const s = sub("spent-at-cert-gha");
    await linked(s);
    const token = await signer.token({ sub: s });
    expect((await certGha(token)).status).toBe(200);
    const res = await login(token);
    expect(res.status).toBe(401);
    expect(hasSession(res)).toBe(false);
  });

  it("login.oidc-jti.spends-shared — a token that logged in cannot then be spent at /cert/gha", async () => {
    const s = sub("login-then-cert");
    await linked(s);
    const token = await signer.token({ sub: s });
    expect((await login(token)).status).toBe(200);
    const cert = await certGha(token);
    expect(cert.status).toBe(401);
    expect(((await cert.json()) as { error: string }).error).toBe("token already used");
  });

  it("login.oidc-jti.required — a token without a jti is 400 and gets no session", async () => {
    const s = sub("no-jti");
    await linked(s);
    const res = await login(await signer.token({ sub: s, jti: undefined }));
    expect(res.status).toBe(400);
    expect(hasSession(res)).toBe(false);
  });

  it("login.oidc-jti.constant-body — a rejected token's 401 carries no verifier text", async () => {
    for (const bad of ["not.a.jwt", await signer.token({ sub: sub("aud"), aud: "elsewhere" })]) {
      const res = await login(bad);
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: "invalid oidc proof" });
    }
  });

  it("login.oidc-jti.refusal-keeps-token — an unknown identity is 403 and does not burn the token", async () => {
    const s = sub("not-yet-linked");
    const token = await signer.token({ sub: s });
    expect((await login(token)).status).toBe(403);
    await linked(s);
    const res = await login(token);
    expect(res.status, await res.clone().text()).toBe(200);
  });

  it("login.oidc-jti.concurrent — two concurrent logins with one token: exactly one session", async () => {
    const s = sub("race");
    await linked(s);
    const token = await signer.token({ sub: s });
    const results = await Promise.all([login(token), login(token)]);
    expect(results.map((r) => r.status).sort()).toEqual([200, 401]);
    expect(results.filter(hasSession)).toHaveLength(1);
  });

  it("login.oidc-jti.expiry-boundary — the DO keeps the consumed jti past exp (review F2)", async () => {
    const s = sub("boundary");
    await linked(s);
    const proof = { jti: crypto.randomUUID(), exp: Math.floor(Date.now() / 1000) - 3, spentElsewhere: false };
    expect((await authority().loginWithFederated(GHA_ISSUER, s, proof)).ok).toBe(true);
    expect(await authority().loginWithFederated(GHA_ISSUER, s, proof)).toEqual({
      ok: false,
      reason: "proof_reused",
    });
  });
});
