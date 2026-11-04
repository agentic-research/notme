/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * oidc-issuer-audience.do.test.ts — every OIDC route reads its audience pin
 * per ISSUER, from the deployment's env (notme-0a1ee8).
 *
 * Google ID tokens carry aud=<client-id>.apps.googleusercontent.com, which a
 * single "notme.bot" pin could never match, so Google was left out of the
 * trusted set entirely. With GOOGLE_CLIENT_ID set, a Google token whose aud
 * is that client id now works at each route that takes an OIDC proof:
 * /cert (oidc), /join, /auth/oidc/login and /connections. With it unset,
 * Google is refused exactly as before. Each route is driven both ways, so a
 * caller still passing a fixed map shows up as one red test.
 *
 * The Google issuer is a local fixture (helpers/oidc-issuer.ts): real RS256
 * keys and JWKS behind a fetch stub, so nothing leaves the process.
 */
import { env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import worker from "../worker";
import { ghaPopBody } from "./__tests__/helpers/gha-token";
import { type FakeIssuer, fakeIssuer } from "./__tests__/helpers/oidc-issuer";
import { ADMIN_SCOPES } from "./auth/admin-scopes";

const ORIGIN = "http://localhost:8788";
const GOOGLE = "https://accounts.google.com";
const CLIENT_ID = "1234567890-notme.apps.googleusercontent.com";
const BASE_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };
const WITH_GOOGLE = { ...BASE_ENV, GOOGLE_CLIENT_ID: CLIENT_ID };

const authority = () => env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));

const call = (path: string, init: RequestInit, local: Record<string, string>) =>
  worker.fetch(new Request(`${ORIGIN}${path}`, init), { ...env, ...local });
const postJson = (path: string, body: unknown, local: Record<string, string>, headers: Record<string, string> = {}) =>
  call(path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) }, local);

let google: FakeIssuer;
const googleToken = (sub: string, aud = CLIENT_ID) =>
  google.token({ sub, aud, jti: crypto.randomUUID(), email: `${sub}@example.test` });
const newSub = (tag: string) => `${tag}-${crypto.randomUUID()}`;

async function linkedPrincipal(sub: string, scopes = ["bridgeCert"]) {
  const pid = `principal-google-${crypto.randomUUID()}`;
  await authority().createPrincipalWithCapabilities(pid, scopes);
  await authority().linkFederatedId(pid, GOOGLE, sub);
  return pid;
}

beforeAll(async () => {
  google = await fakeIssuer(GOOGLE);
  await authority().createPrincipalWithCapabilities("google-inviter", [...ADMIN_SCOPES]);
});

describe("POST /cert with a Google OIDC proof", () => {
  it("mints for the linked principal when GOOGLE_CLIENT_ID is set", async () => {
    const sub = newSub("cert");
    const pid = await linkedPrincipal(sub);
    const token = await googleToken(sub);
    const res = await postJson("/cert", { proof: { type: "oidc", token }, ...(await ghaPopBody(token)) }, WITH_GOOGLE);
    expect(res.status, await res.clone().text()).toBe(200);
    expect(((await res.json()) as { principal_id: string }).principal_id).toBe(pid);
  });

  it("refuses the same kind of token when GOOGLE_CLIENT_ID is unset", async () => {
    const sub = newSub("cert-off");
    await linkedPrincipal(sub);
    const token = await googleToken(sub);
    const res = await postJson("/cert", { proof: { type: "oidc", token }, ...(await ghaPopBody(token)) }, BASE_ENV);
    expect(res.status).toBe(401);
  });

  it("refuses a Google token minted for notme.bot: the pin is Google's client id, not notme's", async () => {
    const sub = newSub("cert-aud");
    await linkedPrincipal(sub);
    const token = await googleToken(sub, "notme.bot");
    const res = await postJson("/cert", { proof: { type: "oidc", token }, ...(await ghaPopBody(token)) }, WITH_GOOGLE);
    expect(res.status).toBe(401);
  });
});

describe("POST /join and /auth/oidc/login with a Google OIDC proof", () => {
  const join = async (sub: string, local: Record<string, string>) => {
    const inv = await authority().createInviteToken("google-inviter", ["bridgeCert"], 3600);
    return postJson("/join", { token: inv.token, proof: { type: "oidc", token: await googleToken(sub) } }, local);
  };

  it("/join links a Google identity when GOOGLE_CLIENT_ID is set, and /auth/oidc/login then signs it in", async () => {
    const sub = newSub("join");
    const joined = await join(sub, WITH_GOOGLE);
    expect(joined.status, await joined.clone().text()).toBe(200);
    const { principalId } = (await joined.json()) as { principalId: string };

    const login = await postJson("/auth/oidc/login", { token: await googleToken(sub) }, WITH_GOOGLE);
    expect(login.status, await login.clone().text()).toBe(200);
    expect(((await login.json()) as { principalId: string }).principalId).toBe(principalId);
  });

  it("/join refuses a Google identity when GOOGLE_CLIENT_ID is unset", async () => {
    // 403 is /join's documented status for a bad OIDC proof (ERROR_STATUS).
    expect((await join(newSub("join-off"), BASE_ENV)).status).toBe(403);
  });

  it("/auth/oidc/login refuses a linked Google identity when GOOGLE_CLIENT_ID is unset", async () => {
    const sub = newSub("login-off");
    await linkedPrincipal(sub);
    const res = await postJson("/auth/oidc/login", { token: await googleToken(sub) }, BASE_ENV);
    expect(res.status).toBe(401);
  });
});

describe("POST /connections with a Google OIDC proof", () => {
  /** A session cookie for a fresh Google-linked principal, via /auth/oidc/login. */
  async function session(): Promise<string> {
    const sub = newSub("session");
    await linkedPrincipal(sub);
    const res = await postJson("/auth/oidc/login", { token: await googleToken(sub) }, WITH_GOOGLE);
    expect(res.status, await res.clone().text()).toBe(200);
    const m = /notme_session=[^;]+/.exec(res.headers.get("set-cookie") ?? "");
    expect(m).not.toBeNull();
    return m![0];
  }

  it("connects a Google identity when GOOGLE_CLIENT_ID is set", async () => {
    const cookie = await session();
    const res = await postJson(
      "/connections",
      { proof: { type: "oidc", token: await googleToken(newSub("conn")) } },
      WITH_GOOGLE,
      { cookie },
    );
    expect(res.status, await res.clone().text()).toBe(200);
    expect(((await res.json()) as { provider: string }).provider).toBe(`oidc:${GOOGLE}`);
  });

  it("refuses it when GOOGLE_CLIENT_ID is unset", async () => {
    const cookie = await session();
    const res = await postJson(
      "/connections",
      { proof: { type: "oidc", token: await googleToken(newSub("conn-off")) } },
      BASE_ENV,
      { cookie },
    );
    expect(res.status).toBe(401);
  });
});
