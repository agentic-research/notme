/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * invite-join.do.test.ts — an invite is RESERVED when a registration starts
 * and CONSUMED only when the passkey verifies (notme-3dfe15, parts 4/5).
 *
 * The defect: /auth/passkey/register/options REDEEMED the invite before the
 * WebAuthn ceremony had happened, and /auth/passkey/register/verify then
 * enrolled the new principal with bridgeCert regardless of what the invite
 * said. So a cancelled or failed ceremony burned the invite, and a
 * successful one silently dropped every scope beyond bridgeCert — an
 * authorityManage invite produced a non-admin. POST /join, separately,
 * redeemed the invite and handed out a session for a principal with no
 * authenticator at all.
 *
 * The fix shape: options/join RESERVE the invite for one WebAuthn user id
 * (no principal yet); verify CONSUMES the reservation and creates the
 * principal with the invite's scopes in the same synchronous block that
 * stores the credential. A registration that holds no live reservation is
 * refused and stores nothing.
 */
import { env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import worker from "../worker";
import { SoftwareAuthenticator } from "./__tests__/helpers/software-authenticator";
import { verifySessionCookie } from "./auth/session";

const ORIGIN = "http://localhost:8788";
const RP_ID = "localhost";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };

const authority = () =>
  env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));

function post(path: string, body: unknown, cookie?: string) {
  return worker.fetch(
    new Request(`${ORIGIN}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(cookie ? { cookie } : {}) },
      body: JSON.stringify(body),
    }),
    { ...env, ...LOCAL_ENV },
  );
}

type Opts = { userId: string; options: { challenge: string }; scopes: string[] };

async function options(inviteToken: string): Promise<Opts> {
  const res = await post("/auth/passkey/register/options", { inviteToken });
  expect(res.status, await res.clone().text()).toBe(200);
  return (await res.json()) as Opts;
}

async function verify(auth: SoftwareAuthenticator, o: Opts, challenge = o.options.challenge) {
  return post("/auth/passkey/register/verify", {
    userId: o.userId,
    response: await auth.register(challenge),
  });
}

async function scopesIn(res: Response): Promise<string[]> {
  const raw = res.headers.get("set-cookie")!.split(";")[0]!.slice("notme_session=".length);
  const s = await verifySessionCookie(raw, await authority().getSessionSecret());
  return s!.scopes;
}

const invite = (scopes: string[]) =>
  authority().createInviteToken("admin-under-test", scopes, 3600);

beforeAll(async () => {
  // First user through the real ceremony, so every registration below is
  // an "everyone else" registration that needs an invite.
  const admin = await SoftwareAuthenticator.create(RP_ID, ORIGIN);
  const res = await post("/auth/passkey/register/options", {
    bootstrapCode: (env as { BOOTSTRAP_CODE?: string }).BOOTSTRAP_CODE,
  });
  expect(res.status, await res.clone().text()).toBe(200);
  const o = (await res.json()) as Opts;
  expect((await verify(admin, o)).status).toBe(200);
});

describe("invite reserve-then-consume (notme-3dfe15 parts 4/5)", () => {
  it("invite.join.failed-ceremony-keeps-invite — a failed ceremony does not burn the invite", async () => {
    const inv = await invite(["bridgeCert"]);
    const user = await SoftwareAuthenticator.create(RP_ID, ORIGIN);

    // Ceremony #1 fails: the authenticator signs the wrong challenge.
    const first = await options(inv.token);
    const bad = await verify(user, first, "d3JvbmctY2hhbGxlbmdl");
    expect(bad.status).not.toBe(200);

    // The same invite still admits the same person on a retry.
    const retry = await options(inv.token);
    const ok = await verify(user, retry);
    expect(ok.status, await ok.clone().text()).toBe(200);
  });

  it("invite.join.keeps-scopes — a successful registration gets the INVITE's scopes, not bridgeCert", async () => {
    const inv = await invite(["bridgeCert", "authorityManage", "sign:git"]);
    const user = await SoftwareAuthenticator.create(RP_ID, ORIGIN);
    const o = await options(inv.token);
    const res = await verify(user, o);
    expect(res.status, await res.clone().text()).toBe(200);

    const want = ["authorityManage", "bridgeCert", "sign:git"];
    expect((await scopesIn(res)).sort()).toEqual(want);
    expect((await authority().getPrincipalScopes(o.userId)).sort()).toEqual(want);
  });

  it("invite.join.single-use — two reservations, one consumption; the loser stores nothing", async () => {
    const inv = await invite(["bridgeCert"]);
    const a = await SoftwareAuthenticator.create(RP_ID, ORIGIN);
    const b = await SoftwareAuthenticator.create(RP_ID, ORIGIN);
    const oa = await options(inv.token);
    const ob = await options(inv.token);

    expect((await verify(b, ob)).status).toBe(200);

    const late = await verify(a, oa);
    expect(late.status).toBe(403);
    expect(late.headers.get("set-cookie")).toBeNull();
    // No principal, and no credential that a later LOGIN could turn into a
    // bridgeCert principal via ensurePasskeyPrincipal.
    expect(await authority().getPrincipalScopes(oa.userId)).toEqual([]);
    const lo = await post("/auth/passkey/login/options", {});
    const { challenge } = (await lo.json()) as { challenge: string };
    const login = await post("/auth/passkey/login/verify", {
      response: await a.authenticate(challenge),
    });
    expect(login.status).not.toBe(200);

    // And the invite is spent: a third registration cannot start.
    const third = await post("/auth/passkey/register/options", { inviteToken: inv.token });
    expect(third.status).toBe(403);
  });

  it("invite.join.no-authenticator — POST /join without a proof issues no session and creates no principal", async () => {
    const inv = await invite(["bridgeCert", "authorityManage"]);
    const res = await post("/join", { token: inv.token });
    const cookie = res.headers.get("set-cookie") ?? "";
    expect(cookie).not.toMatch(/notme_session=[^;]+/);

    // The invite was only reserved: the passkey ceremony it started still
    // completes and gets the invite's scopes.
    expect(res.status, await res.clone().text()).toBe(200);
    const o = (await res.json()) as Opts;
    expect(o.userId).toBeTruthy();
    const user = await SoftwareAuthenticator.create(RP_ID, ORIGIN);
    const v = await verify(user, o);
    expect(v.status, await v.clone().text()).toBe(200);
    expect((await scopesIn(v)).sort()).toEqual(["authorityManage", "bridgeCert"]);
  });

  it("invite.join.bad-oidc — POST /join with an invalid OIDC proof is 403 and does not burn the invite", async () => {
    const inv = await invite(["bridgeCert"]);
    const res = await post("/join", {
      token: inv.token,
      proof: { type: "oidc", token: "not.a.jwt" },
    });
    expect(res.status).toBe(403);
    expect(res.headers.get("set-cookie")).toBeNull();
    // Still usable.
    await options(inv.token);
  });
});
