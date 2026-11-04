/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * invite-federated-admin.do.test.ts — "first user" means "nobody can
 * administer", not "passkey_users is empty" (review L2, notme-3dfe15).
 *
 * register/options and verifyRegistration both decided first-user standing
 * by COUNT(passkey_users) = 0. On an authority whose administrator signs in
 * with a linked OIDC identity and holds no passkey, every invitee therefore
 * hit the first-user branch — "bootstrap required" — and could not join with
 * a passkey at all. And the admit hook trusted the same count, so any
 * registration that reached verify on such an authority would have been
 * treated as the deployer and handed the admin scopes.
 *
 * Its own file because it needs an authority with NO passkey user: the
 * "default" instance is per-file here.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import worker from "../worker";
import { SoftwareAuthenticator } from "./__tests__/helpers/software-authenticator";
import { ADMIN_SCOPES } from "./auth/admin-scopes";
import {
  createPrincipal,
  findPrincipalByFederated,
  grantCapability,
  linkFederatedIdentity,
} from "./auth/principals";
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

const rsvCookie = (res: Response) =>
  /__Host-notme_registration=[^;,\s]+/.exec(res.headers.get("set-cookie") ?? "")?.[0];

beforeAll(async () => {
  // An administrator who authenticates by OIDC alone: grants plus a linked
  // GitHub Actions identity, and no passkey.
  await runInDurableObject(authority(), async (_auth, state) => {
    const sql = state.storage.sql;
    createPrincipal(sql, "oidc-admin", undefined, "test");
    for (const s of ADMIN_SCOPES) grantCapability(sql, "oidc-admin", s, "test");
    linkFederatedIdentity(
      sql,
      "oidc-admin",
      "https://token.actions.githubusercontent.com",
      "repo:example/deploy:ref:refs/heads/main",
    );
  });
});

describe("first-user standing comes from who can administer (review L2)", () => {
  // FIRST, while passkey_users is still empty: that is the condition the
  // old count-based admit mistook for "this is the deployer".
  it("invite.first-user.admit-gate — a verified registration with no first-user mark is not made an admin", async () => {
    // A challenge issued with no gate passed at all (as a stub holder could).
    const userId = crypto.randomUUID();
    // Typed loosely: the stub's inferred return type is too deep for tsc.
    const stub: any = authority();
    const { options } = (await stub.passkeyRegistrationOptions(userId, "user", RP_ID)) as {
      options: { challenge: string };
    };
    const user = await SoftwareAuthenticator.create(RP_ID, ORIGIN);
    const v = await post("/auth/passkey/register/verify", {
      userId,
      response: await user.register(options.challenge),
    });
    expect(v.status).toBe(403);
    expect(await authority().getPrincipalScopes(userId)).toEqual([]);
  });

  it("invite.first-user.oidc-admin — an OIDC-only admin's invitee joins with a passkey and gets the INVITE's scopes", async () => {
    const inv = await authority().createInviteToken("oidc-admin", ["bridgeCert"], 3600);
    const opts = await post("/auth/passkey/register/options", { inviteToken: inv.token });
    expect(opts.status, await opts.clone().text()).toBe(200);
    const { userId, options } = (await opts.json()) as {
      userId: string;
      options: { challenge: string };
    };
    const user = await SoftwareAuthenticator.create(RP_ID, ORIGIN);
    const v = await post(
      "/auth/passkey/register/verify",
      { userId, response: await user.register(options.challenge) },
      rsvCookie(opts),
    );
    expect(v.status, await v.clone().text()).toBe(200);
    const raw = v.headers.get("set-cookie")!.split(";")[0]!.slice("notme_session=".length);
    const s = await verifySessionCookie(raw, await authority().getSessionSecret());
    // The invite's scopes — NOT the deployer's, though this was the first
    // passkey the authority had ever seen.
    expect(s!.scopes).toEqual(["bridgeCert"]);
    expect(await authority().getPrincipalScopes(userId)).toEqual(["bridgeCert"]);
  });
});

describe("a federated link is never silently moved (review I1)", () => {
  // linkFederatedIdentity was INSERT OR REPLACE on UNIQUE(provider,
  // provider_sub): linking an identity that already belonged to someone
  // re-pointed it at the new principal. POST /join guards against that with
  // a 409, but the linkFederatedId RPC called it unguarded.
  it("federated.link.no-replace — linking an identity owned by another principal fails and leaves the owner in place", async () => {
    await runInDurableObject(authority(), async (_auth, state) => {
      const sql = state.storage.sql;
      createPrincipal(sql, "usurper", undefined, "test");
      const iss = "https://token.actions.githubusercontent.com";
      const sub = "repo:example/deploy:ref:refs/heads/main"; // oidc-admin's
      expect(() => linkFederatedIdentity(sql, "usurper", iss, sub)).toThrow();
      expect(findPrincipalByFederated(sql, iss, sub)).toBe("oidc-admin");
    });
  });
});
