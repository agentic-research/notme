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
import { env, runInDurableObject } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import worker from "../worker";
import { SoftwareAuthenticator } from "./__tests__/helpers/software-authenticator";
import { verifySessionCookie } from "./auth/session";
import { ADMIN_SCOPES } from "./auth/admin-scopes";

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

type Opts = {
  userId: string;
  options: { challenge: string };
  scopes: string[];
  /** The reservation cookie the browser was handed, if any (review M1). */
  rsv?: string;
};

/** The `name=value` of the invite-reservation cookie a response set, if any. */
function rsvCookie(res: Response): string | undefined {
  const sc = res.headers.get("set-cookie") ?? "";
  const m = /notme_invite_reservation=[^;,\s]+/.exec(sc);
  return m?.[0];
}

async function asOpts(res: Response): Promise<Opts> {
  return { ...((await res.json()) as Opts), rsv: rsvCookie(res) };
}

async function options(inviteToken: string): Promise<Opts> {
  const res = await post("/auth/passkey/register/options", { inviteToken });
  expect(res.status, await res.clone().text()).toBe(200);
  return asOpts(res);
}

async function verify(
  auth: SoftwareAuthenticator,
  o: Opts,
  challenge = o.options.challenge,
  cookie: string | undefined = o.rsv,
) {
  return post(
    "/auth/passkey/register/verify",
    { userId: o.userId, response: await auth.register(challenge) },
    cookie,
  );
}

async function scopesIn(res: Response): Promise<string[]> {
  const raw = res.headers.get("set-cookie")!.split(";")[0]!.slice("notme_session=".length);
  const s = await verifySessionCookie(raw, await authority().getSessionSecret());
  return s!.scopes;
}

const invite = (scopes: string[]) =>
  authority().createInviteToken("inviter", scopes, 3600);

let adminCookie = "";

beforeAll(async () => {
  // The inviter really holds what its invites grant (review M2). Grants only:
  // no passkey and no identity, so it is not an authenticator.
  await authority().createPrincipalWithCapabilities("inviter", [...ADMIN_SCOPES]);
  // First user through the real ceremony, so every registration below is
  // an "everyone else" registration that needs an invite.
  const admin = await SoftwareAuthenticator.create(RP_ID, ORIGIN);
  const res = await post("/auth/passkey/register/options", {
    bootstrapCode: (env as { BOOTSTRAP_CODE?: string }).BOOTSTRAP_CODE,
  });
  expect(res.status, await res.clone().text()).toBe(200);
  const o = (await res.json()) as Opts;
  const v = await verify(admin, o);
  expect(v.status).toBe(200);
  adminCookie = v.headers.get("set-cookie")!.split(";")[0]!;
});

describe("invite reserve-then-consume (notme-3dfe15 parts 4/5)", () => {
  it("invite.join.failed-ceremony-keeps-invite — a failed ceremony does not burn the invite", async () => {
    const inv = await invite(["bridgeCert"]);
    const user = await SoftwareAuthenticator.create(RP_ID, ORIGIN);

    // Ceremony #1 fails: the authenticator signs the wrong challenge.
    const first = await options(inv.token);
    const bad = await verify(user, first, "d3JvbmctY2hhbGxlbmdl");
    expect(bad.status).not.toBe(200);
    // …and the failure must not tell the caller what the RIGHT challenge
    // was. @simplewebauthn's mismatch error names the expected challenge,
    // and the route used to return e.message as the 500 body — handing
    // anyone who knew a userId the secret half of someone else's ceremony.
    expect(await bad.text()).not.toContain(first.options.challenge);

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
    const o = await asOpts(res);
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

describe("a reservation belongs to the browser that made it (review M1)", () => {
  // The reservation was keyed only on the server-random userId, which comes
  // back in the same response as the challenge. Anyone who learned both —
  // and the 500 body handed out the challenge — could finish the ceremony
  // with their own authenticator and take the invite's scopes. Now /join and
  // register/options set an HttpOnly reservation cookie, and verify must
  // present it.
  it("invite.join.reservation-cookie — the reservation response sets an HttpOnly, Secure, SameSite=Strict cookie", async () => {
    const inv = await invite(["bridgeCert"]);
    const res = await post("/join", { token: inv.token });
    expect(res.status).toBe(200);
    const sc = res.headers.get("set-cookie") ?? "";
    expect(sc).toMatch(/notme_invite_reservation=/);
    expect(sc).toMatch(/HttpOnly/i);
    expect(sc).toMatch(/Secure/i);
    expect(sc).toMatch(/SameSite=Strict/i);
  });

  it("invite.join.failed-verify-burns-challenge — a failed verify burns the challenge it was tried against", async () => {
    const inv = await invite(["bridgeCert"]);
    const o = await options(inv.token);
    const user = await SoftwareAuthenticator.create(RP_ID, ORIGIN);
    expect((await verify(user, o, "d3JvbmctY2hhbGxlbmdl")).status).not.toBe(200);
    // Even the right signature, with the right cookie, cannot use it now.
    expect((await verify(user, o)).status).not.toBe(200);
  });

  it("invite.join.reservation-cookie — a verify without the reservation cookie is refused and spends nothing", async () => {
    const inv = await invite(["bridgeCert", "authorityManage"]);
    const o = await options(inv.token);
    const thief = await SoftwareAuthenticator.create(RP_ID, ORIGIN);
    // Knows the userId and the challenge; does not hold the browser's cookie.
    const stolen = await verify(thief, o, o.options.challenge, "");
    expect(stolen.status).toBe(403);
    expect(stolen.headers.get("set-cookie") ?? "").not.toMatch(/notme_session=/);
    expect(await authority().getPrincipalScopes(o.userId)).toEqual([]);

    // The invitee still gets in with a fresh reservation.
    const user = await SoftwareAuthenticator.create(RP_ID, ORIGIN);
    const again = await options(inv.token);
    const ok = await verify(user, again);
    expect(ok.status, await ok.clone().text()).toBe(200);
  });
});

describe("an invite is only as good as its inviter's CURRENT grants (review M2)", () => {
  // canGrant ran once, when the invite was minted. Revoking the inviter left
  // every invite they had already minted live for its whole lifetime — so a
  // de-privileged admin's 7-day authorityManage link undid the revocation.
  it("invite.consume.inviter-live — an inviter who lost authorityManage cannot have it consumed", async () => {
    await authority().createPrincipalWithCapabilities("inviter-revoked", [...ADMIN_SCOPES]);
    const inv = await authority().createInviteToken(
      "inviter-revoked",
      ["bridgeCert", "authorityManage"],
      3600,
    );
    const o = await options(inv.token);
    await authority().revokeCapability("inviter-revoked", "authorityManage", "test");

    const user = await SoftwareAuthenticator.create(RP_ID, ORIGIN);
    const res = await verify(user, o);
    expect(res.status).toBe(403);
    expect(await authority().getPrincipalScopes(o.userId)).toEqual([]);
    // …and it cannot be reserved again either.
    const again = await post("/auth/passkey/register/options", { inviteToken: inv.token });
    expect(again.status).toBe(403);
  });
});

describe("invites minted before the ceiling are not grandfathered (review M3)", () => {
  // The 7-day clamp lived only in createInvite, so an invite minted earlier
  // with a years-long TTL stayed live — and those are exactly the invites
  // whose /join?t= links were written into the invocation log.
  it("invite.ttl.legacy-dead — an invite whose lifetime exceeds the ceiling is dead, whenever it was minted", async () => {
    const token = crypto.randomUUID();
    await runInDurableObject(authority(), async (_auth, state) => {
      // A pre-fix row, written the way createInvite used to write it:
      // created now, expiring in ten years.
      state.storage.sql.exec(
        "INSERT INTO invites (token, created_by, scopes, expires_at) VALUES (?, ?, ?, ?)",
        token,
        "inviter",
        JSON.stringify(["bridgeCert", "authorityManage"]),
        new Date(Date.now() + 10 * 365 * 24 * 3600 * 1000).toISOString(),
      );
    });
    const res = await post("/auth/passkey/register/options", { inviteToken: token });
    expect(res.status).toBe(403);

    // The boundary: an invite minted AT the ceiling is still live.
    const atCeiling = await authority().createInviteToken("inviter", ["bridgeCert"], 7 * 24 * 3600);
    await options(atCeiling.token);
  });
});

describe("consume and store are one transaction (review L1)", () => {
  // admit ran in its own transactionSync and COMMITTED; the passkey_users and
  // passkey_credentials inserts came after it, outside. A credential insert
  // that threw (a colliding credential_id — attacker-chosen in the
  // attestation) left the invite spent and a principal holding its scopes
  // with no credential at all.
  it("invite.join.store-atomic — a failing credential insert leaves the invite unspent and no principal", async () => {
    const inv = await invite(["bridgeCert", "authorityManage"]);
    const user = await SoftwareAuthenticator.create(RP_ID, ORIGIN);
    // Squat the credential id this authenticator will present.
    await runInDurableObject(authority(), async (_auth, state) => {
      state.storage.sql.exec(
        "INSERT INTO passkey_credentials (credential_id, user_id, public_key, counter, transports) VALUES (?, ?, ?, ?, ?)",
        user.credentialIdB64u,
        "squatter",
        "AA==",
        0,
        "[]",
      );
    });
    const o = await options(inv.token);
    const res = await verify(user, o);
    expect(res.status).not.toBe(200);
    expect(await authority().getPrincipalScopes(o.userId)).toEqual([]);
    await runInDurableObject(authority(), async (_auth, state) => {
      const rows = state.storage.sql
        .exec("SELECT COUNT(*) AS n FROM passkey_users WHERE user_id = ?", o.userId)
        .toArray() as Array<{ n: number }>;
      expect(rows[0]!.n).toBe(0);
    });
    // Unspent: another registration can still start under it.
    await options(inv.token);
  });
});

describe("the invite token stays out of request URLs (notme-3dfe15 part 2)", () => {
  // Workers invocation logs (wrangler.toml [observability.logs]) record the
  // request URL. A link of the form /join?t=<token> therefore wrote a bearer
  // credential — authorityManage, possibly — into the log of every request
  // that opened it. A URL FRAGMENT is never sent to the server, so the
  // browser keeps it and POSTs it in a body, which is not logged.
  it("invite.link.fragment — POST /invites returns a link with the token in the fragment, not the query", async () => {
    const res = await post("/invites", { scopes: ["bridgeCert"] }, adminCookie);
    expect(res.status, await res.clone().text()).toBe(200);
    const { token, url } = (await res.json()) as { token: string; url: string };
    const u = new URL(url);
    expect(u.pathname).toBe("/join");
    expect(u.search).toBe("");
    expect(u.hash).toBe(`#t=${token}`);
  });

  it("invite.link.fragment — GET /join serves the page without a token in the query", async () => {
    const res = await worker.fetch(new Request(`${ORIGIN}/join`), {
      ...env,
      ...LOCAL_ENV,
      ASSETS: { fetch: async (r: Request) => new Response(`asset:${new URL(r.url).pathname}`) },
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("asset:/_login");
  });
});
