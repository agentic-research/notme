/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * registration-mark-cookie.do.test.ts — the FIRST-USER mark belongs to the
 * browser that earned it (notme-a2e75d).
 *
 * Options consumes the bootstrap code and marks the server-random userId as
 * the deployer's registration. The mark used to be keyed on that userId
 * alone, and the userId comes back in the same response body as the
 * challenge: whoever learned that body could finish the ceremony with their
 * own authenticator and become the administrator. That is the shape the
 * invite reservation closed in review M1, so the mark now carries the same
 * HttpOnly secret: SHA-256 stored with the mark, required by admit.
 *
 * The claim mark's half of this lives in bootstrap-claim.do.test.ts, on the
 * unclaimed authority that file walks. This file gets its own authority so
 * the first-user path is still open.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";
import worker from "../worker";
import { SoftwareAuthenticator } from "./__tests__/helpers/software-authenticator";
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

/** The `name=value` of the registration cookie a response set, if any. */
const regCookie = (res: Response) =>
  /__Host-notme_registration=[^;,\s]+/.exec(res.headers.get("set-cookie") ?? "")?.[0];

describe("the first-user mark is bound to the reserving browser (notme-a2e75d)", () => {
  it("registration.first-user.cookie — a first-user verify without the mark's cookie is refused; with it, admitted as admin", async () => {
    const opts = await post("/auth/passkey/register/options", {
      bootstrapCode: (env as { BOOTSTRAP_CODE?: string }).BOOTSTRAP_CODE,
    });
    expect(opts.status, await opts.clone().text()).toBe(200);
    const { userId, options } = (await opts.json()) as {
      userId: string;
      options: { challenge: string };
    };

    // The thief knows the userId and the challenge — the whole options body —
    // but not the browser's HttpOnly cookie.
    const thief = await SoftwareAuthenticator.create(RP_ID, ORIGIN);
    const stolen = await post("/auth/passkey/register/verify", {
      userId,
      response: await thief.register(options.challenge),
    });
    expect(stolen.status).toBe(403);
    expect(stolen.headers.get("set-cookie") ?? "").not.toMatch(/notme_session=[^;]+/);
    expect(await authority().getPrincipalScopes(userId)).toEqual([]);
    // Refused, not spent: the deployer is not locked out by the attempt.
    expect(await authority().registrationIsFirstUser()).toBe(true);

    // registration.mark.cross-cookie (security review F8): a VALID cookie
    // from the thief's own first-user registration does not open the
    // victim's mark — the hash is matched per userId, not "any live secret".
    const own = await post("/auth/passkey/register/options", {
      bootstrapCode: (env as { BOOTSTRAP_CODE?: string }).BOOTSTRAP_CODE,
    });
    expect(own.status, await own.clone().text()).toBe(200);
    const crossed = await post(
      "/auth/passkey/register/verify",
      { userId, response: await thief.register(options.challenge) },
      regCookie(own),
    );
    expect(crossed.status).toBe(403);
    expect(await authority().getPrincipalScopes(userId)).toEqual([]);

    // The browser that ran options still finishes, and is the admin.
    const deployer = await SoftwareAuthenticator.create(RP_ID, ORIGIN);
    const ok = await post(
      "/auth/passkey/register/verify",
      { userId, response: await deployer.register(options.challenge) },
      regCookie(opts),
    );
    expect(ok.status, await ok.clone().text()).toBe(200);
    expect(((await ok.json()) as { scopes: string[] }).scopes.sort()).toEqual([...ADMIN_SCOPES].sort());
  });

  it("registration.mark.pre-column — a mark with no stored hash (secret_hash='') is never admitted, whatever cookie is sent", async () => {
    // A row written before the column existed carries the DEFAULT ''. It must
    // fail closed, not match an empty or arbitrary secret (security review F8).
    const stub: any = authority();
    // One userId per attempt: a second challenge for the same userId in the
    // same second makes the "latest challenge" lookup ambiguous.
    for (const cookie of [undefined, "__Host-notme_registration=", "__Host-notme_registration=anything"]) {
      const userId = crypto.randomUUID();
      await (runInDurableObject as any)(stub, async (inst: any) => {
        inst.ctx.storage.sql.exec(
          "INSERT INTO first_user_registrations (user_id, expires_at, secret_hash) VALUES (?, ?, '')",
          userId,
          Math.floor(Date.now() / 1000) + 300,
        );
      });
      const { options } = (await stub.passkeyRegistrationOptions(userId, "user", RP_ID)) as {
        options: { challenge: string };
      };
      const user = await SoftwareAuthenticator.create(RP_ID, ORIGIN);
      const res = await post(
        "/auth/passkey/register/verify",
        { userId, response: await user.register(options.challenge) },
        cookie,
      );
      expect(res.status, String(cookie)).toBe(403);
      expect(await authority().getPrincipalScopes(userId)).toEqual([]);
    }
  });

  it("registration.cookie.host-prefix —the cookie is __Host- (Secure, Path=/, no Domain), HttpOnly and SameSite=Strict", async () => {
    // Any invite will do: the cookie is the same one for every mark.
    await authority().createPrincipalWithCapabilities("inviter", [...ADMIN_SCOPES]);
    const inv = await authority().createInviteToken("inviter", ["bridgeCert"], 3600);
    const opts = await post("/auth/passkey/register/options", { inviteToken: inv.token });
    expect(opts.status, await opts.clone().text()).toBe(200);
    const sc = opts.headers.get("set-cookie") ?? "";
    expect(sc).toMatch(/^__Host-notme_registration=[^;]+;/);
    expect(sc).toMatch(/;\s*Path=\/(;|$)/);
    expect(sc).not.toMatch(/Domain=/i);
    expect(sc).toMatch(/;\s*Secure/);
    expect(sc).toMatch(/;\s*HttpOnly/);
    expect(sc).toMatch(/;\s*SameSite=Strict/);
  });

  it("registration.cookie.cleared — verify clears the registration cookie, whatever the outcome", async () => {
    const inv = await authority().createInviteToken("inviter", ["bridgeCert"], 3600);
    const opts = await post("/auth/passkey/register/options", { inviteToken: inv.token });
    const { userId, options } = (await opts.json()) as { userId: string; options: { challenge: string } };
    const user = await SoftwareAuthenticator.create(RP_ID, ORIGIN);
    const cleared = /__Host-notme_registration=;[^,]*Max-Age=0/;

    // Refused (no cookie presented) still tells the browser to drop it.
    const refused = await post("/auth/passkey/register/verify", {
      userId,
      response: await user.register(options.challenge),
    });
    expect(refused.status).toBe(403);
    expect(refused.headers.get("set-cookie") ?? "").toMatch(cleared);

    const ok = await post(
      "/auth/passkey/register/verify",
      { userId, response: await user.register(options.challenge) },
      regCookie(opts),
    );
    expect(ok.status, await ok.clone().text()).toBe(200);
    const all = ok.headers.getSetCookie();
    expect(all.some((c) => cleared.test(c))).toBe(true);
    expect(all.some((c) => /^notme_session=[^;]+/.test(c))).toBe(true);

    // A verify that THROWS (here: a body that is not JSON) is cleared too
    // (security review F2) — the outer catch used to answer without it.
    vi.spyOn(console, "error").mockImplementation(() => {});
    const thrown = await worker.fetch(
      new Request(`${ORIGIN}/auth/passkey/register/verify`, {
        method: "POST",
        headers: { "content-type": "application/json", cookie: regCookie(opts)! },
        body: "{not json",
      }),
      { ...env, ...LOCAL_ENV },
    );
    vi.restoreAllMocks();
    expect(thrown.status).toBe(500);
    expect(await thrown.json()).toEqual({ error: "passkey error" });
    expect(thrown.headers.get("set-cookie") ?? "").toMatch(cleared);
  });
});
