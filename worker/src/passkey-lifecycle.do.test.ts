/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * passkey-lifecycle.do.test.ts — register → login → revoke → login again,
 * through the REAL routes with a REAL (software) authenticator.
 *
 * Why this exists: grant-revocation.do.test.ts proved ensurePasskeyPrincipal
 * works by calling it inside the DO. That is a property of the helper, not
 * of the route — remove the call from /auth/passkey/register/verify and that
 * test stays green. This file is the one that goes red: it drives the
 * WebAuthn ceremony through @simplewebauthn/server's actual verification and
 * then reads the resulting session's scopes, which only exist if the route
 * enrolled the principal.
 *
 * The authenticator is software but not a mock: it builds a genuine
 * attestationObject and signs real assertions. Anything the server accepts
 * here, hardware could have produced.
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
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
function get(path: string, cookie: string) {
  return worker.fetch(
    new Request(`${ORIGIN}${path}`, { headers: { cookie } }),
    { ...env, ...LOCAL_ENV },
  );
}
const cookieOf = (res: Response) =>
  res.headers.get("set-cookie")!.split(";")[0]!;

/** Full registration ceremony through the routes. Returns the session cookie + principal id. */
async function register(auth: SoftwareAuthenticator, bootstrapCode?: string) {
  const opts = await post("/auth/passkey/register/options", { bootstrapCode });
  expect(opts.status, await opts.clone().text()).toBe(200);
  // The route returns { options: {challenge, ...}, isFirstUser, userId, scopes }.
  const { userId, options } = (await opts.json()) as {
    userId: string;
    options: { challenge: string };
  };
  const verify = await post("/auth/passkey/register/verify", {
    userId,
    response: await auth.register(options.challenge),
  });
  expect(verify.status, await verify.clone().text()).toBe(200);
  return { cookie: cookieOf(verify), principalId: userId };
}

/** Full login ceremony through the routes. */
async function login(auth: SoftwareAuthenticator) {
  const opts = await post("/auth/passkey/login/options", {});
  const { challenge } = (await opts.json()) as { challenge: string };
  const verify = await post("/auth/passkey/login/verify", {
    response: await auth.authenticate(challenge),
  });
  expect(verify.status, await verify.clone().text()).toBe(200);
  return cookieOf(verify);
}

async function scopesIn(cookie: string): Promise<string[]> {
  const raw = cookie.slice("notme_session=".length);
  const s = await verifySessionCookie(raw, await authority().getSessionSecret());
  return s!.scopes;
}

describe("passkey lifecycle through the real routes", () => {
  it("first user: registers as a principal with admin GRANTS; revocation survives re-login", async () => {
    // First registration on a fresh authority needs the deployment's
    // BOOTSTRAP_CODE — the operator secret, bound in vitest.workers.config.mts.
    const bootstrapCode = (env as { BOOTSTRAP_CODE?: string }).BOOTSTRAP_CODE;

    const admin = await SoftwareAuthenticator.create(RP_ID, ORIGIN);
    const { cookie, principalId } = await register(admin, bootstrapCode);

    // The session's scopes came from the GRANT STORE, and the store agrees.
    const sessionScopes = await scopesIn(cookie);
    const storeScopes = await authority().getPrincipalScopes(principalId);
    expect(storeScopes).toEqual(expect.arrayContaining(["bridgeCert", "authorityManage", "certMint"]));
    expect(sessionScopes.sort()).toEqual([...storeScopes].sort());

    // Admin route admits the live session.
    expect((await get("/admin/alarm-health", cookie)).status).toBe(200);

    // Revoke certMint on the admin (allowed — only authorityManage is self-protected).
    const rev = await post(`/principals/${principalId}/revoke`, { scope: "certMint" }, cookie);
    expect(rev.status).toBe(200);

    // A FRESH login — a real assertion with a real signature — must not
    // restore what was revoked. This is finding (b) of notme-77a024 closed
    // at the route, not just at the helper.
    const cookie2 = await login(admin);
    const scopes2 = await scopesIn(cookie2);
    expect(scopes2).toContain("authorityManage");
    expect(scopes2).not.toContain("certMint");
  });

  it("second user: registers with bridgeCert only, and cannot reach admin routes", async () => {
    const user = await SoftwareAuthenticator.create(RP_ID, ORIGIN);
    const { cookie, principalId } = await register(user);
    expect(await scopesIn(cookie)).toEqual(["bridgeCert"]);
    expect(await authority().getPrincipalScopes(principalId)).toEqual(["bridgeCert"]);
    expect((await get("/admin/alarm-health", cookie)).status).toBe(403);
  });

  it("the server rejects a forged assertion — the authenticator is real, not a bypass", async () => {
    const legit = await SoftwareAuthenticator.create(RP_ID, ORIGIN);
    await register(legit);
    const impostor = await SoftwareAuthenticator.create(RP_ID, ORIGIN);

    const opts = await post("/auth/passkey/login/options", {});
    const { challenge } = (await opts.json()) as { challenge: string };
    // Impostor signs with its own key but claims the legit credential id.
    const assertion = await impostor.authenticate(challenge);
    assertion.id = legit.credentialIdB64u;
    assertion.rawId = legit.credentialIdB64u;
    const verify = await post("/auth/passkey/login/verify", { response: assertion });
    expect(verify.status).not.toBe(200);
  });
});
