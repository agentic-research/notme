/// <reference types="@cloudflare/vitest-plugin/types" />
/**
 * registration-mark-reset.do.test.ts — a reset revokes in-flight
 * registration marks too (security review F4 of notme-a2e75d).
 *
 * resetPasskeyData wiped credentials, challenges and invite reservations,
 * but left first-user and claim marks live. #admitRegistration trusts a
 * first-user mark without re-checking first-user standing, so the browser
 * holding a pre-reset mark's cookie could still finish the ceremony and
 * become the administrator of the post-reset authority — the reset done
 * because that browser was distrusted did not revoke it.
 *
 * Its own authority (file-scoped storage): no administrator, so both a claim
 * and a first-user registration can be started.
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../worker";
import { SoftwareAuthenticator } from "./__tests__/helpers/software-authenticator";

const ORIGIN = "http://localhost:8788";
const RP_ID = "localhost";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };
const SUBJECT = "repo:agentic-research/notme:ref:refs/heads/main";

// Typed loosely: the stub's inferred return types are too deep for tsc.
const authority = (): any => env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));

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
const regCookie = (res: Response) =>
  /__Host-notme_registration=[^;,\s]+/.exec(res.headers.get("set-cookie") ?? "")?.[0];

/** Options, then the userId and the cookie the browser holds. */
async function start(body: unknown) {
  const res = await post("/auth/passkey/register/options", body);
  expect(res.status, await res.clone().text()).toBe(200);
  const { userId, options } = (await res.json()) as { userId: string; options: { challenge: string } };
  return { userId, challenge: options.challenge, cookie: regCookie(res) };
}

/**
 * Verify. Without `challenge`, against a FRESH one for the same userId — the
 * reset deleted the old one, and this test is about the mark, not the
 * challenge.
 */
async function finish(userId: string, cookie?: string, challenge?: string) {
  if (!challenge) {
    ({ options: { challenge } } = (await authority().passkeyRegistrationOptions(userId, "user", RP_ID)) as {
      options: { challenge: string };
    });
  }
  const auth = await SoftwareAuthenticator.create(RP_ID, ORIGIN);
  return post("/auth/passkey/register/verify", { userId, response: await auth.register(challenge!) }, cookie);
}

describe("resetPasskeyData revokes registration marks (security review F4)", () => {
  it("registration.reset.revokes-marks — a pre-reset first-user or claim mark cannot admit after reset, cookie or not", async () => {
    // First-user options first: once any passkey exists it is no longer
    // a first-user registration.
    const first = await start({ bootstrapCode: (env as { BOOTSTRAP_CODE?: string }).BOOTSTRAP_CODE });
    // A claim fully verified, so a claim CODE is pending approval too.
    const approved = await start({});
    const ok = await finish(approved.userId, approved.cookie, approved.challenge);
    expect(ok.status, await ok.clone().text()).toBe(200);
    const { claim } = (await ok.json()) as { claim: { code: string } };

    const claim2 = await start({});

    await authority().resetPasskeyData();

    const f = await finish(first.userId, first.cookie);
    expect(f.status).toBe(403);
    expect(await authority().getPrincipalScopes(first.userId)).toEqual([]);
    expect((await finish(claim2.userId, claim2.cookie)).status).toBe(403);
    // A code issued before the reset is not approvable after it.
    expect((await authority().approveBootstrapClaim(claim.code, SUBJECT)).ok).toBe(false);
  });
});
