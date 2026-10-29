/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * bootstrap-claim.do.test.ts — first boot that a human can finish, with no
 * secret anywhere (notme-486e8a; Goal Zero criterion E, revisited).
 *
 * THE DEAD END. The attested bootstrap (BOOTSTRAP_GHA_SUBJECT) ran as a side
 * effect of /cert/gha and made the WORKFLOW the administrator. Its own comment
 * said "the human attaches a passkey by taking an invite from it" — but
 * /invites accepts only a browser session, and a workflow never has one. Once
 * that headless admin existed the authority read "closed", registration became
 * invite-only, and no human could ever get in without falling back to the
 * BOOTSTRAP_CODE secret this mechanism was meant to replace.
 *
 * THE FLOW NOW. The human registers a passkey on the unclaimed authority and
 * gets a short claim code, holding NOTHING. The named workflow approves that
 * code with its GitHub OIDC token (`gh workflow run claim-authority.yml -f
 * code=…`), and the passkey principal becomes the administrator. The human
 * holds the credential; GitHub attests the deployer; nothing secret crosses a
 * log.
 *
 * Each claim registration is gated on "no ADMINISTRATOR exists", not "no
 * credential exists": otherwise a stranger who registered first and was never
 * approved would lock the deployer out permanently. Anyone may open a claim;
 * only the code the workflow approves becomes admin.
 *
 * Real WebAuthn (software authenticator through @simplewebauthn/server) and
 * real RS256 GitHub tokens. One authority for the file, walked in order.
 */
import { env } from "cloudflare:test";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import worker from "../worker";
import { SoftwareAuthenticator } from "./__tests__/helpers/software-authenticator";
import { type GhaSigner, ghaPopBody, installGhaSigner } from "./__tests__/helpers/gha-token";
import { verifySessionCookie } from "./auth/session";

const ORIGIN = "http://localhost:8788";
const RP_ID = "localhost";
const OWNER = "agentic-research";
// Matches BOOTSTRAP_GHA_SUBJECT in vitest.workers.config.mts.
const LOCAL_ENV = {
  SITE_URL: ORIGIN,
  SIGNET_AUTHORITY_URL: ORIGIN,
  GHA_ALLOWED_OWNERS: OWNER,
  GHA_CERT_AUDIENCE: "notme.bot",
};

let gha: GhaSigner;
beforeAll(async () => {
  // sub = repo:agentic-research/notme:ref:refs/heads/main — the named workflow.
  gha = await installGhaSigner({ owner: OWNER, repo: "notme", audience: "notme.bot" });
});
afterAll(() => gha.restore());

const authority = () => env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
const call = (path: string, init: RequestInit) =>
  worker.fetch(new Request(`${ORIGIN}${path}`, init), { ...env, ...LOCAL_ENV });
const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  call(path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
const cookieOf = (res: Response) => res.headers.get("set-cookie")!.split(";")[0]!;

/** Register a passkey with no bootstrap code and no invite — a claim. */
async function claimRegistration() {
  const auth = await SoftwareAuthenticator.create(RP_ID, ORIGIN);
  const opts = await post("/auth/passkey/register/options", {});
  expect(opts.status, await opts.clone().text()).toBe(200);
  const o = (await opts.json()) as { userId: string; options: { challenge: string }; claim?: boolean };
  const verify = await post("/auth/passkey/register/verify", {
    userId: o.userId,
    response: await auth.register(o.options.challenge),
  });
  expect(verify.status, await verify.clone().text()).toBe(200);
  const v = (await verify.json()) as { scopes: string[]; claim?: { code: string; command: string; expires_in: number } };
  return { auth, principalId: o.userId, optionsClaim: o.claim, scopes: v.scopes, claim: v.claim, cookie: cookieOf(verify) };
}

const approve = (code: string, token: string) =>
  post("/bootstrap/claim", { code }, { authorization: `Bearer ${token}` });

let deployer: Awaited<ReturnType<typeof claimRegistration>>;
let stranger: Awaited<ReturnType<typeof claimRegistration>>;

describe("claiming a fresh authority with a passkey and an attested workflow", () => {
  it("a deploy workflow calling /cert/gha does NOT become the administrator", async () => {
    // The old trap: the release job shares the bootstrap subject, so the
    // first /cert/gha on a fresh authority made the workflow admin and shut
    // the door on every human.
    const token = await gha.token();
    const res = await call("/cert/gha", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify(await ghaPopBody(token)),
    });
    expect(res.status, await res.clone().text()).toBe(200);
    expect(((await res.json()) as { principal_id?: string }).principal_id).toBeUndefined();
    expect(await authority().hasAdministrator()).toBe(false);
  });

  it("registering on an unclaimed authority yields a claim code and NO scopes", async () => {
    deployer = await claimRegistration();
    expect(deployer.optionsClaim).toBe(true);
    expect(deployer.scopes).toEqual([]);
    expect(deployer.claim?.code).toMatch(/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/);
    expect(deployer.claim?.command).toContain(deployer.claim!.code);
    expect(await authority().getPrincipalScopes(deployer.principalId)).toEqual([]);
  });

  it("an unapproved claimant cannot administer", async () => {
    const res = await post("/invites", { scopes: ["bridgeCert"] }, { cookie: deployer.cookie });
    expect(res.status).toBe(403);
  });

  it("a stranger can ALSO open a claim — no one is locked out by registering first", async () => {
    stranger = await claimRegistration();
    expect(stranger.claim?.code).toBeTruthy();
    expect(stranger.claim?.code).not.toBe(deployer.claim?.code);
  });

  it("refuses approval by a workflow the operator did not name", async () => {
    const other = await gha.token({ sub: `repo:${OWNER}/some-other-repo:ref:refs/heads/main` });
    expect((await approve(deployer.claim!.code, other)).status).toBe(403);
    expect(await authority().hasAdministrator()).toBe(false);
  });

  it("refuses an unknown code", async () => {
    expect((await approve("BBBB-BBBB", await gha.token())).status).toBe(404);
  });

  it("refuses a forged token", async () => {
    const t = await gha.token();
    expect((await approve(deployer.claim!.code, t.slice(0, -6) + "AAAAAA")).status).toBe(401);
  });

  it("the named workflow approves the deployer's code, and that passkey becomes admin", async () => {
    const res = await approve(deployer.claim!.code, await gha.token());
    expect(res.status, await res.clone().text()).toBe(200);
    expect(((await res.json()) as { principal_id: string }).principal_id).toBe(deployer.principalId);
    expect((await authority().getPrincipalScopes(deployer.principalId)).sort()).toEqual(
      ["authorityManage", "bridgeCert", "certMint", "sign:attestation", "sign:git"],
    );
    expect(await authority().hasAdministrator()).toBe(true);
  });

  it("signing in afterwards gives an admin session that can issue invites", async () => {
    const lo = await post("/auth/passkey/login/options", {});
    const { challenge } = (await lo.json()) as { challenge: string };
    const lv = await post("/auth/passkey/login/verify", { response: await deployer.auth.authenticate(challenge) });
    expect(lv.status, await lv.clone().text()).toBe(200);
    const cookie = cookieOf(lv);
    const s = await verifySessionCookie(cookie.slice("notme_session=".length), await authority().getSessionSecret());
    expect(s!.scopes).toContain("authorityManage");
    expect((await post("/invites", { scopes: ["bridgeCert"] }, { cookie })).status).toBe(200);
  });

  it("the stranger's claim gained nothing", async () => {
    expect(await authority().getPrincipalScopes(stranger.principalId)).toEqual([]);
  });

  it("once claimed: no further approval, and registration is invite-only again", async () => {
    expect((await approve(stranger.claim!.code, await gha.token())).status).toBe(409);
    const opts = await post("/auth/passkey/register/options", {});
    expect(opts.status).toBe(403);
  });

  it("an earlier stranger's claim does not revive if the authority becomes claimable again", async () => {
    // If the administrator loses authorityManage (revoked), the authority is
    // claimable once more. The stranger's code from before the first claim
    // is still inside its TTL — it must have been voided at approval, not
    // left waiting for the door to reopen.
    const stub = authority();
    await stub.revokeCapability(deployer.principalId, "authorityManage", "test");
    expect(await stub.hasAdministrator()).toBe(false);
    const res = await approve(stranger.claim!.code, await gha.token());
    expect(res.status).toBe(404);
    expect(await stub.getPrincipalScopes(stranger.principalId)).toEqual([]);
  });

  it("each approval token is single-use", async () => {
    // Shared jti keyspace with /cert/gha, /cert and /token.
    const t = await gha.token();
    await approve("CCCC-CCCC", t);
    const again = await approve("CCCC-CCCC", t);
    expect(again.status).toBe(401);
    expect(await again.json()).toMatchObject({ error: "token already used" });
  });
});
