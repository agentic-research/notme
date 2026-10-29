/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * registration-gate.do.test.ts — an authority does not admit strangers
 * (notme-2c4209, ADR-021; Goal Zero criterion B's registration clause).
 *
 * Until now only the FIRST user needed anything: everyone else registered a
 * passkey freely, received a session carrying bridgeCert, and exchanged it
 * at /cert/passkey for a real CA-signed cert pair. An open-registration
 * certificate authority, recorded nowhere but an inline comment.
 *
 * The gate is an invite TODAY and a trust policy bundle EVENTUALLY (signet
 * ADR-011 / sigpol, whose §5.3 is exactly this check). Both are the same
 * decision — registration is a policy question with an answer, not an
 * omission — so these tests assert the property, not the mechanism.
 */
import { env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import worker from "../worker";
import { SoftwareAuthenticator } from "./__tests__/helpers/software-authenticator";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };

const authority = () =>
  env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));

function registerOptions(body: unknown) {
  return worker.fetch(
    new Request(`${ORIGIN}/auth/passkey/register/options`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }),
    { ...env, ...LOCAL_ENV },
  );
}

// `isFirstUser` counts passkey_users, so the everyone-else path only exists
// once a real registration has happened. Seeding principals does not reach
// it — the first user is established through the actual ceremony, with the
// deployment's bootstrap code, exactly as an operator would.
beforeAll(async () => {
  const admin = await SoftwareAuthenticator.create("localhost", ORIGIN);
  const opts = await registerOptions({
    bootstrapCode: (env as { BOOTSTRAP_CODE?: string }).BOOTSTRAP_CODE,
  });
  expect(opts.status, await opts.clone().text()).toBe(200);
  const { userId, options } = (await opts.json()) as {
    userId: string;
    options: { challenge: string };
  };
  const verify = await worker.fetch(
    new Request(`${ORIGIN}/auth/passkey/register/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ userId, response: await admin.register(options.challenge) }),
    }),
    { ...env, ...LOCAL_ENV },
  );
  expect(verify.status, await verify.clone().text()).toBe(200);
});

describe("registration is gated (notme-2c4209)", () => {
  it("REFUSES a stranger with no invite once the authority has an administrator", async () => {
    const res = await registerOptions({});
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    // The SPECIFIC refusal, not just "some 403 mentioning invites". Removing
    // the no-token guard still yields 403 — redeemInviteToken(undefined)
    // fails too — so an assertion on the status, or on /invite/i, cannot
    // tell a present gate from an absent one. Mutation testing found exactly
    // that: the guard could be deleted with every test still green.
    expect(body.error).toMatch(/invite-only/);
    expect(body.error).not.toMatch(/expired|already-used/);
  });

  it("ADMITS a holder of a valid invite, and consumes it", async () => {
    const invite = await authority().createInviteToken(
      "granter-principal",
      ["bridgeCert"],
      3600,
    );
    const res = await registerOptions({ inviteToken: invite.token });
    expect(res.status, await res.clone().text()).toBe(200);

    // Single-use: the same token cannot admit a second stranger.
    const replay = await registerOptions({ inviteToken: invite.token });
    expect(replay.status).toBe(403);
  });

  it("REFUSES a forged or expired invite", async () => {
    expect((await registerOptions({ inviteToken: "not-a-real-token" })).status).toBe(403);
    const expired = await authority().createInviteToken("granter-principal", ["bridgeCert"], -1);
    expect((await registerOptions({ inviteToken: expired.token })).status).toBe(403);
  });

  it("grants the INVITE's scopes, never scopes the caller asked for", async () => {
    const invite = await authority().createInviteToken(
      "granter-principal",
      ["bridgeCert"],
      3600,
    );
    const res = await registerOptions({
      inviteToken: invite.token,
      scopes: ["bridgeCert", "authorityManage", "certMint"],
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { scopes: string[] };
    expect(body.scopes).toEqual(["bridgeCert"]);
  });
});
