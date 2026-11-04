/// <reference types="@cloudflare/vitest-plugin/types" />
/**
 * gha-rejected-events.do.test.ts — a GitHub Actions token minted for a
 * `pull_request` or `pull_request_target` run buys nothing (notme-fbb00e).
 *
 * `@notme/contract` declares GHA_REJECTED_EVENTS and says tokens from those
 * events "MUST NOT receive a notme bridge cert": `pull_request_target` runs
 * fork code in the UPSTREAM context, so its token carries the allowed
 * owner and clears GHA_ALLOWED_OWNERS. Nothing read `event_name`. The check
 * now lives in `validateGHAToken`, so /cert/gha, the /token exchange,
 * /bootstrap/claim and the AUTH binding inherit it, and in `verifyOIDC` for
 * the GitHub issuer, so /cert's oidc proof, /join and /auth/oidc/login do.
 *
 * Every presentation below would otherwise succeed: owner allowed, audience
 * right, fresh jti, and — for /cert — a linked identity.
 */
import { env } from "cloudflare:test";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { GHA_REJECTED_EVENTS } from "@notme/contract";
import worker from "../worker";
import { GHA_ISSUER, type GhaSigner, ghaPopBody, installGhaSigner, spkiPem } from "./__tests__/helpers/gha-token";

const ORIGIN = "http://localhost:8788";
const OWNER = "agentic-research";
const LOCAL_ENV = {
  SITE_URL: ORIGIN,
  SIGNET_AUTHORITY_URL: ORIGIN,
  GHA_ALLOWED_OWNERS: OWNER,
  GHA_CERT_AUDIENCE: "notme.bot",
};

let gha: GhaSigner;
let pem: string;
beforeAll(async () => {
  gha = await installGhaSigner({ owner: OWNER, repo: "events", audience: "notme.bot" });
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  pem = await spkiPem(kp.publicKey);
});
afterAll(() => gha.restore());

const authority = () => env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));

async function certGha(token: string) {
  return worker.fetch(
    new Request(`${ORIGIN}/cert/gha`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify(await ghaPopBody(token)),
    }),
    { ...env, ...LOCAL_ENV },
  );
}

async function certOidc(token: string) {
  return worker.fetch(
    new Request(`${ORIGIN}/cert`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ proof: { type: "oidc", token }, ...(await ghaPopBody(token)) }),
    }),
    { ...env, ...LOCAL_ENV },
  );
}

async function linked(event: string) {
  const sub = `repo:${OWNER}/events:ref:refs/heads/ev-${crypto.randomUUID()}`;
  const pid = `principal-ev-${crypto.randomUUID()}`;
  await authority().createPrincipalWithCapabilities(pid, ["bridgeCert"]);
  await authority().linkFederatedId(pid, GHA_ISSUER, sub);
  return gha.token({ sub, event_name: event });
}

describe("gha.rejected-events — pull_request / pull_request_target tokens are refused (notme-fbb00e)", () => {
  it("gha.rejected-events.contract — the list is the contract's, and non-empty", () => {
    expect([...GHA_REJECTED_EVENTS].sort()).toEqual(["pull_request", "pull_request_target"]);
  });

  for (const event of GHA_REJECTED_EVENTS) {
    it(`gha.rejected-events.cert-gha — ${event} is refused at /cert/gha`, async () => {
      const res = await certGha(await gha.token({ event_name: event }));
      expect(res.status).toBe(401);
    });

    it(`gha.rejected-events.binding — ${event} is refused through mintBridgeCert`, async () => {
      const r = await authority().mintBridgeCert({ kind: "gha-oidc", token: await gha.token({ event_name: event }) }, pem);
      expect(r).toEqual({ ok: false, reason: "invalid_gha_token" });
    });

    it(`gha.rejected-events.cert-oidc — ${event} is refused at /cert with an oidc proof`, async () => {
      const res = await certOidc(await linked(event));
      expect(res.status).toBe(401);
    });
  }

  it("gha.rejected-events.allowed — push and workflow_dispatch still mint", async () => {
    for (const event of ["push", "workflow_dispatch"]) {
      expect((await certGha(await gha.token({ event_name: event }))).status).toBe(200);
      expect((await authority().mintBridgeCert({ kind: "gha-oidc", token: await gha.token({ event_name: event }) }, pem)).ok).toBe(true);
      expect((await certOidc(await linked(event))).status).toBe(200);
    }
  });
});
