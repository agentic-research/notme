/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * cert-exchange-oidc.do.test.ts — POST /cert with an OIDC proof works
 * (notme-486e8a follow-on: "if it advertises it should work").
 *
 * The API docs advertise `/cert` proof types "session (passkey cookie), oidc
 * (any JWT), bootstrap (deployer code)", with an OIDC example. Production
 * verified the token and then returned 501 "OIDC proof path not yet wired".
 *
 * What it does now is ADR-019's missing case 3 — automation acting under a
 * PRINCIPAL's authority. /cert/gha mints a workload identity that represents
 * no principal; this resolves a verified OIDC identity to the principal it was
 * LINKED to (by redeeming an invite with that OIDC proof) and mints for that
 * principal, scopes from its LIVE grants.
 *
 * Same defenses as /cert/gha: the proofs bind SHA-256(token), so captured
 * proofs cannot be paired with another token, and each token's jti is
 * single-use, so a captured token cannot be spent twice.
 */
import { env } from "cloudflare:test";
import { X509Certificate } from "@peculiar/x509";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import worker from "../worker";
import { GHA_ISSUER, type GhaSigner, ghaPopBody, installGhaSigner } from "./__tests__/helpers/gha-token";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };
const OWNER = "agentic-research";
const REPO = "oidc-proof";

let signer: GhaSigner;
beforeAll(async () => {
  signer = await installGhaSigner({ owner: OWNER, repo: REPO, audience: "notme.bot" });
});
afterAll(() => signer.restore());

const authority = () => env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
const post = (body: unknown) =>
  worker.fetch(
    new Request(`${ORIGIN}/cert`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }),
    { ...env, ...LOCAL_ENV },
  );

async function linkedPrincipal(scopes: string[], sub: string) {
  const pid = `principal-oidc-${crypto.randomUUID()}`;
  await authority().createPrincipalWithCapabilities(pid, scopes);
  await authority().linkFederatedId(pid, GHA_ISSUER, sub);
  return pid;
}

describe("POST /cert with an OIDC proof", () => {
  it("mints a cert pair for the principal the OIDC identity is LINKED to", async () => {
    const sub = `repo:${OWNER}/${REPO}:ref:refs/heads/linked-${crypto.randomUUID()}`;
    const pid = await linkedPrincipal(["bridgeCert"], sub);
    const token = await signer.token({ sub });
    const res = await post({ proof: { type: "oidc", token }, ...(await ghaPopBody(token)) });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { principal_id: string; scopes: string[]; auth_method: string; certificates: { signing: string } };
    expect(body.principal_id).toBe(pid);
    expect(body.scopes).toEqual(["bridgeCert"]);
    expect(body.auth_method).toBe(`oidc:${GHA_ISSUER}`);
    expect(new X509Certificate(body.certificates.signing)).toBeTruthy();
  });

  it("refuses an OIDC identity linked to no principal", async () => {
    const token = await signer.token({ sub: `repo:${OWNER}/${REPO}:ref:refs/heads/unlinked-${crypto.randomUUID()}` });
    const res = await post({ proof: { type: "oidc", token }, ...(await ghaPopBody(token)) });
    expect(res.status).toBe(403);
  });

  it("is no longer 501", async () => {
    const token = await signer.token();
    const res = await post({ proof: { type: "oidc", token }, ...(await ghaPopBody(token)) });
    expect(res.status).not.toBe(501);
  });

  it("refuses a token spent twice — jti is single-use", async () => {
    const sub = `repo:${OWNER}/${REPO}:ref:refs/heads/replay-${crypto.randomUUID()}`;
    await linkedPrincipal(["bridgeCert"], sub);
    const token = await signer.token({ sub });
    expect((await post({ proof: { type: "oidc", token }, ...(await ghaPopBody(token)) })).status).toBe(200);
    const again = await post({ proof: { type: "oidc", token }, ...(await ghaPopBody(token)) });
    // Same answer /cert/gha gives, and the same jti keyspace: one GitHub
    // token is spendable once across BOTH routes, not once at each.
    expect(again.status).toBe(401);
    expect(await again.json()).toMatchObject({ error: "token already used" });
  });

  it("refuses proofs bound to a DIFFERENT token", async () => {
    const sub = `repo:${OWNER}/${REPO}:ref:refs/heads/swap-${crypto.randomUUID()}`;
    await linkedPrincipal(["bridgeCert"], sub);
    const token = await signer.token({ sub });
    const other = await signer.token({ sub });
    const res = await post({ proof: { type: "oidc", token }, ...(await ghaPopBody(other)) });
    expect(res.status).toBe(401);
    // The proof is checked BEFORE the jti is spent, so this forged attempt
    // must not have burned the real token. (/cert/gha spends first.)
    expect((await post({ proof: { type: "oidc", token }, ...(await ghaPopBody(token)) })).status).toBe(200);
  });

  it("issues only what the principal's LIVE grants allow, and never certMint", async () => {
    const sub = `repo:${OWNER}/${REPO}:ref:refs/heads/admin-${crypto.randomUUID()}`;
    await linkedPrincipal(["bridgeCert", "authorityManage", "certMint"], sub);
    const token = await signer.token({ sub });
    const res = await post({
      proof: { type: "oidc", token },
      scopes: ["bridgeCert", "authorityManage", "certMint"],
      ...(await ghaPopBody(token)),
    });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { scopes: string[] }).scopes).toEqual(["bridgeCert"]);
  });

  it("refuses a wrong-audience token", async () => {
    const token = await signer.token({ aud: "https://elsewhere.invalid" });
    const res = await post({ proof: { type: "oidc", token }, ...(await ghaPopBody(token)) });
    expect(res.status).toBe(401);
  });
});
