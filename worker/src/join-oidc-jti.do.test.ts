/// <reference types="@cloudflare/vitest-plugin/types" />
/**
 * join-oidc-jti.do.test.ts — an OIDC proof presented at POST /join is
 * single-use, keyed by its `jti` (notme-3dfe15 part 1, interim option A).
 *
 * The residual this closes (worker/THREAT_MODEL.md, "replayed OIDC proof on
 * /join"): no server-issued nonce is bound into the id_token, so an
 * unexpired token for an identity X that has never joined could be replayed
 * with any live invite. That squats X: X's own later join gets 409 and X's
 * `/auth/oidc/login` lands in the attacker's principal. The tokens /join
 * accepts (aud `notme.bot`) are the same tokens /cert/gha, /cert and /token
 * spend, so "captured" includes "already spent at another route".
 *
 * The rule now, the same one those routes follow: one token, one spend.
 * - /join refuses a token whose jti is already spent in the shared
 *   `jti:<jti>` keyspace (/cert/gha, /cert, /token, /bootstrap/claim), and
 *   writes it there when a join succeeds.
 * - The authority DO consumes `(issuer, jti)` in the SAME synchronous block
 *   that redeems the invite and links the identity, so two concurrent uses
 *   cannot both win and the refusal does not depend on the link surviving.
 * - A refused join (bad invite, already-linked identity) spends nothing.
 * - A token without a jti is refused (fail closed), as at /cert/gha.
 *
 * Option B (a server-issued nonce bound into the proof) is notme-e3dede.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import worker from "../worker";
import { type GhaSigner, ghaPopBody, installGhaSigner } from "./__tests__/helpers/gha-token";
import { ADMIN_SCOPES } from "./auth/admin-scopes";

const ORIGIN = "http://localhost:8788";
const OWNER = "example";
const LOCAL_ENV = {
  SITE_URL: ORIGIN,
  SIGNET_AUTHORITY_URL: ORIGIN,
  GHA_ALLOWED_OWNERS: OWNER,
  GHA_CERT_AUDIENCE: "notme.bot",
};

const authority = () =>
  env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));

const call = (path: string, init: RequestInit) =>
  worker.fetch(new Request(`${ORIGIN}${path}`, init), { ...env, ...LOCAL_ENV });

const join = (invite: string, token: string) =>
  call("/join", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token: invite, proof: { type: "oidc", token } }),
  });

const certGha = async (token: string) =>
  call("/cert/gha", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    body: JSON.stringify(await ghaPopBody(token)),
  });

const invite = async () =>
  (await authority().createInviteToken("inviter", ["bridgeCert"], 3600)).token;

/**
 * The invite is unspent: a fresh token for a never-seen identity can still
 * join with it. (A passkey reservation would also show it, but needs a
 * first-user ceremony this file has no other use for.)
 */
let probes = 0;
async function expectUnspent(inv: string) {
  const res = await join(inv, await signer.token({ sub: sub(`probe-${++probes}`) }));
  expect(res.status, await res.clone().text()).toBe(200);
}

const sub = (tag: string) => `repo:${OWNER}/joiner:ref:refs/heads/${tag}`;

let signer: GhaSigner;
beforeAll(async () => {
  await authority().createPrincipalWithCapabilities("inviter", [...ADMIN_SCOPES]);
  signer = await installGhaSigner({ owner: OWNER, repo: "joiner", audience: "notme.bot" });
});
afterAll(() => signer.restore());

describe("an OIDC proof is single-use at /join (notme-3dfe15 part 1, option A)", () => {
  it("join.oidc-jti.replay — the same proof presented twice at /join is refused the second time, and the second invite is unspent", async () => {
    const token = await signer.token({ sub: sub("replay") });
    expect((await join(await invite(), token)).status).toBe(200);

    const second = await invite();
    const res = await join(second, token);
    expect(res.status).not.toBe(200);
    expect(res.headers.get("set-cookie")).toBeNull();
    await expectUnspent(second);
  });

  it("join.oidc-jti.spent-elsewhere — a token already spent at /cert/gha cannot claim a never-linked identity at /join; a fresh token for the same identity still can", async () => {
    const s = sub("spent-at-cert-gha");
    const token = await signer.token({ sub: s });
    const cert = await certGha(token);
    expect(cert.status, await cert.clone().text()).toBe(200);

    // The squat: X never joined, the attacker holds X's spent token and a
    // live invite.
    const inv = await invite();
    const res = await join(inv, token);
    expect(res.status).toBe(401);
    expect(res.headers.get("set-cookie")).toBeNull();
    // Keyed by jti, not by identity, and the refusal spent nothing: X's own
    // fresh token joins with the SAME invite.
    const fresh = await join(inv, await signer.token({ sub: s }));
    expect(fresh.status, await fresh.clone().text()).toBe(200);
  });

  it("join.oidc-jti.spends-shared — a token that joined cannot then be spent at /cert/gha", async () => {
    const token = await signer.token({ sub: sub("joined-then-cert") });
    expect((await join(await invite(), token)).status).toBe(200);
    const cert = await certGha(token);
    expect(cert.status).toBe(401);
    expect(((await cert.json()) as { error: string }).error).toBe("token already used");
  });

  it("join.oidc-jti.independent-of-link — the DO refuses a consumed jti even if the identity's link is gone", async () => {
    // Without this the 409 already-linked guard is the ONLY thing stopping a
    // /join replay, and it holds only while the link row does.
    const s = sub("unlinked");
    const token = await signer.token({ sub: s });
    const first = await join(await invite(), token);
    expect(first.status).toBe(200);
    // And the shared keyspace is gone too (KV is eventually consistent; the
    // DO is the authority for /join).
    const { jti } = JSON.parse(atob(token.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/"))) as { jti: string };
    await (env as unknown as { CA_BUNDLE_CACHE: KVNamespace }).CA_BUNDLE_CACHE.delete(`jti:${jti}`);
    await runInDurableObject(authority(), async (_a, state) => {
      state.storage.sql.exec("DELETE FROM federated_identities WHERE provider_sub = ?", s);
    });

    const second = await invite();
    const res = await join(second, token);
    expect(res.status).toBe(401);
    expect(res.headers.get("set-cookie")).toBeNull();
    await expectUnspent(second);
  });

  it("join.oidc-jti.refusal-keeps-token — a refused join (invalid invite) does not burn the token", async () => {
    const token = await signer.token({ sub: sub("retry") });
    expect((await join("not-a-real-invite", token)).status).toBe(403);
    const ok = await join(await invite(), token);
    expect(ok.status, await ok.clone().text()).toBe(200);
  });

  it("join.oidc-jti.concurrent — two concurrent joins with one proof: exactly one succeeds, the loser's invite is unspent", async () => {
    const token = await signer.token({ sub: sub("race") });
    const [a, b] = [await invite(), await invite()];
    const results = await Promise.all([join(a, token), join(b, token)]);
    const statuses = results.map((r) => r.status);
    expect(statuses.filter((s) => s === 200)).toHaveLength(1);
    const loser = statuses[0] === 200 ? b : a;
    await expectUnspent(loser);
  });

  it("join.oidc-jti.required — a proof without a jti is refused and spends nothing", async () => {
    const inv = await invite();
    const res = await join(inv, await signer.token({ sub: sub("no-jti"), jti: undefined }));
    expect(res.status).toBe(400);
    expect(res.headers.get("set-cookie")).toBeNull();
    await expectUnspent(inv);
  });
});

describe("the consumed jti outlives the token (review F2)", () => {
  // verifyOIDC refuses only `exp < now`, so a token is still accepted in the
  // second `now == exp`. A DO row that expired AT `exp` was swept by the very
  // consume that should have found it, and the replay re-inserted and won.
  // Driven at the DO directly: two different subjects so the already-linked
  // guard cannot stand in for the jti guard.
  it("join.oidc-jti.expiry-boundary — a proof replayed at (or a little past) its exp second is still refused", async () => {
    const iss = "https://token.actions.githubusercontent.com";
    const exp = Math.floor(Date.now() / 1000);
    const proof = { jti: crypto.randomUUID(), exp, spentElsewhere: false };
    const first = await authority().joinInviteWithFederated(await invite(), iss, sub("boundary-a"), proof);
    expect(first.ok).toBe(true);
    const replay = await authority().joinInviteWithFederated(await invite(), iss, sub("boundary-b"), proof);
    expect(replay).toEqual({ ok: false, reason: "proof_reused" });
    // A verifier a few seconds of skew behind the DO would accept exp-3.
    const skewed = { jti: crypto.randomUUID(), exp: exp - 3, spentElsewhere: false };
    expect((await authority().joinInviteWithFederated(await invite(), iss, sub("boundary-c"), skewed)).ok).toBe(true);
    expect(await authority().joinInviteWithFederated(await invite(), iss, sub("boundary-d"), skewed)).toEqual({
      ok: false,
      reason: "proof_reused",
    });
  });
});
