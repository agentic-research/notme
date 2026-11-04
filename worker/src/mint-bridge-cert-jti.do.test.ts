/// <reference types="@cloudflare/vitest-plugin/types" />
/**
 * mint-bridge-cert-jti.do.test.ts — a GitHub Actions token buys ONE thing,
 * through the service binding as well as the routes (notme-f850f2).
 *
 * `AuthService.mintBridgeCert({kind:"gha-oidc"})` re-verified the token
 * inside the DO and minted — but never spent its jti. A token already used at
 * /cert/gha, /join or /auth/oidc/login, or used once through the binding
 * itself, kept buying bridge certs through any Worker holding the AUTH
 * binding for as long as it was unexpired.
 *
 * Now the DO spends it in BOTH keyspaces the routes use: the shared KV
 * `jti:<jti>` (/cert/gha, /cert, /token, /join), checked before and written
 * after; and the DO's own `oidc:<iss>#<jti>` (the /join and /auth/oidc/login
 * key), whose PRIMARY KEY is what makes two binding calls race-free.
 *
 * AuthService.mintBridgeCert is a pass-through to this DO method, so the DO
 * is called directly — on the "default" authority the routes use.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import worker from "../worker";
import { type GhaSigner, ghaPopBody, installGhaSigner, spkiPem } from "./__tests__/helpers/gha-token";
import { ADMIN_SCOPES } from "./auth/admin-scopes";

const ORIGIN = "http://localhost:8788";
const OWNER = "agentic-research";
const GHA_ISSUER = "https://token.actions.githubusercontent.com";
const LOCAL_ENV = {
  SITE_URL: ORIGIN,
  SIGNET_AUTHORITY_URL: ORIGIN,
  GHA_ALLOWED_OWNERS: OWNER,
  GHA_CERT_AUDIENCE: "notme.bot",
};

let gha: GhaSigner;
let pem: string;
beforeAll(async () => {
  gha = await installGhaSigner({ owner: OWNER, repo: "notme", audience: "notme.bot" });
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  pem = await spkiPem(kp.publicKey);
});
afterAll(() => gha.restore());

const authority = () => env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
const viaBinding = (token: string) => authority().mintBridgeCert({ kind: "gha-oidc", token }, pem);
const jtiOf = (token: string) =>
  (JSON.parse(atob(token.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/"))) as { jti: string; exp: number });

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

describe("mintBridgeCert({kind:'gha-oidc'}) spends the token's jti (notme-f850f2)", () => {
  it("mint.gha.jti.binding-twice — the same token through the binding mints once", async () => {
    const token = await gha.token();
    const first = await viaBinding(token);
    expect(first.ok).toBe(true);
    const second = await viaBinding(token);
    expect(second).toEqual({ ok: false, reason: "gha_token_reused" });
  });

  it("mint.gha.jti.after-cert-gha — a token spent at /cert/gha does not mint via the binding", async () => {
    const token = await gha.token();
    const res = await certGha(token);
    expect(res.status, await res.clone().text()).toBe(200);
    expect(await viaBinding(token)).toEqual({ ok: false, reason: "gha_token_reused" });
  });

  it("mint.gha.jti.before-cert-gha — a token spent via the binding is refused at /cert/gha", async () => {
    const token = await gha.token();
    expect((await viaBinding(token)).ok).toBe(true);
    const res = await certGha(token);
    expect(res.status).toBe(401);
    expect(await res.text()).toMatch(/token already used/);
  });

  it("mint.gha.jti.shared-oidc-key — a token spent at /join (the DO's oidc:<iss>#<jti>) does not mint via the binding", async () => {
    // The /join leg writes KV only AFTER its DO call commits, and KV is
    // eventually consistent: the DO key is the guard that does not depend on
    // it. Drive the DO half of /join directly, so only that key is spent.
    await authority().createPrincipalWithCapabilities("jti-inviter", [...ADMIN_SCOPES]);
    const inv = await authority().createInviteToken("jti-inviter", ["bridgeCert"], 3600);
    const token = await gha.token();
    const { jti, exp } = jtiOf(token);
    const joined = await authority().joinInviteWithFederated(
      inv.token,
      GHA_ISSUER,
      `repo:${OWNER}/notme:ref:refs/heads/main`,
      { jti, exp, spentElsewhere: false },
    );
    expect(joined.ok).toBe(true);
    expect(await viaBinding(token)).toEqual({ ok: false, reason: "gha_token_reused" });
  });

  it("mint.gha.owner.allowlist — a token from an owner not in GHA_ALLOWED_OWNERS is refused via the binding, and its jti is not spent", async () => {
    // Pre-existing gap (security review F7): /cert/gha and /token refuse an
    // owner outside the allowlist; the binding minted for any GitHub repo
    // whose token said aud=notme.bot.
    const token = await gha.token({
      repository: "someone-else/notme",
      repository_owner: "someone-else",
      sub: "repo:someone-else/notme:ref:refs/heads/main",
    });
    expect(await viaBinding(token)).toEqual({ ok: false, reason: "invalid_gha_token" });
    // Refused BEFORE the consume: a refusal burns nothing.
    expect(await env.CA_BUNDLE_CACHE.get(`jti:${jtiOf(token).jti}`)).toBeNull();
    // And the allowlist check is case-insensitive, as the routes' is.
    const upper = await gha.token({ repository_owner: OWNER.toUpperCase() });
    expect((await viaBinding(upper)).ok).toBe(true);
  });

  it("mint.gha.ttl.clamped — a caller-chosen ttlMs cannot exceed the /cert/gha bound (GHA_CERT_TTL_MS, 5 min)", async () => {
    const r = await authority().mintBridgeCert({ kind: "gha-oidc", token: await gha.token() }, pem, 24 * 3600_000);
    expect(r.ok).toBe(true);
    if (!r.ok) throw new Error("unreachable");
    // expires_at is unix seconds.
    expect(r.expires_at - Math.floor(Date.now() / 1000)).toBeLessThanOrEqual(5 * 60 + 5);
  });

  it("mint.gha.jti.kv-write-fails — a failing KV write after the consume still returns the mint, not a thrown RPC error", async () => {
    // Security review F5. The DO key is the authoritative spend; KV only
    // shortens the window for the KV-only routes, so its failure must not
    // turn a spent token into an exception.
    // Typed loosely: the stub's inferred type is too deep for tsc here.
    const stub: any = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("kv-put-fails"));
    const token = await gha.token();
    const [first, second] = (await (runInDurableObject as any)(stub, async (inst: any) => {
      const kv = inst.env.CA_BUNDLE_CACHE;
      inst.env.CA_BUNDLE_CACHE = {
        get: (k: string) => kv.get(k),
        put: async () => {
          throw new Error("KV PUT failed: 429 Too Many Requests");
        },
      };
      vi.spyOn(console, "error").mockImplementation(() => {});
      try {
        const a = await inst.mintBridgeCert({ kind: "gha-oidc", token }, pem);
        const b = await inst.mintBridgeCert({ kind: "gha-oidc", token }, pem);
        return [a, b];
      } finally {
        inst.env.CA_BUNDLE_CACHE = kv;
        vi.restoreAllMocks();
      }
    })) as Array<{ ok: boolean; reason?: string }>;
    expect(first.ok).toBe(true);
    // And the DO key still made it single-use.
    expect(second).toEqual({ ok: false, reason: "gha_token_reused" });
  });

  it("mint.gha.jti.required — a token with no jti is refused, as /cert/gha refuses it", async () => {
    const token = await gha.token({ jti: undefined });
    expect(await viaBinding(token)).toEqual({ ok: false, reason: "invalid_gha_token" });
  });
});
