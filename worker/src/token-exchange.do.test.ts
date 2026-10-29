/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * token-exchange.do.test.ts — the token endpoint does what discovery says
 * (notme-486e8a follow-on: "if it advertises it should work").
 *
 * Both discovery documents published `grant_types_supported:
 * ["github_actions_oidc", "dpop"]` against `token_endpoint: /token`. Neither is
 * an OAuth grant type, and /token implemented neither: it ignored grant_type
 * and accepted only a notme session cookie. A client following RFC 8414 would
 * send one of those grants to /token and be refused.
 *
 * /token now implements the standard one that claim was reaching for: RFC 8693
 * token exchange, with a GitHub Actions OIDC token as the subject token. That
 * is how CI obtains a notme access token — which rig, for one, now requires as
 * mint evidence. Still DPoP-bound (cnf.jkt), audience-allowlisted, and the
 * subject token's jti is single-use in the keyspace /cert/gha and /cert's oidc
 * proof share: one GitHub token, one spend, anywhere.
 */
import { env } from "cloudflare:test";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import worker from "../worker";
import { createSessionCookie } from "./auth/session";
import { type GhaSigner, installGhaSigner } from "./__tests__/helpers/gha-token";
import { AUTHORITY_GRANT_TYPES } from "./as-metadata";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN, GHA_ALLOWED_OWNERS: "agentic-research" };
const TOKEN_URL = `${ORIGIN}/token`;
const AUDIENCE = "https://rosary.bot";
const EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
const OWNER = "agentic-research";

let signer: GhaSigner;
beforeAll(async () => {
  signer = await installGhaSigner({ owner: OWNER, repo: "token-exchange", audience: "notme.bot" });
});
afterAll(() => signer.restore());

const b64url = (b: Uint8Array) =>
  btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function dpopProof(kp: CryptoKeyPair) {
  const jwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as JsonWebKey;
  const enc = (o: unknown) => b64url(new TextEncoder().encode(JSON.stringify(o)));
  const input = `${enc({ typ: "dpop+jwt", alg: "ES256", jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } })}.${enc({
    jti: crypto.randomUUID(), htm: "POST", htu: TOKEN_URL, iat: Math.floor(Date.now() / 1000),
  })}`;
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, new TextEncoder().encode(input)));
  return `${input}.${b64url(sig)}`;
}
const keys = () => crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as Promise<CryptoKeyPair>;

/** RFC 8693 is form-encoded. */
async function exchange(subjectToken: string, extra: Record<string, string> = {}) {
  const form = new URLSearchParams({
    grant_type: EXCHANGE,
    subject_token: subjectToken,
    subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
    audience: AUDIENCE,
    ...extra,
  });
  return worker.fetch(
    new Request(TOKEN_URL, {
      method: "POST",
      headers: { DPoP: await dpopProof(await keys()), "content-type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    }),
    { ...env, ...LOCAL_ENV },
  );
}

const claimsOf = (jwt: string) =>
  JSON.parse(atob(jwt.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/"))) as Record<string, any>;

describe("POST /token — RFC 8693 token exchange with a GitHub Actions OIDC token", () => {
  it("issues a DPoP-bound token for the workload the GitHub token names", async () => {
    const gha = await signer.token();
    const res = await exchange(gha);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { access_token: string; token_type: string; issued_token_type?: string };
    expect(body.token_type).toBe("DPoP");
    expect(body.issued_token_type).toBe("urn:ietf:params:oauth:token-type:access_token");
    const c = claimsOf(body.access_token);
    expect(c.sub).toBe(claimsOf(gha).sub);
    expect(c.aud).toBe(AUDIENCE);
    expect(c.scope).toBe("bridgeCert");
    expect(c.cnf?.jkt).toBeTruthy();
  });

  it("the subject token is single-use", async () => {
    const gha = await signer.token();
    expect((await exchange(gha)).status).toBe(200);
    const again = await exchange(gha);
    expect(again.status).toBe(400);
    expect(await again.json()).toMatchObject({ error: "invalid_grant" });
  });

  it("refuses a forged subject token", async () => {
    const gha = await signer.token();
    const [h, p, s] = gha.split(".");
    const mid = Math.floor(s!.length / 2);
    const forged = `${h}.${p}.${s!.slice(0, mid)}${s![mid] === "A" ? "B" : "A"}${s!.slice(mid + 1)}`;
    const res = await exchange(forged);
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "invalid_grant" });
  });

  it("refuses a repository owner this authority does not serve", async () => {
    const res = await exchange(await signer.token({ repository_owner: "someone-else" }));
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "invalid_grant" });
  });

  it("refuses an unsupported subject token type", async () => {
    const res = await exchange(await signer.token(), {
      subject_token_type: "urn:ietf:params:oauth:token-type:saml2",
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "invalid_request" });
  });

  it("refuses a grant type it does not implement, by its RFC 6749 name", async () => {
    const res = await exchange(await signer.token(), { grant_type: "client_credentials" });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "unsupported_grant_type" });
  });

  it("still requires DPoP — the exchanged token is sender-constrained", async () => {
    const res = await worker.fetch(
      new Request(TOKEN_URL, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: EXCHANGE, subject_token: await signer.token(), audience: AUDIENCE }).toString(),
      }),
      { ...env, ...LOCAL_ENV },
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "dpop_proof_required" });
  });
});

describe("POST /token — the session path reads LIVE grants", () => {
  it("a cookie claiming a scope with no grant behind it does not get that scope in the token", async () => {
    // The fifth route found reading scopes from the cookie (notme-486e8a).
    const stub = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
    const pid = `principal-token-live-${crypto.randomUUID()}`;
    await stub.createPrincipalWithCapabilities(pid, ["bridgeCert"]);
    const cookie = await createSessionCookie(
      { principalId: pid, scopes: ["bridgeCert", "authorityManage"], authMethod: "passkey" },
      await stub.getSessionSecret(),
    );
    const res = await worker.fetch(
      new Request(TOKEN_URL, {
        method: "POST",
        headers: { DPoP: await dpopProof(await keys()), cookie, "content-type": "application/json" },
        body: JSON.stringify({ audience: AUDIENCE }),
      }),
      { ...env, ...LOCAL_ENV },
    );
    expect(res.status).toBe(200);
    const c = claimsOf(((await res.json()) as { access_token: string }).access_token);
    expect(c.scope).toBe("bridgeCert");
  });
});

describe("discovery does not advertise a grant /token refuses", () => {
  it("every value in grant_types_supported is accepted by the token endpoint", async () => {
    // The constant keeps the two discovery documents consistent with EACH
    // OTHER. It was consistent and false for months. This is what keeps it
    // consistent with the code: each advertised grant is actually posted.
    for (const grant of AUTHORITY_GRANT_TYPES) {
      const res = await exchange(await signer.token(), { grant_type: grant });
      expect(res.status, `${grant} is advertised but /token answered ${res.status}`).toBe(200);
    }
  });
});
