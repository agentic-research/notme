/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * threat-model-cert-gha.do.test.ts — every `cert-gha.*` row of
 * THREAT_MODEL.md §OIDC, exercised against the REAL /cert/gha handler
 * (notme-8da0a3).
 *
 * REPLACES src/__tests__/cert-gha.test.ts, which imported nothing from the
 * worker. It declared `new Set(["agentic-research"])` and asserted the Set
 * was case-insensitive when you lowercased the input yourself; it declared
 * `{count, windowStart}` and asserted `count++` increments; it re-typed
 * getConfig's default object and asserted the copy had the defaults it had
 * just been given. Four of the seven rows the table claims — audience,
 * signature, expiry, future-iat — had NO test under any name at all.
 *
 * The tokens here are genuinely signed: a real RSA keypair, a JWKS served
 * to the worker's own fetch, an RS256 signature `validateGHAToken` verifies
 * for real. The replay row in particular cannot mean anything otherwise —
 * "presented twice" is only a fact about a token the authority accepted the
 * first time.
 */
import { env } from "cloudflare:test";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import worker, { getAllowedOwners } from "../worker";
import { type GhaSigner, ghaPopBody, installGhaSigner } from "./__tests__/helpers/gha-token";

const ORIGIN = "http://localhost:8788";
const OWNER = "agentic-research";
const REPO = "notme";
const AUDIENCE = "notme.bot";

const BASE_ENV = {
  SITE_URL: ORIGIN,
  SIGNET_AUTHORITY_URL: ORIGIN,
  GHA_ALLOWED_OWNERS: OWNER,
  GHA_CERT_AUDIENCE: AUDIENCE,
};

let signer: GhaSigner;

// ONE keypair for the file: validateGHAToken caches JWKS at module scope for
// an hour, so a second keypair would be checked against the first one's
// cached key and fail for a reason unrelated to the test.
beforeAll(async () => {
  signer = await installGhaSigner({ owner: OWNER, repo: REPO, audience: AUDIENCE });
});
afterAll(() => signer.restore());

/** POST a token to the real route. `body` lets a replay resend byte-identical. */
async function certGha(
  token: string,
  extraEnv: Record<string, unknown> = {},
  body?: unknown,
) {
  return worker.fetch(
    new Request(`${ORIGIN}/cert/gha`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify(body ?? (await ghaPopBody(token))),
    }),
    { ...env, ...BASE_ENV, ...extraEnv } as never,
  );
}

const errorOf = async (res: Response) => ((await res.json()) as { error: string }).error;

describe("cert-gha.owner.allowlist", () => {
  it("refuses a repository whose owner is not listed", async () => {
    const token = await signer.token({
      repository: "evil-corp/notme",
      repository_owner: "evil-corp",
      sub: "repo:evil-corp/notme:ref:refs/heads/main",
    });
    const res = await certGha(token);
    expect(res.status).toBe(403);
    expect(await errorOf(res)).toMatch(/owner not permitted/);
  });

  it("matches the owner case-insensitively on BOTH sides", async () => {
    // GitHub's `repository_owner` preserves the org's display casing; the
    // configured list is written by hand. Either side may differ in case and
    // the exchange must still be allowed.
    const token = await signer.token({ repository_owner: "Agentic-Research" });
    const res = await certGha(token, { GHA_ALLOWED_OWNERS: "AGENTIC-research" });
    expect(res.status, await res.clone().text()).not.toBe(403);
  });

  it("refuses EVERY owner when the variable is unset", async () => {
    // No default: an authority that has not declared whose workflows it
    // trusts trusts none. It once defaulted to the production org, so a
    // deployment that DELETED the variable silently re-supplied it
    // (notme-1532eb).
    const res = await certGha(await signer.token(), { GHA_ALLOWED_OWNERS: undefined });
    expect(res.status).toBe(403);
    expect(await errorOf(res)).toMatch(/owner not permitted/);
  });

  it("parses the list the way an operator writes it", async () => {
    // The production symbol itself, since the route only ever sees the Set.
    expect([...getAllowedOwners({ GHA_ALLOWED_OWNERS: " Foo , BAR ,, " })]).toEqual([
      "foo",
      "bar",
    ]);
    expect(getAllowedOwners({}).size).toBe(0);
    expect(getAllowedOwners({ GHA_ALLOWED_OWNERS: "" }).size).toBe(0);
  });
});

describe("cert-gha.audience.validation", () => {
  it("refuses a token minted for a different authority", async () => {
    // A token this authority did not ask for is a token some OTHER service
    // asked GitHub for — accepting it lets that service's workflows mint
    // here.
    const token = await signer.token({ aud: "someone-else.example" });
    const res = await certGha(token);
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toMatch(/wrong audience/);
  });

  it("the audience checked is the CONFIGURED one, not a constant", async () => {
    // Proves getConfig's value reaches validateGHAToken: the same token that
    // is fine by default is refused once the authority expects another
    // audience. The old test asserted a re-typed copy of the defaults object.
    const token = await signer.token();
    const res = await certGha(token, { GHA_CERT_AUDIENCE: "staging.notme.bot" });
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toMatch(/wrong audience: notme\.bot/);
  });
});

describe("cert-gha.signature.verification", () => {
  it("refuses a token whose signature was tampered with", async () => {
    const good = await signer.token();
    const [h, p, s] = good.split(".") as [string, string, string];
    // Flip a base64url character in the MIDDLE of the signature. Not the
    // last one: a 256-byte RSA signature is 343 base64url characters, and
    // the final character's low four bits are padding that decodes away —
    // changing it yields the identical byte string and a token that still
    // verifies. Which is correct, and exactly the kind of test that looks
    // like it proves forgery detection while proving nothing.
    const flipped = s[10] === "A" ? "B" : "A";
    const bad = `${h}.${p}.${s.slice(0, 10)}${flipped}${s.slice(11)}`;
    const res = await certGha(bad);
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toMatch(/invalid signature/);
  });

  it("refuses alg=none — the classic JWT forgery", async () => {
    const good = await signer.token();
    const [, p, s] = good.split(".") as [string, string, string];
    const header = btoa(JSON.stringify({ alg: "none", typ: "JWT", kid: "test-key" }))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const res = await certGha(`${header}.${p}.${s}`);
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toMatch(/unsupported alg: none/);
  });

  it("refuses a token signed by a key GitHub does not publish", async () => {
    const other = (await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true, ["sign", "verify"],
    )) as CryptoKeyPair;
    const good = await signer.token();
    const [h, p] = good.split(".") as [string, string];
    const sig = new Uint8Array(await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5", other.privateKey, new TextEncoder().encode(`${h}.${p}`),
    ));
    const b64u = btoa(String.fromCharCode(...sig))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const res = await certGha(`${h}.${p}.${b64u}`);
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toMatch(/invalid signature/);
  });
});

describe("cert-gha.token.expiry", () => {
  it("refuses an expired token", async () => {
    const now = Math.floor(Date.now() / 1000);
    const res = await certGha(await signer.token({ iat: now - 600, exp: now - 1 }));
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toMatch(/token expired/);
  });
});

describe("cert-gha.token.future", () => {
  it("refuses a token backdated into the future beyond the skew allowance", async () => {
    const now = Math.floor(Date.now() / 1000);
    const res = await certGha(await signer.token({ iat: now + 120, exp: now + 900 }));
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toMatch(/issued in the future/);
  });

  it("ACCEPTS a token inside the 60s skew allowance", async () => {
    // The bound must be a skew allowance, not a ban on any future iat —
    // otherwise a runner clock 5s fast cannot mint at all.
    const now = Math.floor(Date.now() / 1000);
    const res = await certGha(await signer.token({ iat: now + 30 }));
    expect(res.status, await res.clone().text()).toBe(200);
  });
});

describe("cert-gha.jti.replay", () => {
  it("accepts a token once and refuses the identical request the second time", async () => {
    const token = await signer.token();
    const body = await ghaPopBody(token);

    const first = await certGha(token, {}, body);
    expect(first.status, await first.clone().text()).toBe(200);

    const second = await certGha(token, {}, body);
    expect(second.status).toBe(401);
    expect(await errorOf(second)).toMatch(/already used/);
  });

  it("refuses a token carrying no jti at all", async () => {
    // Without the claim there is nothing to record, so an unbounded replay
    // would be possible; the exchange must fail closed rather than proceed.
    const res = await certGha(await signer.token({ jti: undefined }));
    expect([400, 401]).toContain(res.status);
    expect(await errorOf(res)).toMatch(/jti/);
  });
});

describe("cert-gha.rate-limit", () => {
  /** A stand-in for the CERT_LIMITER binding, which has no test constructor. */
  function limiter(allow: number) {
    const keys: string[] = [];
    return {
      keys,
      binding: {
        limit: async ({ key }: { key: string }) => {
          keys.push(key);
          return { success: keys.length <= allow };
        },
      },
    };
  }

  it("refuses with 429 once the limiter says no", async () => {
    const rl = limiter(0);
    const res = await certGha(await signer.token(), { CERT_LIMITER: rl.binding });
    expect(res.status).toBe(429);
    expect(await errorOf(res)).toMatch(/rate limit exceeded/);
  });

  it("counts PER REPOSITORY, not globally", async () => {
    // The key decides who is throttled. `cert:` alone would let one repo
    // exhaust every other repo's budget; the repository must be in it.
    const rl = limiter(1);
    await certGha(await signer.token(), { CERT_LIMITER: rl.binding });
    expect(rl.keys).toEqual([`cert:${OWNER}/${REPO}`]);

    const other = await signer.token({
      repository: `${OWNER}/other-repo`,
      sub: `repo:${OWNER}/other-repo:ref:refs/heads/main`,
    });
    await certGha(other, { CERT_LIMITER: rl.binding });
    expect(rl.keys[1]).toBe(`cert:${OWNER}/other-repo`);
  });

  it("is checked AFTER the owner allowlist, so a stranger cannot consume a repo's budget", async () => {
    const rl = limiter(10);
    const token = await signer.token({
      repository: "evil-corp/notme",
      repository_owner: "evil-corp",
      sub: "repo:evil-corp/notme:ref:refs/heads/main",
    });
    expect((await certGha(token, { CERT_LIMITER: rl.binding })).status).toBe(403);
    expect(rl.keys).toEqual([]);
  });
});
