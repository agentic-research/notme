/**
 * dpop-nonce.do.test.ts — browser-facing auth routes driven through the REAL
 * worker in REAL workerd against a REAL SigningAuthority DO.
 *
 * Named for the nonce work it started as; it now covers three flows that
 * share this harness and could not be proven by unit tests, because each
 * failure mode lives in the WIRING rather than in a module:
 *
 *   1. /token RFC 9449 §8/§9 nonce challenge — does the route actually emit
 *      the header, is the nonce it hands out accepted on the retry, is the
 *      JTI left unburned by a challenge, and does the whole thing stay off
 *      when the flag is off.
 *   2. /token CORS — ACAO and Access-Control-Expose-Headers must BOTH be
 *      present or a browser cannot complete the nonce retry (notme-0a27a6).
 *   3. /authorize authorization code + PKCE (ADR-013) — single-use,
 *      verifier-bound, redirect_uri-bound, with no oracle distinguishing
 *      failure reasons.
 *
 * Runs under vitest.workers.config.mts (`pnpm test:do`), NOT the plain suite.
 */

// The worker's own default export, invoked directly — NOT `SELF.fetch`.
//
// SELF dispatches through a service binding, so the worker receives the env
// the POOL configured, and `withEnv` cannot reach it. This file's whole
// subject is one env var, so it needs per-call control of env: calling
// `worker.fetch(request, env)` gives exactly that while still running the
// real route code, against real Durable Objects, inside real workerd.
import worker from "../worker";
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { createSessionCookie } from "./auth/session";

// localhost, not auth.notme.bot. The auth routes sit behind
// `if (sub === "auth" || isLocal)`, and `sub` comes from the `host` HEADER,
// which a synthesized Request does not carry — so an https://auth.notme.bot
// URL falls all the way through to the static-asset handler and dies on an
// undeclared ASSETS binding. Driving the worker in its `isLocal` mode is also
// the more faithful test: it is the exact configuration config.capnp gives
// the published container image.
const ORIGIN = "http://localhost:8788";
const TOKEN_URL = `${ORIGIN}/token`;
const AUDIENCE = "https://rosary.bot";

/** Env the route needs to behave as a local/container deployment. */
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };

/**
 * Mint a session cookie the real route will accept, using the real authority's
 * real session secret. No shortcut: `verifySessionCookie` inside the route
 * re-derives the HMAC from this same secret, so a cookie built any other way
 * would be rejected exactly as an attacker's would.
 */
async function realSessionCookie(): Promise<string> {
  const stub = env.SIGNING_AUTHORITY.get(
    env.SIGNING_AUTHORITY.idFromName("default"),
  );
  const secret = await stub.getSessionSecret();
  return createSessionCookie(
    {
      principalId: "principal-nonce-e2e",
      scopes: ["bridgeCert"],
      authMethod: "passkey",
    },
    secret,
  );
}

function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** A genuine ES256 DPoP proof — real P-256 key, real WebCrypto signature. */
async function makeProof(
  keyPair: CryptoKeyPair,
  extraClaims: Record<string, unknown> = {},
): Promise<string> {
  // `exportKey` is typed as ArrayBuffer | JsonWebKey across all formats; the
  // "jwk" overload is not narrowed for us, so assert the branch we asked for.
  const jwk = (await crypto.subtle.exportKey(
    "jwk",
    keyPair.publicKey,
  )) as JsonWebKey;
  const header = {
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
  };
  const payload = {
    jti: crypto.randomUUID(),
    htm: "POST",
    htu: TOKEN_URL,
    iat: Math.floor(Date.now() / 1000),
    ...extraClaims,
  };
  const enc = (o: unknown) =>
    b64url(new TextEncoder().encode(JSON.stringify(o)));
  const signingInput = `${enc(header)}.${enc(payload)}`;
  const sig = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      keyPair.privateKey,
      new TextEncoder().encode(signingInput),
    ),
  );
  return `${signingInput}.${b64url(sig)}`;
}

function newKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  ) as Promise<CryptoKeyPair>;
}

/**
 * POST /token through the real worker entry point.
 *
 * `requireNonce` is applied with `withEnv` rather than by mutating the shared
 * `env`: the flag is the entire subject of this file, and a test that leaked
 * it would make the flag-OFF case — the default posture every existing client
 * depends on — pass or fail depending on execution order.
 */
async function postToken(
  proof: string,
  cookie: string,
  opts: { requireNonce?: boolean } = {},
): Promise<Response> {
  const request = new Request(TOKEN_URL, {
    method: "POST",
    headers: { DPoP: proof, cookie, "Content-Type": "application/json" },
    body: JSON.stringify({ audience: AUDIENCE }),
  });
  return worker.fetch(request, {
    ...env,
    ...LOCAL_ENV,
    ...(opts.requireNonce ? { DPOP_REQUIRE_NONCE: "true" } : {}),
  });
}

/** Shorthand for the nonce-enforcing deployment. */
const postTokenNonced = (proof: string, cookie: string) =>
  postToken(proof, cookie, { requireNonce: true });

function decodeJwtPayload(jwt: string): Record<string, any> {
  const part = jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
  return JSON.parse(atob(part));
}

describe("/token nonce challenge — real route, real DO", () => {
  it("mints without a nonce when the flag is off", async () => {
    // The default posture. If this ever fails, enabling nothing has broken
    // every existing client — the single most important regression here.
    const res = await postToken(
      await makeProof(await newKeyPair()),
      await realSessionCookie(),
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.token_type).toBe("DPoP");
    expect(decodeJwtPayload(body.access_token).cnf.jkt).toBeTruthy();
    // No nonce machinery leaks into the off path.
    expect(res.headers.get("DPoP-Nonce")).toBeNull();
  });

  it("challenges a nonce-less proof with 400 use_dpop_nonce + a readable nonce", async () => {
    const res = await postTokenNonced(
      await makeProof(await newKeyPair()),
      await realSessionCookie(),
    );

    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("use_dpop_nonce");
    expect(res.headers.get("DPoP-Nonce")).toBeTruthy();
    // The half that makes the challenge actionable in a browser: without
    // this, JS reads null off the Headers object and loops forever.
    expect(res.headers.get("Access-Control-Expose-Headers")).toContain(
      "DPoP-Nonce",
    );
  });

  it("accepts the retry carrying the nonce it just handed out", async () => {
    const cookie = await realSessionCookie();
    const keyPair = await newKeyPair();

    const challenge = await postTokenNonced(await makeProof(keyPair), cookie);
    const nonce = challenge.headers.get("DPoP-Nonce")!;

    // Fresh proof (new jti), same key, now carrying the server's nonce —
    // exactly what a spec-compliant client does on 400 use_dpop_nonce.
    const res = await postTokenNonced(
      await makeProof(keyPair, { nonce }),
      cookie,
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(decodeJwtPayload(body.access_token).cnf.jkt).toBeTruthy();
    // §8.2 — a fresh nonce rides the success, so steady state is one
    // round-trip rather than challenge-then-mint forever.
    expect(res.headers.get("DPoP-Nonce")).toBeTruthy();
    expect(res.headers.get("Access-Control-Expose-Headers")).toContain(
      "DPoP-Nonce",
    );
  });

  it("does not burn the proof's JTI on a challenge", async () => {
    // If the challenge consumed the jti, the client's retry would have to
    // carry a NEW proof or hit proof_reused — turning every nonce refresh
    // into a silent extra failure. Replaying the identical proof (same jti)
    // with the nonce added must therefore still mint.
    const cookie = await realSessionCookie();
    const keyPair = await newKeyPair();
    const jti = crypto.randomUUID();

    const challenge = await postTokenNonced(
      await makeProof(keyPair, { jti }),
      cookie,
    );
    expect(challenge.status).toBe(400);
    const nonce = challenge.headers.get("DPoP-Nonce")!;

    const res = await postTokenNonced(
      await makeProof(keyPair, { jti, nonce }),
      cookie,
    );
    expect(res.status).toBe(200);
  });

  it("rejects a forged nonce and re-challenges", async () => {
    const res = await postTokenNonced(
      await makeProof(await newKeyPair(), {
        nonce: `${Math.floor(Date.now() / 1000)}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`,
      }),
      await realSessionCookie(),
    );

    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("use_dpop_nonce");
    expect(res.headers.get("DPoP-Nonce")).toBeTruthy();
  });

  it("still rejects a replayed proof when the nonce is valid", async () => {
    // The nonce bounds freshness; the jti bounds reuse. This asserts adding
    // the first did not weaken the second — a valid nonce must not make a
    // spent proof acceptable.
    const cookie = await realSessionCookie();
    const keyPair = await newKeyPair();

    const challenge = await postTokenNonced(await makeProof(keyPair), cookie);
    const nonce = challenge.headers.get("DPoP-Nonce")!;

    const proof = await makeProof(keyPair, { nonce });
    expect((await postTokenNonced(proof, cookie)).status).toBe(200);

    const replay = await postTokenNonced(proof, cookie);
    expect(replay.status).toBe(401);
    expect(((await replay.json()) as any).error).toBe("proof_reused");
  });
});

describe("/authorize redirect token — real route, real DO (notme-07204f)", () => {
  it("is an UNBOUND bearer, and the threat model must not claim otherwise", async () => {
    // THREAT_MODEL.md's `token in URL logs` row asserted this token was
    // "DPoP-bound (useless without ephemeral key)". It never was:
    // mintRedirectToken omits cnf.jkt on purpose, because the /authorize
    // flow's DPoP keypair is lost across the navigation.
    //
    // This test exists so the doc and the code cannot silently disagree
    // again. It pins the ABSENCE of cnf — if someone later makes the token
    // sender-constrained, this fails, and the corrected threat-model row has
    // to be revisited in the same change.
    const cookie = await realSessionCookie();
    const res = await worker.fetch(
      new Request(`${ORIGIN}/authorize/token`, {
        method: "POST",
        headers: { cookie, "Content-Type": "application/json" },
        body: JSON.stringify({ audience: AUDIENCE }),
      }),
      { ...env, ...LOCAL_ENV },
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.token_type).toBe("Bearer");

    const claims = decodeJwtPayload(body.access_token);
    expect(claims.cnf).toBeUndefined();
    // The mitigations that DO survive, per the corrected row.
    expect(claims.aud).toBe(AUDIENCE);
    expect(claims.jti).toBeTruthy();
    expect(claims.exp - claims.iat).toBeLessThanOrEqual(300);
  });

  it("serves the authorize page with Referrer-Policy: no-referrer", async () => {
    // Narrow claim, deliberately: this protects the AUTHORIZE URL (which
    // carries `state`) from being sent onward as a Referer. It does NOT
    // protect the access token — once the browser is on
    // `${redirect_uri}?token=...`, onward Referers are governed by the
    // destination's own Referrer-Policy, not ours. See THREAT_MODEL.md
    // `token in URL logs`.
    // Session cookie required — without one the route 302s to /login, and
    // the header would go untested while the assertion still "passed" on a
    // redirect that never carries the token.
    const res = await worker.fetch(
      new Request(
        `${ORIGIN}/authorize?redirect_uri=${encodeURIComponent("https://rosary.bot/cb")}&audience=${encodeURIComponent(AUDIENCE)}&state=abc`,
        { headers: { cookie: await realSessionCookie() } },
      ),
      { ...env, ...LOCAL_ENV },
    );

    expect(res.status).toBe(200);
    expect(res.headers.get("Referrer-Policy")).toBe("no-referrer");
  });
});

describe("/token CORS — real route (notme-0a27a6)", () => {
  const CROSS_ORIGIN = "https://rosary.bot";

  it("mirrors the preflight's origin decision onto the actual response", async () => {
    // The bug this pins: the OPTIONS preflight answered 204 with ACAO and
    // permitted the DPoP request header, while the actual POST answered with
    // no ACAO at all. A browser passed preflight and then had the response
    // blocked with nothing readable to explain why.
    const preflight = await worker.fetch(
      new Request(TOKEN_URL, {
        method: "OPTIONS",
        headers: {
          Origin: CROSS_ORIGIN,
          "Access-Control-Request-Method": "POST",
        },
      }),
      { ...env, ...LOCAL_ENV },
    );
    expect(preflight.headers.get("Access-Control-Allow-Origin")).toBe(
      CROSS_ORIGIN,
    );

    const actual = await worker.fetch(
      new Request(TOKEN_URL, {
        method: "POST",
        headers: { Origin: CROSS_ORIGIN, "Content-Type": "application/json" },
        body: JSON.stringify({ audience: AUDIENCE }),
      }),
      { ...env, ...LOCAL_ENV },
    );

    expect(actual.headers.get("Access-Control-Allow-Origin")).toBe(
      CROSS_ORIGIN,
    );
    // Depends on the request's Origin, so it must not be cached origin-blind.
    expect(actual.headers.get("Vary")).toContain("Origin");
  });

  it("does not grant credentials, so a cross-origin caller still gets 401", async () => {
    // THREAT_MODEL §7 omits Allow-Credentials deliberately. Exposing the
    // response must not quietly turn into exposing an authenticated one:
    // without a cookie the answer is 401, and that is the answer that
    // becomes readable — not a token.
    const res = await worker.fetch(
      new Request(TOKEN_URL, {
        method: "POST",
        headers: {
          Origin: CROSS_ORIGIN,
          DPoP: await makeProof(await newKeyPair()),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ audience: AUDIENCE }),
      }),
      { ...env, ...LOCAL_ENV },
    );

    expect(res.headers.get("Access-Control-Allow-Credentials")).toBeNull();
    expect(res.status).toBe(401);
    expect(((await res.json()) as any).error).toBe("session_required");
  });

  it("does not emit ACAO for an origin outside the allowlist", async () => {
    const res = await worker.fetch(
      new Request(TOKEN_URL, {
        method: "POST",
        headers: {
          Origin: "https://evil.example",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ audience: AUDIENCE }),
      }),
      { ...env, ...LOCAL_ENV },
    );

    expect(res.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });
});

describe("nonce challenge is actionable from a cross-origin browser", () => {
  it("carries ACAO and Expose-Headers together, so JS can read the nonce", async () => {
    // The composite property the two fixes exist for, and which neither
    // covers alone. A browser needs BOTH: Access-Control-Allow-Origin to be
    // allowed to see the response at all (notme-0a27a6), and
    // Access-Control-Expose-Headers to be allowed to read DPoP-Nonce off it
    // (notme-e1700d). With either missing the client cannot complete the
    // RFC 9449 §8 retry and loops on challenges forever — and browsers are
    // the entire residual scope of this endpoint (ADR-006).
    const res = await worker.fetch(
      new Request(TOKEN_URL, {
        method: "POST",
        headers: {
          Origin: "https://rosary.bot",
          DPoP: await makeProof(await newKeyPair()),
          cookie: await realSessionCookie(),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ audience: AUDIENCE }),
      }),
      { ...env, ...LOCAL_ENV, DPOP_REQUIRE_NONCE: "true" },
    );

    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("use_dpop_nonce");
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe(
      "https://rosary.bot",
    );
    expect(res.headers.get("Access-Control-Expose-Headers")).toContain(
      "DPoP-Nonce",
    );
    expect(res.headers.get("DPoP-Nonce")).toBeTruthy();
  });
});

// ── ADR-013: authorization code + PKCE ────────────────────────────────────

/** RFC 7636 §4.1 verifier: 43-128 chars from the unreserved set. */
function newVerifier(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return b64url(bytes); // 43 chars, unreserved alphabet
}

async function challengeFor(verifier: string): Promise<string> {
  const { sha256Base64url } = await import("./auth/pkce");
  return sha256Base64url(verifier);
}

async function mintCode(
  cookie: string,
  challenge: string,
  redirectUri = "https://rosary.bot/cb",
): Promise<Response> {
  return worker.fetch(
    new Request(`${ORIGIN}/authorize/code`, {
      method: "POST",
      headers: { cookie, "Content-Type": "application/json" },
      body: JSON.stringify({
        audience: AUDIENCE,
        redirect_uri: redirectUri,
        code_challenge: challenge,
      }),
    }),
    { ...env, ...LOCAL_ENV },
  );
}

async function redeem(body: Record<string, unknown>): Promise<Response> {
  return worker.fetch(
    new Request(`${ORIGIN}/authorize/redeem`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
    { ...env, ...LOCAL_ENV },
  );
}

describe("authorization code + PKCE (ADR-013, notme-2bba44)", () => {
  it("completes the full flow: code in the URL, token server-to-server", async () => {
    const cookie = await realSessionCookie();
    const verifier = newVerifier();

    const minted = await mintCode(cookie, await challengeFor(verifier));
    expect(minted.status).toBe(200);
    const { code, expires_in } = (await minted.json()) as any;
    expect(code).toBeTruthy();
    // Short by design — the redeemer already holds the verifier, so the
    // window that needs covering is one round-trip, not RFC 6749's 600s max.
    expect(expires_in).toBeLessThanOrEqual(60);

    const res = await redeem({
      code,
      code_verifier: verifier,
      redirect_uri: "https://rosary.bot/cb",
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.token_type).toBe("Bearer");
    const claims = decodeJwtPayload(body.access_token);
    expect(claims.aud).toBe(AUDIENCE);
    expect(claims.sub).toBe("principal-nonce-e2e");
  });

  it("is single-use — a replayed code is dead", async () => {
    // The property that makes a logged code worthless. If this regresses,
    // the whole rationale for the flow goes with it.
    const cookie = await realSessionCookie();
    const verifier = newVerifier();
    const { code } = (await (
      await mintCode(cookie, await challengeFor(verifier))
    ).json()) as any;
    const args = {
      code,
      code_verifier: verifier,
      redirect_uri: "https://rosary.bot/cb",
    };

    expect((await redeem(args)).status).toBe(200);
    const replay = await redeem(args);
    expect(replay.status).toBe(400);
    expect(((await replay.json()) as any).error).toBe("invalid_grant");
  });

  it("rejects the wrong verifier — a stolen code alone is useless", async () => {
    // This is the load-bearing claim of ADR-013: an attacker who reads the
    // code out of an access log still cannot redeem it, because the verifier
    // never left the client that started the flow.
    const cookie = await realSessionCookie();
    const verifier = newVerifier();
    const { code } = (await (
      await mintCode(cookie, await challengeFor(verifier))
    ).json()) as any;

    const res = await redeem({
      code,
      code_verifier: newVerifier(), // attacker's own, correctly formed
      redirect_uri: "https://rosary.bot/cb",
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
  });

  it("burns the code even when the verifier is wrong", async () => {
    // A code whose verifier fails has been seen by someone who should not
    // have it. Consuming it is the correct response, not a bug — so the
    // legitimate holder cannot then redeem it either.
    const cookie = await realSessionCookie();
    const verifier = newVerifier();
    const { code } = (await (
      await mintCode(cookie, await challengeFor(verifier))
    ).json()) as any;

    await redeem({
      code,
      code_verifier: newVerifier(),
      redirect_uri: "https://rosary.bot/cb",
    });
    const legitimate = await redeem({
      code,
      code_verifier: verifier,
      redirect_uri: "https://rosary.bot/cb",
    });
    expect(legitimate.status).toBe(400);
  });

  it("rejects a redirect_uri that differs from the one bound (RFC 6749 §4.1.3)", async () => {
    const cookie = await realSessionCookie();
    const verifier = newVerifier();
    const { code } = (await (
      await mintCode(
        cookie,
        await challengeFor(verifier),
        "https://rosary.bot/cb",
      )
    ).json()) as any;

    const res = await redeem({
      code,
      code_verifier: verifier,
      redirect_uri: "https://rosary.bot/other",
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
  });

  it("rejects an unknown code with the same answer as a spent one", async () => {
    // No oracle: unknown / spent / expired / wrong-uri / bad-verifier must be
    // indistinguishable, or probing with harvested codes tells the attacker
    // which were real.
    const res = await redeem({
      code: newVerifier(),
      code_verifier: newVerifier(),
      redirect_uri: "https://rosary.bot/cb",
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
  });

  it("rejects a too-short code_verifier rather than failing open", async () => {
    const cookie = await realSessionCookie();
    const verifier = newVerifier();
    const { code } = (await (
      await mintCode(cookie, await challengeFor(verifier))
    ).json()) as any;

    const res = await redeem({
      code,
      code_verifier: "short",
      redirect_uri: "https://rosary.bot/cb",
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_request");
  });

  it("requires a session to mint a code", async () => {
    const res = await worker.fetch(
      new Request(`${ORIGIN}/authorize/code`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          audience: AUDIENCE,
          redirect_uri: "https://rosary.bot/cb",
          code_challenge: await challengeFor(newVerifier()),
        }),
      }),
      { ...env, ...LOCAL_ENV },
    );
    expect(res.status).toBe(401);
  });

  it("re-validates redirect_uri at the code endpoint, not just at /authorize", async () => {
    // /authorize/code is directly reachable, so the allowlist has to hold at
    // the point the code is BOUND to a destination — otherwise the check on
    // /authorize is decorative and a caller binds a code to anywhere.
    const res = await mintCode(
      await realSessionCookie(),
      await challengeFor(newVerifier()),
      "https://evil.example/cb",
    );
    expect(res.status).toBe(403);
  });

  it("refuses plain PKCE at /authorize — it would put the verifier in the URL", async () => {
    const res = await worker.fetch(
      new Request(
        `${ORIGIN}/authorize?redirect_uri=${encodeURIComponent("https://rosary.bot/cb")}&code_challenge=${await challengeFor(newVerifier())}&code_challenge_method=plain`,
        { headers: { cookie: await realSessionCookie() } },
      ),
      { ...env, ...LOCAL_ENV },
    );
    expect(res.status).toBe(400);
  });

  it("still serves the legacy token path when no challenge is sent", async () => {
    // The migration contract. rig has not shipped yet; breaking this breaks
    // /admin/setup-github, which is the flow used to RECOVER admin access.
    const res = await worker.fetch(
      new Request(
        `${ORIGIN}/authorize?redirect_uri=${encodeURIComponent("https://rosary.bot/cb")}&state=s`,
        { headers: { cookie: await realSessionCookie() } },
      ),
      { ...env, ...LOCAL_ENV },
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toContain('data-code-challenge=""');
  });
});
