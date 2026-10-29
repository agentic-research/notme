/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * gha-bootstrap.do.test.ts — first boot without a secret in the logs
 * (notme-addef9, Goal Zero criterion E).
 *
 * THE FINDING THIS FILE EXISTS FOR. The register/options 401 tells a fresh
 * deployer "…or bootstrap via GitHub OIDC at /cert/gha". Following that
 * advice mints a bridgeCert-only credential, creates no principal, and
 * leaves the authority with ZERO administrators — so the message that
 * replaced the log-scraping one is itself untrue. Same defect class as the
 * lie notme-addef9 was filed about, reintroduced in its own fix.
 *
 * The tokens here are REAL: an RSA keypair, a JWKS served to the worker's
 * own fetch, and an RS256 signature that `validateGHAToken` verifies for
 * real. Nothing about the OIDC path is mocked, so a route that stopped
 * verifying would fail these rather than pass them.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import worker from "../worker";
import type { SigningAuthority } from "./signing-authority";

const ORIGIN = "http://localhost:8788";
const ISSUER = "https://token.actions.githubusercontent.com";
const OWNER = "agentic-research";
const SUBJECT = `repo:${OWNER}/notme:ref:refs/heads/main`;

function b64u(bytes: Uint8Array | string): string {
  const u8 = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
  return btoa(String.fromCharCode(...u8))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

let keys: CryptoKeyPair;
let jwks: string;
let realFetch: typeof fetch;

// ONE keypair for the file: validateGHAToken caches JWKS for an hour at
// module scope, so a per-test keypair would be verified against the first
// test's cached key and fail for the wrong reason.
beforeAll(async () => {
  keys = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true, ["sign", "verify"],
  )) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", keys.publicKey)) as JsonWebKey;
  jwks = JSON.stringify({ keys: [{ ...jwk, kid: "test-key", alg: "RS256", use: "sig" }] });

  realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url.startsWith(ISSUER)) {
      return new Response(jwks, { headers: { "content-type": "application/json" } });
    }
    return realFetch(input as RequestInfo, init);
  }) as typeof fetch;
});

afterAll(() => {
  globalThis.fetch = realFetch;
});

/** A genuinely signed GHA OIDC token. */
async function ghaToken(overrides: Record<string, unknown> = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = b64u(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "test-key" }));
  const payload = b64u(JSON.stringify({
    iss: ISSUER, aud: "notme.bot", sub: SUBJECT,
    exp: now + 300, iat: now, jti: crypto.randomUUID(),
    repository: `${OWNER}/notme`, repository_owner: OWNER,
    ref: "refs/heads/main", sha: "a".repeat(40), actor: "jamestexas",
    workflow: "release", job_workflow_ref: `${OWNER}/notme/.github/workflows/release.yml@refs/heads/main`,
    run_id: "1", event_name: "push",
    ...overrides,
  }));
  const sig = new Uint8Array(await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5", keys.privateKey, new TextEncoder().encode(`${header}.${payload}`),
  ));
  return `${header}.${payload}.${b64u(sig)}`;
}

function pemOf(spki: ArrayBuffer): string {
  const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
  return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
}

/**
 * The PoP pair /cert/gha requires: binding = mtls_spki ‖ signing_spki ‖
 * SHA-256(oidc token), signed as the PRE-IMAGE by both private keys.
 */
async function popBody(token: string) {
  const mtls = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
  )) as CryptoKeyPair;
  const signing = (await crypto.subtle.generateKey(
    { name: "Ed25519" }, true, ["sign", "verify"],
  )) as CryptoKeyPair;
  const mtlsSpki = (await crypto.subtle.exportKey("spki", mtls.publicKey)) as ArrayBuffer;
  const signingSpki = (await crypto.subtle.exportKey("spki", signing.publicKey)) as ArrayBuffer;
  const oidcHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  const binding = new Uint8Array(mtlsSpki.byteLength + signingSpki.byteLength + 32);
  binding.set(new Uint8Array(mtlsSpki), 0);
  binding.set(new Uint8Array(signingSpki), mtlsSpki.byteLength);
  binding.set(new Uint8Array(oidcHash), mtlsSpki.byteLength + signingSpki.byteLength);
  const sig = (b: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(b)));
  return {
    public_keys: { mtls: pemOf(mtlsSpki), signing: pemOf(signingSpki) },
    proofs: {
      mtls: sig(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, mtls.privateKey, binding)),
      signing: sig(await crypto.subtle.sign({ name: "Ed25519" }, signing.privateKey, binding)),
    },
  };
}

async function certGha(token: string, extraEnv: Record<string, string> = {}) {
  return worker.fetch(
    new Request(`${ORIGIN}/cert/gha`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(await popBody(token)),
    }),
    {
      ...env,
      SITE_URL: ORIGIN,
      SIGNET_AUTHORITY_URL: ORIGIN,
      GHA_ALLOWED_OWNERS: OWNER,
      GHA_CERT_AUDIENCE: "notme.bot",
      ...extraEnv,
    },
  );
}

/** A fresh authority instance — no principals, no authenticators. */
function freshAuthority(name: string) {
  return env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(name));
}

describe("attested first boot (notme-addef9, criterion E — revised by notme-486e8a)", () => {
  // REVISED. This block used to assert that a matching workflow calling
  // /cert/gha BECAME the administrator. That was the dead end: a workflow
  // never holds a session, /invites accepts only one, so the authority was
  // governed by an identity no human could act as and closed to everyone
  // else. The workflow now APPROVES a human's passkey claim instead —
  // end to end in bootstrap-claim.do.test.ts. What stays here is criterion
  // E's own promise: first boot needs no secret out of a log, and /cert/gha
  // is a certificate endpoint with no administrative side effect.

  it("an unauthenticated first registration becomes a CLAIM — never an admin, never a log", async () => {
    // Runs first, on the still-fresh authority. This message is the one
    // notme-addef9 was filed about: it used to say "check Worker logs".
    const res = await worker.fetch(
      new Request(`${ORIGIN}/auth/passkey/register/options`, {
        method: "POST", headers: { "content-type": "application/json" }, body: "{}",
      }),
      { ...env, SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { claim?: boolean; scopes: string[] };
    expect(body.claim).toBe(true);
    expect(body.scopes).toEqual([]);
    expect(JSON.stringify(body)).not.toMatch(/check Worker logs|wrangler tail/i);
  });

  it("a matching workflow calling /cert/gha gets a cert and creates NO administrator", async () => {
    const res = await certGha(await ghaToken());
    expect(res.status, await res.clone().text()).toBe(200);
    const body = (await res.json()) as { scopes: string[]; principal_id?: string };
    expect(body.principal_id).toBeUndefined();
    expect(body.scopes).toEqual(["bridgeCert"]);
    expect(await freshAuthority("default").hasAdministrator()).toBe(false);
  });

  it("still rejects a token this authority cannot verify", async () => {
    const token = await ghaToken();
    const res = await certGha(token.slice(0, -6) + "AAAAAA");
    expect(res.status).not.toBe(200);
  });
});

describe("who may approve a claim — policy, on authorities of its own", () => {
  /** A claim on a fresh authority, created the way verify creates one. */
  async function claimOn(stub: ReturnType<typeof freshAuthority>, pid: string) {
    expect((await stub.markClaimRegistration(pid)).ok).toBe(true);
    const c = await stub.finalizeClaimRegistration(pid);
    expect(c).not.toBeNull();
    return c!.code;
  }

  it("REFUSES a subject the operator did not name, on a FRESH authority", async () => {
    // Owner-allowlisted is not authorised-to-administer: anyone with push
    // access to any repo under the owner clears the allowlist. The
    // authority is fresh, so the refusal can only be the subject check.
    const stub = freshAuthority("claim-wrong-subject");
    const code = await claimOn(stub, "claimant-1");
    const r = await stub.approveBootstrapClaim(code, `repo:${OWNER}/some-other-repo:ref:refs/heads/main`);
    expect(r).toEqual({ ok: false, reason: "subject_mismatch" });
    expect(await stub.hasAdministrator()).toBe(false);
  });

  it("REFUSES once an administrator exists, even for the named subject", async () => {
    const stub = freshAuthority("claim-once-only");
    const first = await claimOn(stub, "claimant-a");
    const second = await claimOn(stub, "claimant-b");
    expect(await stub.approveBootstrapClaim(first, SUBJECT)).toEqual({ ok: true, principalId: "claimant-a" });
    expect(await stub.approveBootstrapClaim(second, SUBJECT)).toEqual({ ok: false, reason: "governed" });
    expect(await stub.getPrincipalScopes("claimant-b")).toEqual([]);
  });

  it("a claim cannot be opened once an administrator exists", async () => {
    const stub = freshAuthority("claim-closed");
    await stub.createPrincipalWithCapabilities("admin", ["bridgeCert", "authorityManage", "certMint"]);
    expect(await stub.claimAvailable()).toBe(false);
    expect(await stub.markClaimRegistration("late")).toEqual({ ok: false, reason: "unavailable" });
  });

  it("finalize is a no-op for a registration that was not a claim", async () => {
    // So an ordinary invite or bootstrap-code registration is never turned
    // into a zero-scope claimant by accident.
    expect(await freshAuthority("claim-not-marked").finalizeClaimRegistration("nobody")).toBeNull();
  });
});
