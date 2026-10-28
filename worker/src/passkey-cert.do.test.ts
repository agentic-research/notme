/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * passkey-cert.do.test.ts — POST /cert/passkey against the real route and a
 * real SigningAuthority.
 *
 * The scope-filter tests are the ones that matter. This route differs from
 * /cert/gha in exactly one respect — the authenticator carries privilege — and
 * that difference is the whole reason it needs its own reasoning rather than
 * being a copy.
 */

import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../worker";
import { createSessionCookie } from "./auth/session";
import { getPrincipal, grantCapability } from "./auth/principals";
import type { SigningAuthority } from "./signing-authority";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };

// The WIMSE trust domain is DERIVED from SITE_URL, not a literal — a
// staging or local authority must not mint identities that name production
// (notme-1532eb). These tests drive the worker in its local configuration,
// so the expected domain is this origin's host, and asserting the literal
// "notme.bot" here would pin exactly the confusion the derivation removes.
const TRUST_DOMAIN = new URL(ORIGIN).host;

function b64u(b: Uint8Array): string {
  return btoa(String.fromCharCode(...b))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function pem(spki: ArrayBuffer, label: string): string {
  const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
  return `-----BEGIN ${label}-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END ${label}-----`;
}

async function sessionCookie(
  scopes: string[],
  authMethod = "passkey",
  principalId = "principal-passkey-test",
): Promise<string> {
  const stub = env.SIGNING_AUTHORITY.get(
    env.SIGNING_AUTHORITY.idFromName("default"),
  );
  // The cookie is a cache of the grant, never the source: the route reads
  // LIVE grants (notme-486e8a), so each cookie is backed by a real one. Grants
  // only accumulate on a principal, and the route intersects them with the
  // cookie, so a test's cookie still bounds what it can claim.
  // createPrincipalWithCapabilities refuses an existing principal, and there
  // is (deliberately) no grant RPC, so grant through the DO's own storage
  // module — idempotent, and off the pinned surface.
  await runInDurableObject(stub, (a) => {
    const sql = (a as SigningAuthority)["ctx"].storage.sql;
    if (!getPrincipal(sql, principalId)) return (a as SigningAuthority).createPrincipalWithCapabilities(principalId, scopes);
    for (const scope of scopes) grantCapability(sql, principalId, scope, "test");
  });
  const secret = await stub.getSessionSecret();
  return createSessionCookie({ principalId, scopes, authMethod }, secret);
}

/**
 * A session-bound nonce, fetched the way a BROWSER can (notme-486e8a).
 *
 * The binding used to be SHA-256 of the session cookie. This helper's
 * predecessor, sessionValue(), sliced the raw cookie out of the header to hash
 * it — something only a test can do: notme_session is HttpOnly, so no browser
 * script can read it, and the route was uncallable by any real client. The
 * nonce is fetched with the cookie (sent automatically, same-origin) and is
 * bound to that session's principal server-side.
 */
async function fetchNonce(cookie: string): Promise<string> {
  const res = await worker.fetch(
    new Request(`${ORIGIN}/cert/nonce`, { method: "POST", headers: { cookie } }),
    { ...env, ...LOCAL_ENV },
  );
  expect(res.status).toBe(200);
  return ((await res.json()) as { nonce: string }).nonce;
}

/** Generate keys and the PoP proofs the route requires. */
async function mintRequest(cookie: string, nonce?: string) {
  nonce ??= await fetchNonce(cookie);
  const mtls = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const signing = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;

  const mtlsSpki = (await crypto.subtle.exportKey(
    "spki",
    mtls.publicKey,
  )) as ArrayBuffer;
  const signingSpki = (await crypto.subtle.exportKey(
    "spki",
    signing.publicKey,
  )) as ArrayBuffer;
  // Written out by hand rather than imported, so this test checks the
  // route's binding against an independent implementation of it.
  const tag = new TextEncoder().encode("notme/cert-pair/v1\0");
  const nonceHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(nonce)),
  );
  const input = new Uint8Array(
    tag.length + mtlsSpki.byteLength + signingSpki.byteLength + 32,
  );
  input.set(tag, 0);
  input.set(new Uint8Array(mtlsSpki), tag.length);
  input.set(new Uint8Array(signingSpki), tag.length + mtlsSpki.byteLength);
  input.set(nonceHash, tag.length + mtlsSpki.byteLength + signingSpki.byteLength);
  // Sign the PRE-IMAGE, not its digest (notme-a011d2). WebCrypto ECDSA
  // applies SHA-256 itself, so signing a digest here would produce a proof
  // over two hashes that only another WebCrypto caller could reproduce.
  return {
    nonce,
    public_keys: {
      mtls: pem(mtlsSpki, "PUBLIC KEY"),
      signing: pem(signingSpki, "PUBLIC KEY"),
    },
    proofs: {
      mtls: b64u(
        new Uint8Array(
          await crypto.subtle.sign(
            { name: "ECDSA", hash: "SHA-256" },
            mtls.privateKey,
            input,
          ),
        ),
      ),
      signing: b64u(
        new Uint8Array(
          await crypto.subtle.sign(
            { name: "Ed25519" },
            signing.privateKey,
            input,
          ),
        ),
      ),
    },
  };
}

function post(body: unknown, cookie: string) {
  return worker.fetch(
    new Request(`${ORIGIN}/cert/passkey`, {
      method: "POST",
      headers: { cookie, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
    { ...env, ...LOCAL_ENV },
  );
}

describe("POST /cert/passkey", () => {
  it("mints a cert pair from a passkey session", async () => {
    const cookie = await sessionCookie(["bridgeCert"]);
    const res = await post(await mintRequest(cookie), cookie);
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;

    // Reconstructing this response by hand once shipped `certificates.mtls:
    // undefined` with a 200, because tsc cannot see through the DO stub.
    expect(body.certificates.mtls).toContain("BEGIN CERTIFICATE");
    expect(body.certificates.signing).toContain("BEGIN CERTIFICATE");
    expect(body.identity).toBe(
      `wimse://${TRUST_DOMAIN}/principal/principal-passkey-test`,
    );
    expect(body.auth_method).toBe("passkey");
    expect(body.expires_at).toBeGreaterThan(0);
  });

  it("does NOT widen a deployer session into a minting credential", async () => {
    // THE POINT OF THIS ROUTE'S EXISTENCE AS SEPARATE CODE.
    //
    // A deployer's passkey session carries certMint and authorityManage. If
    // the cert inherited them, a browser session would become a credential
    // that can mint further certs — long-lived, exportable, usable off-origin,
    // with none of the properties (HttpOnly, SameSite=Strict, revocable by
    // clearing a cookie) that made granting the session acceptable.
    const cookie = await sessionCookie([
      "bridgeCert",
      "certMint",
      "authorityManage",
    ]);
    const res = await post(await mintRequest(cookie), cookie);
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;

    expect(body.scopes).toEqual(["bridgeCert"]);
    expect(body.scopes).not.toContain("certMint");
    expect(body.scopes).not.toContain("authorityManage");
  });

  it("refuses a session holding nothing a cert may carry", async () => {
    // Rather than minting an authority-less cert, which looks like success
    // and fails confusingly at first use.
    const cookie = await sessionCookie(["authorityManage"]);
    const res = await post(await mintRequest(cookie), cookie);
    expect(res.status).toBe(403);
  });

  it("requires a session", async () => {
    const cookie = await sessionCookie(["bridgeCert"]);
    const req = await mintRequest(cookie);
    const res = await worker.fetch(
      new Request(`${ORIGIN}/cert/passkey`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req),
      }),
      { ...env, ...LOCAL_ENV },
    );
    expect(res.status).toBe(401);
  });

  it("rejects proofs bound to a DIFFERENT session", async () => {
    // The point of the session term: a captured public-keys+proofs pair must
    // not be replayable under someone else's session, binding the victim's
    // key to the attacker's identity.
    //
    // This test used to mint victim and attacker cookies for the SAME
    // principal within the same second — identical cookies — and then
    // `if (victim === attacker) return;`. It returned before asserting
    // anything, on every run. Different principals now, and no escape hatch.
    const victim = await sessionCookie(["bridgeCert"], "passkey", "principal-victim");
    const attacker = await sessionCookie(["bridgeCert"], "passkey", "principal-attacker");
    expect(victim).not.toBe(attacker);
    const capturedFromVictim = await mintRequest(victim);
    const res = await post(capturedFromVictim, attacker);
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: "invalid_nonce" });
  });

  it("requires a nonce", async () => {
    const cookie = await sessionCookie(["bridgeCert"]);
    const { nonce: _n, ...withoutNonce } = await mintRequest(cookie);
    expect((await post(withoutNonce, cookie)).status).toBe(400);
  });

  it("a nonce is single-use", async () => {
    const cookie = await sessionCookie(["bridgeCert"]);
    const nonce = await fetchNonce(cookie);
    expect((await post(await mintRequest(cookie, nonce), cookie)).status).toBe(200);
    const again = await post(await mintRequest(cookie, nonce), cookie);
    expect(again.status).toBe(401);
    expect(await again.json()).toMatchObject({ error: "invalid_nonce" });
  });

  it("a forged proof does not burn the nonce", async () => {
    // Otherwise anyone who saw a nonce in flight could deny the real holder.
    const cookie = await sessionCookie(["bridgeCert"]);
    const nonce = await fetchNonce(cookie);
    const bad = await mintRequest(cookie, nonce);
    bad.proofs.mtls = b64u(new Uint8Array(64).fill(0x01));
    expect((await post(bad, cookie)).status).toBe(401);
    expect((await post(await mintRequest(cookie, nonce), cookie)).status).toBe(200);
  });

  it("issuing a nonce requires a session", async () => {
    const res = await worker.fetch(
      new Request(`${ORIGIN}/cert/nonce`, { method: "POST" }),
      { ...env, ...LOCAL_ENV },
    );
    expect(res.status).toBe(401);
  });

  it("rejects a forged proof", async () => {
    const cookie = await sessionCookie(["bridgeCert"]);
    const req = await mintRequest(cookie);
    req.proofs.mtls = b64u(new Uint8Array(64).fill(0x01));
    expect((await post(req, cookie)).status).toBe(401);
  });

  it("requires public keys and proofs", async () => {
    const cookie = await sessionCookie(["bridgeCert"]);
    expect((await post({}, cookie)).status).toBe(400);
    const req = await mintRequest(cookie);
    expect((await post({ public_keys: req.public_keys }, cookie)).status).toBe(
      400,
    );
  });
});

describe("authMethod provenance (notme-ebc9af)", () => {
  // The route accepts ANY valid session — /join sets authMethod "invite",
  // /auth/oidc/login sets "oidc:<issuer>" — but used to stamp every minted
  // cert authMethod:"passkey". A verifier reading such a cert concluded a
  // human touched a passkey when none did. The cert must DERIVE its
  // provenance from the session that authorized it.
  //
  // That property is unchanged; where it is READ moved (notme-77438b,
  // ADR-019 D2). This test asserted provenance via the identity URI, which
  // is what made one principal have several identities — a true-but-unstable
  // identifier traded for a false-but-stable one. Provenance now lives in
  // the auth_method claim, and the identity is stable, so both halves hold
  // at once. identity-stability.do.test.ts pins the pairing directly.

  it("an invite-authed session mints a cert that says invite, not passkey", async () => {
    const cookie = await sessionCookie(["bridgeCert"], "invite");
    const res = await post(await mintRequest(cookie), cookie);
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.auth_method).toBe("invite");
    expect(body.auth_method).not.toBe("passkey");
    // Stable regardless of the door: the ceremony is no longer in the name.
    expect(body.identity).toBe(
      `wimse://${TRUST_DOMAIN}/principal/principal-passkey-test`,
    );
  });

  it("refuses a session with no authMethod rather than stamping a placeholder", async () => {
    // verifySessionCookie JSON.parses the payload with no shape validation,
    // so a future issuer that forgets authMethod would reach the mint with
    // undefined. Defaulting to "passkey" would re-create the exact lie
    // notme-ebc9af fixed; stamping String(undefined) puts the literal
    // "undefined" in a certificate. Fail closed instead.
    const stub = env.SIGNING_AUTHORITY.get(
      env.SIGNING_AUTHORITY.idFromName("default"),
    );
    const secret = await stub.getSessionSecret();
    const cookie = await createSessionCookie(
      { principalId: "principal-passkey-test", scopes: ["bridgeCert"] } as any,
      secret,
    );
    const res = await post(await mintRequest(cookie), cookie);
    expect(res.status).toBeGreaterThanOrEqual(400);
    const body = (await res.json()) as any;
    expect(JSON.stringify(body)).not.toContain("undefined");
  });

  it("an oidc session's cert carries the issuer-qualified method, URI-encoded", async () => {
    const method = "oidc:https://accounts.example";
    const cookie = await sessionCookie(["bridgeCert"], method);
    const res = await post(await mintRequest(cookie), cookie);
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.auth_method).toBe(method);
    // The issuer-qualified method no longer appears in the URI at all, which
    // is the fix: it was the segment whose ':' and '/' had to be encoded to
    // avoid inventing path segments, and the reason the subject's position
    // in the path differed by route. The identity is now the principal, and
    // the ONLY encoded segment is the principal id itself.
    expect(body.identity).toBe(
      `wimse://${TRUST_DOMAIN}/principal/principal-passkey-test`,
    );
    expect(body.identity).not.toContain(encodeURIComponent(method));
  });
});
