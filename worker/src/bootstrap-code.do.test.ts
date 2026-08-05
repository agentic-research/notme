/**
 * bootstrap-code.do.test.ts — the bootstrap-code lifecycle against the REAL
 * SigningAuthority DO in real workerd (notme-e9f809).
 *
 * Why this file exists: four tests appeared to cover this invariant and none
 * called the DO — adversarial.test.ts simulates consumeBootstrapCode locally
 * (its own words), and passkey.test.ts asserted an 8-hex-char code the DO has
 * never generated. The invariants below are the ones a first boot actually
 * depends on:
 *
 *   1. Single-use: a consumed code never consumes again (existing behavior,
 *      pinned here against the real storage for the first time).
 *   2. Fresh-authority recovery (notme-976385): three routes can burn the
 *      code (register/options, /auth/passkey/reset, POST /cert) and only one
 *      creates an admin. While NO principal exists, a consumed code must
 *      regenerate — otherwise a fresh authority is permanently stranded with
 *      no way to ever create an administrator.
 *   3. Bootstrap closes for good once a principal exists — regeneration must
 *      NOT resurrect the code on an established authority (the original
 *      anti-wipe-loop invariant, kept).
 *   4. POST /cert bootstrap persists the admin it mints a credential for
 *      (notme-92a1b9): pre-fix, principalId was a local variable — the sole
 *      code was burned, a live credential with authorityManage+certMint
 *      walked away, and the authority had zero principals.
 *
 * Runs under vitest.workers.config.mts (`pnpm test:do`), NOT the plain suite.
 */

// worker.fetch(request, env) directly (not SELF) so each call controls env —
// same harness rationale as dpop-nonce.do.test.ts. isLocal mode routes the
// auth surface without a host header.
import worker from "../worker";
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// Unique DO instance per test — this pool config shares storage across
// tests in a file, so isolation comes from names (same pattern as
// signing-authority.do.test.ts). The route test uses "default" because the
// real /cert handler resolves idFromName("default") internally; no other
// test in this file touches it.
function authority(name: string) {
  return env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(name));
}

describe("bootstrap code single-use invariant (real DO)", () => {
  it("consumes exactly once — the same code never consumes twice", async () => {
    const stub = authority("bs-single-use");
    const code = await stub.getOrCreateBootstrapCode();
    expect(code).toBeTruthy();
    expect(await stub.consumeBootstrapCode(code!)).toBe(true);
    expect(await stub.consumeBootstrapCode(code!)).toBe(false);
  });

  it("stores the full UUID — not the 8-char prefix passkey.test.ts used to claim", async () => {
    const code = await authority("bs-uuid-shape").getOrCreateBootstrapCode();
    expect(code).toMatch(UUID_RE);
  });

  it("returns the SAME code on repeated calls before consumption", async () => {
    const stub = authority("bs-stable-code");
    const first = await stub.getOrCreateBootstrapCode();
    expect(await stub.getOrCreateBootstrapCode()).toBe(first);
  });
});

describe("fresh-authority recovery (notme-976385)", () => {
  it("regenerates a NEW code after consumption while no principal exists", async () => {
    const stub = authority("bs-regen");
    const first = await stub.getOrCreateBootstrapCode();
    expect(await stub.consumeBootstrapCode(first!)).toBe(true);

    const second = await stub.getOrCreateBootstrapCode();
    expect(second).toMatch(UUID_RE);
    expect(second).not.toBe(first);

    // The regenerated code is live…
    expect(await stub.consumeBootstrapCode(second!)).toBe(true);
    // …and the burned one stays dead.
    expect(await stub.consumeBootstrapCode(first!)).toBe(false);
  });

  it("regenerates after /auth/passkey/reset burns the code on a fresh authority", async () => {
    const stub = authority("bs-reset-regen");
    const first = await stub.getOrCreateBootstrapCode();
    await stub.resetPasskeyData();

    const second = await stub.getOrCreateBootstrapCode();
    expect(second).toMatch(UUID_RE);
    expect(second).not.toBe(first);
  });

  it("does NOT regenerate once a principal exists — bootstrap closes for good", async () => {
    const stub = authority("bs-closed-after-admin");
    const code = await stub.getOrCreateBootstrapCode();
    expect(await stub.consumeBootstrapCode(code!)).toBe(true);
    await stub.createPrincipalWithCapabilities(crypto.randomUUID(), [
      "bridgeCert",
    ]);
    expect(await stub.getOrCreateBootstrapCode()).toBeNull();
  });
});

describe("POST /cert bootstrap persists the admin (notme-92a1b9)", () => {
  it("the minted credential's principal survives the exchange with its scopes", async () => {
    const stub = authority("default");
    const code = await stub.getOrCreateBootstrapCode();

    const resp = await worker.fetch(
      new Request(`${ORIGIN}/cert`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ proof: { type: "bootstrap", code } }),
      }),
      { ...env, ...LOCAL_ENV },
    );
    expect(resp.status).toBe(200);
    const body = (await resp.json()) as {
      principal_id: string;
      auth_method: string;
    };
    expect(body.auth_method).toBe("bootstrap");
    expect(body.principal_id).toMatch(UUID_RE);

    // The defect: pre-fix, principal_id was a local variable — nothing was
    // persisted, so the credential's subject did not exist and no scope
    // could ever be looked up, granted, or revoked for it.
    const scopes = await stub.getPrincipalScopes(body.principal_id);
    expect(scopes).toEqual(
      expect.arrayContaining(["bridgeCert", "authorityManage", "certMint"]),
    );
  });
});
