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
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { SigningAuthority } from "./signing-authority";

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

/**
 * The code from an "issued" bootstrap state, asserting it was issued.
 *
 * getOrCreateBootstrapCode returns a discriminated state rather than
 * `string | null` (notme-addef9) precisely so a caller cannot ignore the
 * closed case — these helpers keep the tests honest about which they expect.
 */
async function issuedCode(stub: {
  getOrCreateBootstrapCode: () => Promise<any>;
}): Promise<string> {
  const state = await stub.getOrCreateBootstrapCode();
  expect(state.status).toBe("issued");
  return state.code as string;
}

async function bootstrapStatus(stub: {
  getOrCreateBootstrapCode: () => Promise<any>;
}): Promise<string> {
  return (await stub.getOrCreateBootstrapCode()).status as string;
}

describe("bootstrap code single-use invariant (real DO)", () => {
  it("consumes exactly once — the same code never consumes twice", async () => {
    const stub = authority("bs-single-use");
    const code = await issuedCode(stub);
    expect(code).toBeTruthy();
    expect(await stub.consumeBootstrapCode(code)).toBe(true);
    expect(await stub.consumeBootstrapCode(code)).toBe(false);
  });

  it("stores the full UUID — not the 8-char prefix passkey.test.ts used to claim", async () => {
    const code = await issuedCode(authority("bs-uuid-shape"));
    expect(code).toMatch(UUID_RE);
  });

  it("returns the SAME code on repeated calls before consumption", async () => {
    const stub = authority("bs-stable-code");
    const first = await issuedCode(stub);
    expect(await issuedCode(stub)).toBe(first);
  });
});

describe("fresh-authority recovery (notme-976385)", () => {
  it("regenerates a NEW code after consumption while no principal exists", async () => {
    const stub = authority("bs-regen");
    const first = await issuedCode(stub);
    expect(await stub.consumeBootstrapCode(first)).toBe(true);

    const second = await issuedCode(stub);
    expect(second).toMatch(UUID_RE);
    expect(second).not.toBe(first);

    // The regenerated code is live…
    expect(await stub.consumeBootstrapCode(second)).toBe(true);
    // …and the burned one stays dead.
    expect(await stub.consumeBootstrapCode(first)).toBe(false);
  });

  it("regenerates after /auth/passkey/reset burns the code on a fresh authority", async () => {
    const stub = authority("bs-reset-regen");
    const first = await issuedCode(stub);
    await stub.resetPasskeyData();

    const second = await issuedCode(stub);
    expect(second).toMatch(UUID_RE);
    expect(second).not.toBe(first);
  });

  // THE CASE THE FIRST VERSION OF THIS FILE MISSED (found by adversarial
  // review). The tests below it prove closure by calling
  // createPrincipalWithCapabilities — but the PRIMARY deployer flow never
  // creates a principal at all: registerPasskey writes passkey_users +
  // passkey_credentials only (worker/src/auth/passkey.ts). So a
  // principals-only predicate reports "nobody is here" on the exact
  // configuration that means "the admin is here", and the DO would re-arm
  // bootstrap for any caller that asked.
  //
  // Today the only caller gates on isFirstUser, which masks it — but that
  // makes the invariant depend on the CALLER rather than on the DO that
  // claims to enforce it. These tests pin it in the DO.
  //
  // The rows are inserted directly rather than by driving WebAuthn: a real
  // registration needs an authenticator attestation, and the invariant under
  // test is "an authenticator EXISTS", not how it got there.
  it("does NOT regenerate when a passkey credential exists but no principal row does", async () => {
    const stub = authority("bs-passkey-no-principal");
    const code = await issuedCode(stub);
    expect(await stub.consumeBootstrapCode(code)).toBe(true);

    await runInDurableObject(stub, async (auth) => {
      const a = auth as SigningAuthority;
      const { ensurePasskeySchema } = await import("./auth/passkey");
      ensurePasskeySchema((a as any).ctx.storage.sql);
      (a as any).ctx.storage.sql.exec(
        "INSERT INTO passkey_users (user_id, display_name, is_admin) VALUES (?, ?, ?)",
        "deployer",
        "deployer",
        1,
      );
      (a as any).ctx.storage.sql.exec(
        "INSERT INTO passkey_credentials (credential_id, user_id, public_key, counter, transports) VALUES (?, ?, ?, ?, ?)",
        "cred-1",
        "deployer",
        "AAAA",
        0,
        "[]",
      );
    });

    // The deployer's authenticator is registered. Bootstrap must be closed —
    // re-arming here would mint a fresh admin code into the Worker logs for
    // an authority that already has an administrator.
    expect(await bootstrapStatus(stub)).toBe("closed");
  });

  it("does NOT regenerate when a federated identity exists but no passkey does", async () => {
    const stub = authority("bs-federated-no-passkey");
    const code = await issuedCode(stub);
    expect(await stub.consumeBootstrapCode(code)).toBe(true);

    const principalId = crypto.randomUUID();
    await stub.createPrincipalWithCapabilities(principalId, ["bridgeCert"]);
    await stub.linkFederatedId(
      principalId,
      "https://accounts.example",
      "subject-1",
    );

    expect(await bootstrapStatus(stub)).toBe("closed");
  });

  it("DOES regenerate when only a bare principal exists — a cert holder is not an interactive admin", async () => {
    // The /cert bootstrap path persists a principal (notme-92a1b9) that has
    // no passkey credential and no federated identity, and no HTTP route
    // turns a bridge cert into a session. Treating that row as "someone is
    // here" would close bootstrap against an authority nobody can log in to
    // — reintroducing notme-976385's strand through the one burn route that
    // previously caused it. Counting authenticators keeps the two fixes from
    // cancelling each other.
    const stub = authority("bs-bare-principal");
    const code = await issuedCode(stub);
    expect(await stub.consumeBootstrapCode(code)).toBe(true);
    await stub.createPrincipalWithCapabilities(crypto.randomUUID(), [
      "bridgeCert",
    ]);
    const regenerated = await issuedCode(stub);
    expect(regenerated).toMatch(UUID_RE);
    expect(regenerated).not.toBe(code);
  });
});

describe("resetPasskeyData revokes what it wipes", () => {
  // The bootstrap predicate asks "can anyone authenticate?" — and a session
  // cookie IS a way to authenticate. resetPasskeyData wipes every passkey
  // credential but the session secret was generated once and never rotated,
  // so cookies issued before a reset stayed valid for their full 24h TTL.
  //
  // That produced the predicate's most reachable gap: a deployer who resets
  // WHILE LOGGED IN leaves hasAuthenticator() false and an admin session
  // live, and bootstrap re-arms a fresh code into the Worker logs for an
  // authority that still has a working administrator.
  //
  // Rotating the secret here makes "reset" mean what it says, which makes
  // the predicate true by construction for this population — and it
  // independently fixes the fact that a reset previously revoked nothing.
  it("rotates the session secret, invalidating cookies issued before it", async () => {
    const stub = authority("bs-reset-rotates-secret");
    const before = await stub.getSessionSecret();
    expect(before).toBeTruthy();

    await stub.resetPasskeyData();

    const after = await stub.getSessionSecret();
    expect(after).toBeTruthy();
    expect(after).not.toBe(before);

    // A cookie minted under the old secret must no longer verify — the
    // point of rotating, not merely that the stored string changed.
    const { createSessionCookie, verifySessionCookie } = await import(
      "./auth/session"
    );
    const staleCookie = await createSessionCookie(
      {
        principalId: "pre-reset-admin",
        scopes: ["bridgeCert", "authorityManage", "certMint"],
        authMethod: "passkey",
      },
      before,
    );
    const value = staleCookie.slice("notme_session=".length).split(";")[0]!;
    expect(await verifySessionCookie(value, after)).toBeNull();
  });
});

describe("POST /cert bootstrap persists the admin (notme-92a1b9)", () => {
  it("the minted credential's principal survives the exchange with its scopes", async () => {
    const stub = authority("default");
    const code = await issuedCode(stub);

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

describe("epoch key index — third-party historical verification (notme-a0cff4)", () => {
  // A third party auditing a receipt or cert that names epoch N must resolve
  // which key signed it. Today notme retains retired keys (rotate() archives
  // before deleting) and getEpochPublicKey() can answer — but it had ZERO
  // callers and no HTTP surface, so the answer was unreachable to anyone
  // without a service binding. Cloister could only archive epochs it happened
  // to observe by polling; a rotation between polls left that epoch
  // permanently unresolvable even though notme held the key.
  //
  // This is the notme half of third-party attestability: publish the epoch →
  // key mapping so an auditor can verify history, not just the present.
  it("serves every epoch's signing key, current and retired", async () => {
    const stub = authority("default");
    // Establish a key, then rotate twice so there is real history to resolve.
    const first = await stub.getPublicKeyRawB64();
    const r1 = await stub.rotate();
    const r2 = await stub.rotate();

    const res = await worker.fetch(
      new Request(`${ORIGIN}/.well-known/epochs.json`),
      { ...env, ...LOCAL_ENV },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      epochs: Array<{
        epoch: number;
        keyId: string;
        publicRawB64: string;
        retiredAt: number | null;
      }>;
    };

    // Every epoch that ever existed is resolvable, including the two retired
    // by the rotations above — the case cloister could previously miss.
    const byEpoch = new Map(body.epochs.map((e) => [e.epoch, e]));
    expect(byEpoch.size).toBeGreaterThanOrEqual(3);
    expect(byEpoch.get(r2.epoch)?.retiredAt).toBeNull(); // current
    expect(byEpoch.get(r1.epoch)?.retiredAt).toBeTypeOf("number"); // retired
    // The original key is still resolvable two rotations later — the exact
    // repudiation risk notme-acd503 described.
    const oldest = [...byEpoch.values()].sort((a, b) => a.epoch - b.epoch)[0]!;
    expect(oldest.publicRawB64).toBe(first);
  });

  it("is cacheable and needs no authentication — an auditor is not a principal", async () => {
    const res = await worker.fetch(
      new Request(`${ORIGIN}/.well-known/epochs.json`),
      { ...env, ...LOCAL_ENV },
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toContain("max-age");
  });
});

describe("first-boot 401 must not send operators after a code that was never minted (notme-addef9)", () => {
  // getOrCreateBootstrapCode returns null when an authenticator already
  // exists — bootstrap is closed. worker.ts DISCARDED that return value and
  // emitted "bootstrap code required — check Worker logs" unconditionally, so
  // in the closed case an operator is told to go find a UUID that was never
  // logged. The two states must be distinguishable at the caller.
  async function registerOptions(name: string) {
    return worker.fetch(
      new Request(`${ORIGIN}/auth/passkey/register/options`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      }),
      { ...env, ...LOCAL_ENV },
    );
  }

  it("tells an UNCONFIGURED authority how to arm itself — and never says 'logs'", async () => {
    // Was: "check Worker logs (wrangler tail)". That message is gone with the
    // mechanism behind it (notme-addef9). An unauthenticated request no longer
    // MINTS anything, so there is no code in a log to go and read — and this
    // cycle proved the logs are not reliably readable anyway (`wrangler tail`
    // returned nothing for a known-good 200 in production).
    //
    // Asserting the absence of /log/i as well as the presence of the new
    // instruction: a message that named both paths would leave operators
    // hunting for a credential that was never created.
    const res = await registerOptions("default");
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/BOOTSTRAP_CODE/);
    expect(body.error).not.toMatch(/log/i);
  });

  it("says the authority already has an administrator when bootstrap is CLOSED", async () => {
    // Establish an authenticator so hasAuthenticator() is true and
    // getOrCreateBootstrapCode returns null.
    const stub = authority("default");
    await runInDurableObject(stub, async (auth) => {
      const a = auth as SigningAuthority;
      const { ensurePasskeySchema } = await import("./auth/passkey");
      ensurePasskeySchema((a as any).ctx.storage.sql);
      (a as any).ctx.storage.sql.exec(
        "INSERT OR IGNORE INTO passkey_credentials (credential_id, user_id, public_key, counter, transports) VALUES (?, ?, ?, ?, ?)",
        "closed-cred",
        "closed-user",
        "AAAA",
        0,
        "[]",
      );
    });

    // Confirm the DO itself now reports closed, so a failure below is the
    // ROUTE ignoring the state rather than the predicate being wrong.
    expect(await bootstrapStatus(stub)).toBe("closed");

    const res = await registerOptions("default");
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    // The old message pointed at logs that hold nothing. It must not.
    expect(body.error).not.toMatch(/log/i);
    expect(body.error).toMatch(/administrator|already/i);
  });
});

describe("a bootstrap code is valid ONLY while nobody can authenticate (notme-addef9)", () => {
  // The invariant must hold at CONSUME, not only at MINT. Gating
  // getOrCreateBootstrapCode alone fixed what the authority REPORTS while
  // leaving what it ACCEPTS unchanged: a code minted before the first admin
  // existed, captured from the Worker logs and never redeemed, stayed
  // consumable afterwards. POST /cert consumes bootstrap codes and mints
  // authorityManage + certMint, so that is a live admin credential
  // outliving its purpose — bounded only by the 15-minute TTL.
  it("refuses a still-unused code once an authenticator exists", async () => {
    const stub = authority("bs-consume-after-admin");
    const code = await issuedCode(stub); // minted while nobody can authenticate

    // An administrator arrives by some other path — here a registered
    // passkey, which is the primary deployer flow.
    await runInDurableObject(stub, async (auth) => {
      const a = auth as SigningAuthority;
      const { ensurePasskeySchema } = await import("./auth/passkey");
      ensurePasskeySchema((a as any).ctx.storage.sql);
      (a as any).ctx.storage.sql.exec(
        "INSERT INTO passkey_credentials (credential_id, user_id, public_key, counter, transports) VALUES (?, ?, ?, ?, ?)",
        "admin-cred",
        "admin",
        "AAAA",
        0,
        "[]",
      );
    });

    // Reporting is already closed…
    expect(await bootstrapStatus(stub)).toBe("closed");
    // …and consumption must be too. This is the half that was missing.
    expect(await stub.consumeBootstrapCode(code)).toBe(false);
  });

  it("still accepts a code while the authority has no way in — recovery must keep working", async () => {
    // The guard must not break the case it exists to serve: a stranded
    // authority with nobody able to authenticate.
    const stub = authority("bs-consume-no-admin");
    const code = await issuedCode(stub);
    expect(await stub.consumeBootstrapCode(code)).toBe(true);
  });
});
