/**
 * auth-service-isolation.test.ts — Threat: credential state confusion across
 * RPC sessions on AuthService (notme/worker review Finding 1).
 *
 * AuthService.authenticate() previously wrote to a module-level `heldCerts`
 * variable. workerd creates a fresh `this` per RPC session, but module state
 * is shared across every concurrent and sequential caller in the isolate —
 * a second authenticate() silently swapped the first caller's identity.
 *
 * The fix puts heldCerts on `this`. These tests pin that invariant by
 * exercising two separate AuthService instances and asserting their state
 * does NOT cross-contaminate.
 */

import { describe, expect, it, vi } from "vitest";

// The Worker's transitive imports reach `cloudflare:workers` (DurableObject,
// WorkerEntrypoint) which is not available in plain vitest. Stub the runtime
// module with minimal shapes — these tests are about AuthService's INTERNAL
// state isolation, not its DO/runtime integration.
vi.mock("cloudflare:workers", () => ({
  DurableObject: class {},
  WorkerEntrypoint: class {
    ctx: unknown;
    env: unknown;
    constructor(ctx: unknown, env: unknown) {
      this.ctx = ctx;
      this.env = env;
    }
  },
}));

const { AuthService } = await import("../../worker");
type AuthService = InstanceType<typeof AuthService>;

function makeAuthService(): AuthService {
  // Construct a bare instance with a minimal stub env. WorkerEntrypoint's
  // base ctor takes (ctx, env); for state-isolation tests we don't touch
  // the SIGNING_AUTHORITY binding.
  return new (AuthService as any)({} as any, {} as any);
}

async function makeFakeCreds(identity: string, scopes: string[]) {
  // Non-extractable key — matches production posture.
  const kp = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  return {
    mtlsCert: `cert-for-${identity}`,
    signingCert: `signing-cert-for-${identity}`,
    mtlsKey: kp.privateKey,
    signingKey: kp.privateKey,
    identity,
    scopes,
    expiresAt: Math.floor(Date.now() / 1000) + 600,
  };
}

describe("Threat: AuthService credentials must not leak across RPC sessions", () => {
  it("two AuthService instances hold independent credentials", async () => {
    const svcA = makeAuthService();
    const svcB = makeAuthService();

    await svcA.authenticate(await makeFakeCreds("alice", ["bridgeCert"]));
    await svcB.authenticate(
      await makeFakeCreds("bob", ["bridgeCert", "sign:git"]),
    );

    const idA = await svcA.identity();
    const idB = await svcB.identity();

    expect(idA.identity).toBe("alice");
    expect(idA.scopes).toEqual(["bridgeCert"]);
    expect(idB.identity).toBe("bob");
    expect(idB.scopes).toEqual(["bridgeCert", "sign:git"]);
  });

  it("unauthenticated instance never observes another instance's credentials", async () => {
    const svcA = makeAuthService();
    const svcB = makeAuthService();

    await svcA.authenticate(await makeFakeCreds("alice", ["bridgeCert"]));

    const idB = await svcB.identity();
    expect(idB.authenticated).toBe(false);
    expect(idB.identity).toBe("");
    expect(idB.scopes).toEqual([]);
  });

  it("authenticate() on one instance does not change another's signing identity", async () => {
    const svcA = makeAuthService();
    const svcB = makeAuthService();

    await svcA.authenticate(await makeFakeCreds("alice", []));
    await svcB.authenticate(await makeFakeCreds("bob", []));

    // Now re-authenticate A — must not affect B.
    await svcA.authenticate(await makeFakeCreds("alice-rekeyed", []));

    expect((await svcA.identity()).identity).toBe("alice-rekeyed");
    expect((await svcB.identity()).identity).toBe("bob");
  });

  it("concurrent authenticate→identity flows preserve per-session identity", async () => {
    // Real exploit shape: two callers, two distinct identities, both in
    // flight at once. Each must see only its own creds throughout.
    // (Uses identity() rather than sign() — sign() needs Ed25519 keys
    // which the test fixture doesn't generate; the state-leak surface is
    // identical because both methods read from `this.heldCerts`.)
    const svcA = makeAuthService();
    const svcB = makeAuthService();

    const [idA, idB] = await Promise.all([
      (async () => {
        await svcA.authenticate(await makeFakeCreds("alice", ["bridgeCert"]));
        return svcA.identity();
      })(),
      (async () => {
        await svcB.authenticate(await makeFakeCreds("bob", ["sign:git"]));
        return svcB.identity();
      })(),
    ]);

    expect(idA.identity).toBe("alice");
    expect(idA.scopes).toEqual(["bridgeCert"]);
    expect(idB.identity).toBe("bob");
    expect(idB.scopes).toEqual(["sign:git"]);
  });
});
