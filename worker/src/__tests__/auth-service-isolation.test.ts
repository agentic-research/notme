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
import { makeCA, mintCreds, stubEnv } from "./helpers/mint-creds";

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

// ONE CA for the whole file, so every service instance verifies against the
// same authority a real deployment would. The second stands in for anyone
// else's CA — certs it signs must be refused however well-formed they are.
const CA = await makeCA();
const ATTACKER_CA = await makeCA();

function makeAuthService(): AuthService {
  // WorkerEntrypoint's base ctor takes (ctx, env). authenticate() now reaches
  // the authority for the CA public key it verifies against, so the stub env
  // supplies SIGNING_AUTHORITY — the one binding these tests exercise.
  return new (AuthService as any)({} as any, stubEnv(CA) as any);
}

const makeRealCreds = (
  identity: string,
  scopes: string[],
  opts: { attackerCA?: boolean } = {},
) => mintCreds(opts.attackerCA ? ATTACKER_CA : CA, identity, scopes);


describe("Threat: a bound Worker asserts its own identity (notme-6ad276)", () => {
  it("ignores caller-asserted identity and scopes — the cert is the only source", async () => {
    // The exploit from the red-team bead: a Worker holding an AUTH service
    // binding presents its own legitimately-minted low-privilege cert, then
    // simply *says* it is someone else with more scopes. Before the fix,
    // authenticate() was one assignment and believed every word.
    const svc = makeAuthService();
    const real = await makeRealCreds("wimse://notme.bot/test/alice", ["bridgeCert"]);

    await svc.authenticate({
      ...real,
      identity: "wimse://notme.bot/gha/agentic-research/cloister",
      scopes: ["bridgeCert", "sign:git", "sign:attestation", "authorityManage"],
      expiresAt: Math.floor(Date.now() / 1000) + 86_400,
    } as never);

    const id = await svc.identity();
    expect(id.identity).toBe("wimse://notme.bot/test/alice");
    expect(id.scopes).toEqual(["bridgeCert"]);
  });

  it("refuses certs not signed by this authority's CA", async () => {
    const svc = makeAuthService();
    // Self-minted under an attacker CA, naming a privileged principal.
    const forged = await makeRealCreds(
      "wimse://notme.bot/gha/agentic-research/cloister",
      ["authorityManage"],
      { attackerCA: true },
    );

    await expect(svc.authenticate(forged as never)).rejects.toThrow(/signature|CA|trusted/i);
    expect((await svc.identity()).authenticated).toBe(false);
  });
});

describe("Threat: AuthService credentials must not leak across RPC sessions", () => {
  it("two AuthService instances hold independent credentials", async () => {
    const svcA = makeAuthService();
    const svcB = makeAuthService();

    await svcA.authenticate(await makeRealCreds("wimse://notme.bot/test/alice", ["bridgeCert"]));
    await svcB.authenticate(
      await makeRealCreds("wimse://notme.bot/test/bob", ["bridgeCert", "sign:git"]),
    );

    const idA = await svcA.identity();
    const idB = await svcB.identity();

    expect(idA.identity).toBe("wimse://notme.bot/test/alice");
    expect(idA.scopes).toEqual(["bridgeCert"]);
    expect(idB.identity).toBe("wimse://notme.bot/test/bob");
    expect(idB.scopes).toEqual(["bridgeCert", "sign:git"]);
  });

  it("unauthenticated instance never observes another instance's credentials", async () => {
    const svcA = makeAuthService();
    const svcB = makeAuthService();

    await svcA.authenticate(await makeRealCreds("wimse://notme.bot/test/alice", ["bridgeCert"]));

    const idB = await svcB.identity();
    expect(idB.authenticated).toBe(false);
    expect(idB.identity).toBe("");
    expect(idB.scopes).toEqual([]);
  });

  it("authenticate() on one instance does not change another's signing identity", async () => {
    const svcA = makeAuthService();
    const svcB = makeAuthService();

    await svcA.authenticate(await makeRealCreds("wimse://notme.bot/test/alice", []));
    await svcB.authenticate(await makeRealCreds("wimse://notme.bot/test/bob", []));

    // Now re-authenticate A — must not affect B.
    await svcA.authenticate(await makeRealCreds("wimse://notme.bot/test/alice-rekeyed", []));

    expect((await svcA.identity()).identity).toBe("wimse://notme.bot/test/alice-rekeyed");
    expect((await svcB.identity()).identity).toBe("wimse://notme.bot/test/bob");
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
        await svcA.authenticate(await makeRealCreds("wimse://notme.bot/test/alice", ["bridgeCert"]));
        return svcA.identity();
      })(),
      (async () => {
        await svcB.authenticate(await makeRealCreds("wimse://notme.bot/test/bob", ["sign:git"]));
        return svcB.identity();
      })(),
    ]);

    expect(idA.identity).toBe("wimse://notme.bot/test/alice");
    expect(idA.scopes).toEqual(["bridgeCert"]);
    expect(idB.identity).toBe("wimse://notme.bot/test/bob");
    expect(idB.scopes).toEqual(["sign:git"]);
  });
});
