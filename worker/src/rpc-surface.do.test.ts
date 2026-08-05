/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * rpc-surface.do.test.ts — pin the RPC-reachable method surface of every
 * WorkerEntrypoint and of the SigningAuthority DO.
 *
 * WHY: `AuthService.getAuthority()` was declared TypeScript `private` and was
 * a live RPC method that returned the raw SigningAuthority stub — mint a cert
 * with any identity and scopes, rotate the CA, read the session secret. A
 * complete CA compromise for anyone holding an AUTH binding, which per ADR-009
 * is every agent Worker.
 *
 * It survived because `private` LOOKS like a boundary. It is erased at
 * compile time; workerd exposes ordinary prototype methods over RPC and cannot
 * see the annotation. Only `#private` is enforced by the runtime.
 *
 * `Object.getOwnPropertyNames(Cls.prototype)` is precisely what workerd walks,
 * so this test sees the surface the way an RPC caller does:
 *   - a TypeScript `private` method APPEARS here (correctly — it is reachable)
 *   - a `#private` method does NOT (correctly — it is not)
 *
 * So a new method is only reachable once someone adds it to an allow-list
 * below, in a diff a reviewer reads. Reviewing an annotation is how this class
 * of bug got in; reviewing a list is not.
 */

import { describe, expect, it } from "vitest";
import { AuthService, JwtSigner, ReceiptSigner } from "../worker";
import { SigningAuthority } from "./signing-authority";

/** What workerd will dispatch to. `constructor` is not callable over RPC. */
function rpcSurface(cls: { prototype: object }): string[] {
  return Object.getOwnPropertyNames(cls.prototype)
    .filter((n) => n !== "constructor")
    .sort();
}

describe("RPC surface is an allow-list, not an accident", () => {
  it("ReceiptSigner exposes only receipt signing (ADR-014 least privilege)", () => {
    // The ADR claims a binding to ReceiptSigner "grants receipt signing and
    // nothing else". This is that claim, executable.
    expect(rpcSurface(ReceiptSigner)).toEqual(["receiptFacts", "signReceipt"]);
  });

  it("JwtSigner exposes only delegated JWT signing (ADR-015)", () => {
    // #allowedIssuers and #authority are absent because they are ECMAScript
    // private. If either is ever downgraded to TS `private`, it appears here
    // and this fails — which is the whole point.
    expect(rpcSurface(JwtSigner)).toEqual(["issuerPublicKey", "signJwt"]);
  });

  it("AuthService exposes no capability-handing method", () => {
    const surface = rpcSurface(AuthService);

    // The specific regression. getAuthority() returned a DO stub; a stub is a
    // capability, and handing one over RPC forwards the entire DO.
    expect(surface).not.toContain("getAuthority");

    // Nothing else may return a stub or key material either. Named rather than
    // pattern-matched, so adding one is a deliberate, reviewable act.
    for (const forbidden of [
      "getAuthority",
      "authority",
      "getSigningKey",
      "getPrivateKey",
      "exportKey",
      "getEnv",
    ]) {
      expect(surface, `${forbidden} must not be RPC-reachable`).not.toContain(
        forbidden,
      );
    }
  });

  it("AuthService's surface is exactly the reviewed set", () => {
    // A full pin, so ANY new method fails until it is added here on purpose.
    // If this breaks after you add a method, that is the test working: decide
    // whether a service-binding holder should be able to call it, then add it.
    // `fetch` is absent: it is inherited from WorkerEntrypoint, not an own
    // property of this prototype. Own properties are what an RPC caller
    // reaches by name, which is why this walks them specifically.
    expect(rpcSurface(AuthService)).toEqual([
      "authenticate",
      "getAuthorityState",
      "getCACertificatePem",
      "getPublicKeyPem",
      "identity",
      "mintBridgeCert",
      "mintDPoPToken",
      "proxy",
      "sign",
      "verifySession",
    ]);
  });

  it("SigningAuthority's surface is pinned — it is what a leaked stub yields", () => {
    // Not directly bound by anyone, but getAuthority() proved a stub can
    // escape. Pinning it means a new DO method shows up in a diff, and the
    // reviewer gets to ask what happens if this one leaks too.
    const surface = rpcSurface(SigningAuthority);
    expect(surface).toContain("signReceiptCommitment");
    expect(surface).toContain("signDelegatedJwt");

    // Deleted in ADR-014 review: "sign arbitrary data with the authority key",
    // the universal forgery oracle. It must not come back.
    expect(surface).not.toContain("sign");

    // Pinned COUNT rather than a full list: this class is large (41) and
    // churns, and a brittle full pin gets updated reflexively instead of read.
    // A count still forces a diff to touch this file, which is where the
    // question gets asked.
    //
    // 46 -> 41 (notme-41d0d3): five methods declared `private` in TypeScript
    // were live on the surface all along — `private` is a COMPILE-TIME
    // annotation and is erased in the emitted JS, so it hides a member from the
    // author and from nobody else. ensureSchema, getKeyId, keyStorageMode,
    // ensureAlarmHealthSchema and readAlarmHealthRow are now ECMAScript
    // #private and genuinely unreachable. None was individually dangerous, but
    // the pin had been silently blessing them.
    //
    // The lesson this file exists to enforce: on an RPC-reachable class write
    // `#foo()`, never `private foo()`. Same trap as #getAuthority() in
    // worker.ts (ADR-016 rule 2). Note that this count only tells you the
    // surface CHANGED, not that a member was wrongly exposed — it catches the
    // mistake after it is written, so it is a backstop, not the rule.
    //
    // (The first version of this line was `toBe(surface.length)` — comparing a
    // value to itself, a test that always passes and asserts nothing. Left
    // noted because it is the same shape as the fixtures-built-with-the-
    // encoder-under-test problem found in ADR-014: self-referential checks
    // look green for free.)
    expect(
      surface.length,
      `SigningAuthority RPC surface changed (now ${surface.length}). A stub ` +
        `for this DO is a full-CA capability — confirm the new method is safe ` +
        `in the hands of anyone who obtains one, then update this count.\n` +
        surface.join(", "),
      // 41 → 42: listEpochKeys (notme-a0cff4). Reviewed against the standard
      // above — it returns epoch, keyId, PUBLIC key bytes and retiredAt, which
      // is exactly the payload /.well-known/epochs.json serves
      // unauthenticated. A leaked stub therefore gains nothing a public GET
      // does not already give, and it exposes no private material, no minting
      // and no mutation.
    ).toBe(42);
  });
});

// ── Instance fields, not just prototype methods (notme-2154b8) ──────────────
//
// The surface walk above reads `Cls.prototype`, which sees METHODS. TypeScript
// `private` is erased for fields too, and a field lives on the INSTANCE — so a
// `private` field on an RPC-reachable class is invisible to every assertion in
// this file while remaining readable on any stub someone obtains.
//
// AuthService.heldCerts is the live instance of the pattern. It holds
// per-session credential state, and the class is reachable by service binding.
// The mitigations are real — workerd gives a fresh `this` per RPC session, so a
// caller sees only their own, and CryptoKeys are not structured-cloneable — but
// they are properties of the RUNTIME, not of the declaration, and the rule this
// file exists to enforce is about the declaration: on an RPC-reachable class
// write `#foo`, never `private foo`.
describe("instance fields are private too, not merely TypeScript-private", () => {
  it("AuthService exposes no own enumerable state on an instance", async () => {
    const { AuthService } = await import("../worker");
    // WorkerEntrypoint's ctor takes (ctx, env); neither is touched here.
    const instance = new (AuthService as any)({}, {});
    // ctx and env are WorkerEntrypoint's own, assigned by the base
    // constructor — unavoidable and not ours to hide. Everything else on the
    // instance is state WE declared, and must be #private.
    const FRAMEWORK_OWNED = new Set(["ctx", "env"]);
    const ours = Object.getOwnPropertyNames(instance).filter(
      (n) => !FRAMEWORK_OWNED.has(n),
    );
    expect(
      ours,
      `AuthService instance exposes ${ours.join(", ")} — a TypeScript \`private\` ` +
        `field is erased and stays readable on a stub. Use #private.`,
    ).toEqual([]);
  });
});
