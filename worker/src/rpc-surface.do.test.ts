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

    // Pinned COUNT rather than a full list: this class is large (46) and
    // churns, and a brittle full pin gets updated reflexively instead of read.
    // A count still forces a diff to touch this file, which is where the
    // question gets asked.
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
    ).toBe(46);
  });
});
