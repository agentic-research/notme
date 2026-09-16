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

import { env, runInDurableObject } from "cloudflare:test";
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
      //
      // 42 → 43: getBootstrapState (notme-addef9). Reviewed and SAFER than
      // what it displaces. It is a pure read returning one of three words —
      // closed, armed, unconfigured — and carries no code in any variant.
      // The method it removes from the unauthenticated path,
      // getOrCreateBootstrapCode, MINTS an admin credential as a side effect
      // of being called; this one cannot. A leaked stub learns only whether
      // an authority has an administrator, which /auth/passkey/status
      // already answers publicly.
      //
      // 43 → 44: mintIssuingCa (ADR-019 D4). Reviewed: a leaked stub could
      // already mint arbitrary LEAF certs via mintBridgeCertPair, so the new
      // capability class is not "can mint" — it is post-leak PERSISTENCE: an
      // Issuing CA cert keeps signing task certs offline after stub access is
      // lost. Bounded two ways: the method refuses any TTL over 24h (the
      // route sends none, so a long TTL is evidence of misuse, not clamped
      // away), and pathlen=0 means verifiers reject anything a minted tier
      // tries to issue below itself beyond one hop.
      //
      // 44 → 47: revokeCapability, listGrants, ensurePasskeyPrincipal
      // (notme-77a024). Reviewed. revokeCapability only NARROWS — a leaked
      // stub can strip authority, never add it, and the pre-existing
      // createPrincipalWithCapabilities already let a stub grant anything,
      // so the widening capability class is unchanged. listGrants returns
      // scope strings, timestamps and principal ids: an audit view, no
      // secrets. ensurePasskeyPrincipal is a GRANTING path, so it was
      // reviewed hardest: it grants the admin triple only when the principal
      // has no row AND isFirstUser is true — the same "first user is admin"
      // rule verifyRegistration already enforced via is_admin, now expressed
      // as revocable grants. Idempotent by construction: an existing
      // principal's grants are returned, never re-granted, so it cannot
      // restore a revoked scope.
      //
      // 47 → 48: bootstrapFromAttestation (notme-addef9). Reviewed hardest
      // of any addition so far, because it CREATES AN ADMINISTRATOR. Three
      // conditions gate it and a leaked stub satisfies none of them: the
      // deployer must have set BOOTSTRAP_GHA_SUBJECT (unset means off, and
      // that is the branch a pure predicate in auth/bootstrap-policy.ts now
      // covers), the argument must equal it, and the authority must have no
      // principal or authenticator — which any authority a stub was stolen
      // FROM necessarily has. So on a live authority this method is a no-op
      // by construction; on a fresh one, a caller holding a stub already had
      // the deployment access needed to set the variable in the first place.
      //
      // 48 → 47: getOrCreateSigningKey REMOVED (notme-eedc9c). The first
      // removal in this log, and the only one so far that was a live
      // exposure rather than a reviewed addition.
      //
      // Its return type was { signingKey: CryptoKey; verifyKey: CryptoKey;
      // keyId } — the CA's private key, handed to anyone holding a stub. The
      // pin above never caught it because the pin asks what is REACHABLE,
      // not what reachable things RETURN, and the surrounding documentation
      // asserted (falsely) that "CryptoKey is not Structured Cloneable", so
      // a method returning one read as harmless (notme-bcbd74).
      //
      // What actually stopped delivery was workerd refusing to serialize
      // CryptoKey — measured, and a runtime behaviour no standard requires.
      // Non-extractability did not cover it: the held key is non-extractable
      // in every mode, which stops byte export but not USE, and a delivered
      // key still signs as this CA.
      //
      // It is `#getOrCreateSigningKey()` now. All fourteen call sites were
      // internal; the only external consumer was delegation-depth.do.test.ts,
      // which reads the stored JWK directly instead — a test forging
      // production's exact condition, not a caller being handed a key.
      //
      // The standard for the next removal: prefer taking a method off the
      // surface over relying on any property of the boundary.
    ).toBe(47);
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
// caller sees only their own, and workerd's serializer refuses CryptoKey (see
// rpc.cryptokey.isolation below — a workerd behaviour, not a W3C one) — but
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

// ── rpc.cryptokey.isolation ─────────────────────────────────────────────────
//
// THREAT_MODEL's "CryptoKey extraction" row names this test. It did not
// exist, and the mitigation the row asserted was wrong as stated: five sites
// claimed "CryptoKey is not Structured Cloneable" as a PLATFORM property
// needing no check. W3C WebCrypto declares `[Serializable] interface
// CryptoKey`, and Node clones a non-extractable Ed25519 private key happily
// — so as a statement about the web platform it is false, and a future
// change reasoned against it reasons from a false premise (notme-bcbd74).
//
// What is true is narrower and had never been measured: WORKERD's serializer
// refuses CryptoKey. Pinning it matters more than it first looks, because
// this is not a redundant second line of defence —
// `getOrCreateSigningKey()` is in the allow-list above and returns
// `{ signingKey: CryptoKey, verifyKey: CryptoKey, keyId }`, so a stub holder
// DOES reach a method that hands back the authority's private key, and the
// serializer is the only thing that stops delivery. Non-extractability does
// not cover it either: keys are non-extractable only in `ephemeral` mode and
// production runs `cf-managed`.
//
// If workerd ever aligns with the IDL, that changes from "hardened" to "key
// export endpoint", and it should break here loudly.
describe("rpc.cryptokey.isolation", () => {
  const edKeys = () =>
    crypto.subtle.generateKey({ name: "Ed25519" }, false, [
      "sign",
      "verify",
    ]) as Promise<CryptoKeyPair>;

  it("workerd refuses to serialize a CryptoKey at all", async () => {
    const { privateKey } = await edKeys();
    expect(privateKey.extractable).toBe(false);
    expect(() => structuredClone(privateKey)).toThrow(/serialize|clone/i);
  });

  it("...so a CryptoKey cannot cross a real RPC boundary", async () => {
    // The serializer runs before the method does, so the argument being of
    // the wrong type for getEpochPublicKey is irrelevant — and deliberate:
    // this probes the BOUNDARY, not a particular method's validation.
    const { privateKey } = await edKeys();
    const stub = env.SIGNING_AUTHORITY.get(
      env.SIGNING_AUTHORITY.idFromName("cryptokey-isolation"),
    );
    await expect(
      // @ts-expect-error probing the serializer with a deliberately wrong type
      stub.getEpochPublicKey(privateKey),
    ).rejects.toThrow(/DataCloneError|serialize/i);
  });

  it("...nor nested inside an argument object", async () => {
    // AuthService.authenticate's declared parameter is exactly this shape:
    // { mtlsCert, signingCert, mtlsKey: CryptoKey, signingKey: CryptoKey }.
    // Nesting does not help; the whole argument fails to serialize. Which
    // means that signature cannot be satisfied across a service binding at
    // all — see the note on authenticate() in worker.ts.
    const { privateKey } = await edKeys();
    const stub = env.SIGNING_AUTHORITY.get(
      env.SIGNING_AUTHORITY.idFromName("cryptokey-isolation"),
    );
    await expect(
      // @ts-expect-error probing the serializer with a deliberately wrong type
      stub.getEpochPublicKey({
        mtlsCert: "-----BEGIN CERTIFICATE-----",
        signingCert: "-----BEGIN CERTIFICATE-----",
        mtlsKey: privateKey,
        signingKey: privateKey,
      }),
    ).rejects.toThrow(/DataCloneError|serialize/i);
  });

  it("THE FIX: no method returning the authority's private key is on the surface", () => {
    // getOrCreateSigningKey() used to be here, returning
    // { signingKey: CryptoKey, verifyKey, keyId }. A stub holder called it and
    // the ONLY thing that stopped delivery was the serializer above — a
    // workerd behaviour no standard requires. It is #getOrCreateSigningKey()
    // now, so the property is "not returnable" rather than "undeliverable by
    // a quirk" (notme-eedc9c).
    expect(rpcSurface(SigningAuthority)).not.toContain("getOrCreateSigningKey");
  });

  it("...and no surface method hands back a CryptoKey by any other name", async () => {
    // The generic form, so the next method with a CryptoKey in its return
    // type is caught when it is written rather than when it is exploited.
    //
    // Every zero-argument method on the surface is called over a REAL stub.
    // Methods that need arguments fail for their own reasons and are ignored;
    // the only failure this cares about is the serializer refusing a
    // CryptoKey, which is precisely the signature of a method that tried to
    // return one.
    const stub = env.SIGNING_AUTHORITY.get(
      env.SIGNING_AUTHORITY.idFromName("cryptokey-return-sweep"),
    );
    const leaks: string[] = [];
    for (const name of rpcSurface(SigningAuthority)) {
      let result: unknown;
      try {
        result = await (stub as unknown as Record<string, () => Promise<unknown>>)[
          name
        ]!();
      } catch (e) {
        const msg = String((e as Error).message ?? e);
        if (/CryptoKey/.test(msg)) leaks.push(`${name}: ${msg}`);
        continue;
      }
      // A delivered CryptoKey would mean workerd started serializing them —
      // the day the old mitigation evaporates.
      const values = result && typeof result === "object" ? Object.values(result) : [];
      if (values.some((v) => v instanceof CryptoKey)) leaks.push(`${name}: returned a CryptoKey`);
    }
    expect(leaks, `methods returning key material: ${leaks.join(" | ")}`).toEqual([]);
  });

  it("the authority still signs — the key was hidden, not removed", async () => {
    // Negative control for the two above. If #getOrCreateSigningKey had been
    // broken by the rename rather than merely made private, every assertion
    // in this describe would pass over a DO that can no longer do anything,
    // and the file would look hardened because it was inert.
    const stub = env.SIGNING_AUTHORITY.get(
      env.SIGNING_AUTHORITY.idFromName("cryptokey-still-signs"),
    );
    const pem = await stub.getCACertificatePem();
    expect(pem).toContain("BEGIN CERTIFICATE");
    const jwk = await stub.getPublicKeyJwk();
    expect(jwk.crv).toBe("Ed25519");
  });
});
