/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * jwt-signer.do.test.ts — delegated JWT signing against a real
 * SigningAuthority in real workerd (ADR-015).
 *
 * The test that matters is the FIRST one. Everything else is a footgun check;
 * that one is the reason the feature is designed the way it is.
 */

import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

const ISSUER = "https://cluster.example";

function b64url(s: string): string {
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const seg = (o: unknown) => b64url(JSON.stringify(o));

function authority() {
  return env.SIGNING_AUTHORITY.get(
    env.SIGNING_AUTHORITY.idFromName("jwt-test"),
  );
}

describe("delegated JWT signing — real DO (ADR-015)", () => {
  it("CANNOT mint a token that verifies as one of notme's own", async () => {
    // THE BYPASS THIS DESIGN EXISTS TO PREVENT.
    //
    // notme's own access tokens are at+jwt, iss=https://auth.notme.bot,
    // signed with the CA master. The SDK leaves `issuer` unchecked by default.
    // If delegated signing used the master key, this exact payload would
    // produce a token every notme resource server accepts with
    // scope=authorityManage.
    //
    // Two independent things stop it: the reserved `typ` and, decisively, the
    // signature being made by a DIFFERENT key. This asserts the second — the
    // one that holds even if every claim check were removed.
    const stub = authority();
    const { publicRawB64 } = await stub.getDelegatedJwtKey(ISSUER);

    const res = await stub.signDelegatedJwt({
      issuer: ISSUER,
      headerB64: seg({ alg: "EdDSA", typ: "JWT" }),
      payloadB64: seg({ sub: "attacker", scope: "authorityManage" }),
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    // The delegated public key is NOT the authority's master public key.
    const masterRaw = await stub.getPublicKeyRawB64();
    expect(publicRawB64).not.toBe(masterRaw);

    // And the signature does not verify under the master key — so notme's own
    // JWKS cannot be used to accept this token.
    const masterKey = await crypto.subtle.importKey(
      "raw",
      Uint8Array.from(atob(masterRaw), (c) => c.charCodeAt(0)),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    const input = new TextEncoder().encode(
      `${seg({ alg: "EdDSA", typ: "JWT" })}.${seg({ sub: "attacker", scope: "authorityManage" })}`,
    );
    expect(
      await crypto.subtle.verify(
        { name: "Ed25519" },
        masterKey,
        res.signature,
        input,
      ),
    ).toBe(false);
  });

  it("produces a signature that verifies under the DELEGATED key", async () => {
    const stub = authority();
    const { publicRawB64 } = await stub.getDelegatedJwtKey(ISSUER);
    const header = seg({ alg: "EdDSA", typ: "JWT" });
    const payload = seg({ sub: "user-1", aud: "api", iss: ISSUER });

    const res = await stub.signDelegatedJwt({
      issuer: ISSUER,
      headerB64: header,
      payloadB64: payload,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const key = await crypto.subtle.importKey(
      "raw",
      Uint8Array.from(atob(publicRawB64), (c) => c.charCodeAt(0)),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    expect(
      await crypto.subtle.verify(
        { name: "Ed25519" },
        key,
        res.signature,
        new TextEncoder().encode(`${header}.${payload}`),
      ),
    ).toBe(true);
  });

  it("is stable per issuer and distinct across issuers", async () => {
    // Stable: cloister publishes one JWKS per issuer and it must not move.
    // Distinct: two delegated issuers must not share a blast radius.
    const stub = authority();
    const a1 = await stub.getDelegatedJwtKey(ISSUER);
    const a2 = await stub.getDelegatedJwtKey(ISSUER);
    const b = await stub.getDelegatedJwtKey("https://other.example");
    expect(a1.kid).toBe(a2.kid);
    expect(a1.publicRawB64).toBe(a2.publicRawB64);
    expect(b.kid).not.toBe(a1.kid);
    expect(b.publicRawB64).not.toBe(a1.publicRawB64);
  });

  it("refuses the reserved at+jwt typ", async () => {
    const res = await authority().signDelegatedJwt({
      issuer: ISSUER,
      headerB64: seg({ alg: "EdDSA", typ: "at+jwt" }),
      payloadB64: seg({ sub: "x" }),
    });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.code).toBe("TYP_RESERVED");
  });

  it("refuses a forged iss", async () => {
    // Derived, never received: the caller does not get to say who issued.
    const res = await authority().signDelegatedJwt({
      issuer: ISSUER,
      headerB64: seg({ alg: "EdDSA", typ: "JWT" }),
      payloadB64: seg({ iss: "https://auth.notme.bot", sub: "x" }),
    });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.code).toBe("ISS_MISMATCH");
  });

  it("refuses a delegated cnf claim", async () => {
    // A delegated issuer must not mint DPoP-bound tokens claiming key-binding
    // this authority never established.
    const res = await authority().signDelegatedJwt({
      issuer: ISSUER,
      headerB64: seg({ alg: "EdDSA", typ: "JWT" }),
      payloadB64: seg({ sub: "x", cnf: { jkt: "whatever" } }),
    });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.code).toBe("CNF_FORBIDDEN");
  });

  it("refuses a mismatched kid", async () => {
    const res = await authority().signDelegatedJwt({
      issuer: ISSUER,
      headerB64: seg({ alg: "EdDSA", typ: "JWT", kid: "someone-elses-kid" }),
      payloadB64: seg({ sub: "x" }),
    });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.code).toBe("KID_MISMATCH");
  });

  it("refuses non-EdDSA and malformed segments", async () => {
    const stub = authority();
    for (const [header, payload, code] of [
      [seg({ alg: "HS256", typ: "JWT" }), seg({ sub: "x" }), "ALG_NOT_EDDSA"],
      [seg({ alg: "none" }), seg({ sub: "x" }), "ALG_NOT_EDDSA"],
      ["not+base64url/", seg({ sub: "x" }), "NOT_BASE64URL"],
      [b64url("{not json"), seg({ sub: "x" }), "NOT_JSON"],
      [seg([1, 2]), seg({ sub: "x" }), "HEADER_NOT_OBJECT"],
      [seg({ alg: "EdDSA" }), seg([1, 2]), "PAYLOAD_NOT_OBJECT"],
    ] as Array<[string, string, string]>) {
      const res = await stub.signDelegatedJwt({
        issuer: ISSUER,
        headerB64: header,
        payloadB64: payload,
      });
      expect(res.ok, `expected ${code}`).toBe(false);
      if (res.ok) continue;
      expect(res.code).toBe(code);
    }
  });

  it("never returns private key material", async () => {
    const stub = authority();
    const out = await stub.getDelegatedJwtKey(ISSUER);
    expect(Object.keys(out).sort()).toEqual(["kid", "publicRawB64"]);
    const signed = await stub.signDelegatedJwt({
      issuer: ISSUER,
      headerB64: seg({ alg: "EdDSA", typ: "JWT" }),
      payloadB64: seg({ sub: "x" }),
    });
    expect(signed.ok).toBe(true);
    if (!signed.ok) return;
    expect(Object.keys(signed).sort()).toEqual(["kid", "ok", "signature"]);
  });
});
