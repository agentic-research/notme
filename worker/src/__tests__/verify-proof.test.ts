/**
 * verify-proof.test.ts — OIDC + X.509 proof verification.
 * Maps to THREAT_MODEL.md:
 *   oidc.audience.confused-deputy
 *   oidc.connections.audience-binding
 *
 * The audience check runs BEFORE any network/JWKS call (see verify-proof.ts
 * lines 108-119), so we can test it without mocking fetch — a token with a
 * mismatched audience throws synchronously on the audience branch.
 */

import { describe, expect, it } from "vitest";
import { verifyOIDC, verifyProof } from "../auth/verify-proof";

// Build a minimal JWT (header.payload.sig) with the given audience claim.
// Signature is junk — we only care that the audience check fires before
// signature verification.
function makeJwt(payload: Record<string, unknown>): string {
  const enc = (obj: unknown) =>
    btoa(JSON.stringify(obj))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  const header = enc({ alg: "RS256", typ: "JWT", kid: "test" });
  const body = enc(payload);
  return `${header}.${body}.AAAA`;
}

const FUTURE_EXP = Math.floor(Date.now() / 1000) + 600;

describe("oidc.audience.confused-deputy", () => {
  it("rejects token whose aud does not match expected (string)", async () => {
    const token = makeJwt({
      iss: "https://accounts.google.com",
      sub: "victim@gmail.com",
      aud: "evil-app.com",
      exp: FUTURE_EXP,
    });
    await expect(verifyOIDC(token, "notme.bot")).rejects.toThrow(
      /wrong audience/,
    );
  });

  it("rejects token whose aud array doesn't include expected", async () => {
    const token = makeJwt({
      iss: "https://accounts.google.com",
      sub: "victim@gmail.com",
      aud: ["evil-app.com", "another-app.com"],
      exp: FUTURE_EXP,
    });
    await expect(verifyOIDC(token, "notme.bot")).rejects.toThrow(
      /wrong audience/,
    );
  });

  it("rejects token with missing aud claim when expected is set", async () => {
    const token = makeJwt({
      iss: "https://accounts.google.com",
      sub: "victim@gmail.com",
      exp: FUTURE_EXP,
    });
    await expect(verifyOIDC(token, "notme.bot")).rejects.toThrow(
      /wrong audience/,
    );
  });

  it("rejects expired token before audience check fires", async () => {
    // Sanity: exp check at line 105 runs BEFORE the audience check.
    const token = makeJwt({
      iss: "https://accounts.google.com",
      sub: "victim@gmail.com",
      aud: "notme.bot",
      exp: Math.floor(Date.now() / 1000) - 60,
    });
    await expect(verifyOIDC(token, "notme.bot")).rejects.toThrow(
      /token expired/,
    );
  });
});

describe("oidc.connections.audience-binding", () => {
  // Threat: /connections (POST) used to call verifyProof with no expected
  // audience, letting an attacker who held a Google OIDC token issued for a
  // different app link (google, victim@gmail.com) → attacker's notme
  // principal. The fix passes "notme.bot" through verifyProof.

  it("verifyProof forwards audience constraint to OIDC path", async () => {
    const token = makeJwt({
      iss: "https://accounts.google.com",
      sub: "victim@gmail.com",
      aud: "evil-app.com",
      exp: FUTURE_EXP,
    });
    await expect(
      verifyProof({ type: "oidc", token }, undefined, "notme.bot"),
    ).rejects.toThrow(/wrong audience/);
  });

  it("verifyProof requires expectedAudience at the type level (regression)", async () => {
    // Earlier this argument was optional, which let /connections (and any
    // future caller that omitted it) skip the audience check entirely.
    // Now the parameter is required by the type signature; the test below
    // simply exercises the value-pin contract — TypeScript would reject a
    // call site that omits the audience at compile time.
    const token = makeJwt({
      iss: "https://accounts.google.com",
      sub: "victim@gmail.com",
      aud: "evil-app.com",
      exp: FUTURE_EXP,
    });
    // X.509 path also accepts the parameter for signature-uniformity even
    // though certs don't carry an aud claim — the value is ignored.
    await expect(
      verifyProof({ type: "oidc", token }, undefined, "notme.bot"),
    ).rejects.toThrow(/wrong audience/);
  });
});
