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

import { describe, expect, it, beforeAll } from "vitest";
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

describe("oidc.issuer.allowlist (notme-ae65a0, M1)", () => {
  // Google is intentionally absent from TRUSTED_ISSUERS — Google ID tokens
  // carry aud=<client-id>.apps.googleusercontent.com so they can never match
  // the "notme.bot" audience pin used by /connections, /auth/oidc/login,
  // /join. Including Google would be misleading. A proper fix needs a
  // per-issuer audience map (filed elsewhere); until then, failing fast at
  // the issuer-trust check gives a clearer error than "wrong audience" on
  // every legitimate Google token.

  it("rejects Google as untrusted issuer when audience would otherwise pass", async () => {
    // Audience matches what /connections expects — would pass the audience
    // check. The trust check at fetchJWKS fires next and surfaces the
    // architectural gap clearly.
    const token = makeJwt({
      iss: "https://accounts.google.com",
      sub: "alice@gmail.com",
      aud: "notme.bot",
      exp: FUTURE_EXP,
    });
    await expect(verifyOIDC(token, "notme.bot")).rejects.toThrow(
      /untrusted issuer/,
    );
  });

  it("accepts auth.notme.bot as trusted issuer (still 'untrusted' would fail later)", async () => {
    // Self-issued tokens get past trust + audience and proceed to JWKS
    // fetch + signature verify. We can't run those without a network or
    // mocked JWKS — but reaching that step (different error: JWKS fetch
    // failure rather than "untrusted issuer") proves the issuer was
    // accepted. Test asserts the failure message is NOT the trust error.
    const token = makeJwt({
      iss: "https://auth.notme.bot",
      sub: "principal-test",
      aud: "notme.bot",
      exp: FUTURE_EXP,
    });
    let err: Error | null = null;
    try {
      await verifyOIDC(token, "notme.bot");
    } catch (e) {
      err = e as Error;
    }
    expect(err).toBeTruthy();
    expect(err!.message).not.toMatch(/untrusted issuer/);
  });

  it("accepts GHA token issuer as trusted (workflow can request aud=notme.bot)", async () => {
    const token = makeJwt({
      iss: "https://token.actions.githubusercontent.com",
      sub: "repo:agentic-research/notme:ref:refs/heads/main",
      aud: "notme.bot",
      exp: FUTURE_EXP,
    });
    let err: Error | null = null;
    try {
      await verifyOIDC(token, "notme.bot");
    } catch (e) {
      err = e as Error;
    }
    expect(err).toBeTruthy();
    expect(err!.message).not.toMatch(/untrusted issuer/);
  });

  it("rejects an attacker-controlled iss that's not in the allowlist", async () => {
    const token = makeJwt({
      iss: "https://attacker.example",
      sub: "anyone",
      aud: "notme.bot",
      exp: FUTURE_EXP,
    });
    await expect(verifyOIDC(token, "notme.bot")).rejects.toThrow(
      /untrusted issuer/,
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

describe("oidc.x509.ca-pem-shape", () => {
  // Threat: caller passes the CA's bare SPKI PEM ("PUBLIC KEY") to
  // verifyX509 instead of the CA's X.509 CERTIFICATE PEM. The function
  // does `new X509Certificate(caPublicKeyPem)` which fails on SPKI input,
  // producing 401 on every legitimate cert. This is rosary-9b7d67.
  //
  // The test below uses a well-formed leaf cert (minted in beforeAll
  // from a real CA keypair) as the user-cert input — so verifyX509
  // gets PAST the leaf-cert parse and fails specifically at the
  // CA-cert parse step, which is the path the bug actually affected.

  let leafCertPem: string;
  let caCertPem: string;
  let caSpkiPem: string;

  beforeAll(async () => {
    const { X509CertificateGenerator } = await import("@peculiar/x509");
    const ED25519 = "Ed25519" as any;

    const ca = (await crypto.subtle.generateKey(ED25519, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;

    const leaf = (await crypto.subtle.generateKey(ED25519, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;

    const now = new Date();
    const expires = new Date(now.getTime() + 5 * 60 * 1000);

    const caCert = await X509CertificateGenerator.create({
      subject: "CN=test-ca",
      issuer: "CN=test-ca",
      notBefore: now,
      notAfter: expires,
      signingAlgorithm: ED25519,
      publicKey: ca.publicKey,
      signingKey: ca.privateKey,
      serialNumber: "01",
    });
    caCertPem = caCert.toString("pem");

    const leafCert = await X509CertificateGenerator.create({
      subject: "CN=test-principal",
      issuer: "CN=test-ca",
      notBefore: now,
      notAfter: expires,
      signingAlgorithm: ED25519,
      publicKey: leaf.publicKey,
      signingKey: ca.privateKey,
      serialNumber: "02",
    });
    leafCertPem = leafCert.toString("pem");

    // Build a SPKI "PUBLIC KEY" PEM from the CA's public key — the
    // wrong shape that the bug fed to verifyX509 as caPublicKeyPem.
    const spki = (await crypto.subtle.exportKey(
      "spki",
      ca.publicKey,
    )) as ArrayBuffer;
    const spkiB64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
    const spkiLines = spkiB64.match(/.{1,64}/g)!.join("\n");
    caSpkiPem = `-----BEGIN PUBLIC KEY-----\n${spkiLines}\n-----END PUBLIC KEY-----`;
  });

  it("succeeds when caPublicKeyPem is the CA CERTIFICATE PEM (control)", async () => {
    // Sanity: the well-formed leaf cert + correctly-shaped CA cert PEM
    // should validate. Without this control, a "rejects" assertion in
    // the next case might be passing for the wrong reason.
    const identity = await verifyProof(
      { type: "x509", cert: leafCertPem },
      caCertPem,
      "notme.bot",
    );
    expect(identity.type).toBe("x509");
    expect(identity.subject).toBe("test-principal");
  });

  it("rejects when caPublicKeyPem is SPKI 'PUBLIC KEY' instead of CERTIFICATE", async () => {
    // The leaf cert IS valid, so verifyX509 reaches the CA-parse step.
    // Passing SPKI there throws inside `new X509Certificate(...)` with
    // a recognisable parse error — the bug class rosary-9b7d67 fixed.
    await expect(
      verifyProof({ type: "x509", cert: leafCertPem }, caSpkiPem, "notme.bot"),
    ).rejects.toThrow();
  });
});
