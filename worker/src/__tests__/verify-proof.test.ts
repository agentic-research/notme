/**
 * verify-proof.test.ts — OIDC + X.509 proof verification.
 * Maps to THREAT_MODEL.md:
 *   oidc.audience.confused-deputy
 *   oidc.connections.audience-binding
 *
 * The trust and audience checks run BEFORE any network/JWKS call, so a token
 * with a mismatched audience is refused without a fetch. Each issuer has its
 * own audience pin (notme-0a1ee8); the Google cases below configure Google's
 * client id, so they test Google's pin rather than an untrusted issuer.
 */

import { describe, expect, it, beforeAll } from "vitest";
import { issuerAudiences, verifyOIDC, verifyProof, selectVerifyingKey } from "../auth/verify-proof";
import { OID_EPOCH } from "../cert-authority";
import { fakeIssuer } from "./helpers/oidc-issuer";

/** The epoch stamped into this suite's leaf cert. */
const TEST_EPOCH = 1;

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
    await expect(verifyOIDC(token, issuerAudiences({ GOOGLE_CLIENT_ID: "notme-client.apps.googleusercontent.com" }))).rejects.toThrow(
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
    await expect(verifyOIDC(token, issuerAudiences({ GOOGLE_CLIENT_ID: "notme-client.apps.googleusercontent.com" }))).rejects.toThrow(
      /wrong audience/,
    );
  });

  it("rejects token with missing aud claim when expected is set", async () => {
    const token = makeJwt({
      iss: "https://accounts.google.com",
      sub: "victim@gmail.com",
      exp: FUTURE_EXP,
    });
    await expect(verifyOIDC(token, issuerAudiences({ GOOGLE_CLIENT_ID: "notme-client.apps.googleusercontent.com" }))).rejects.toThrow(
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
    await expect(verifyOIDC(token, issuerAudiences({ GOOGLE_CLIENT_ID: "notme-client.apps.googleusercontent.com" }))).rejects.toThrow(
      /token expired/,
    );
  });
});

describe("oidc.issuer.allowlist (notme-ae65a0, M1)", () => {
  // Google is trusted only when the deployment sets GOOGLE_CLIENT_ID, and then
  // pinned to that client id (notme-0a1ee8). The baseline map has no Google
  // entry, so Google is refused at the trust check.

  it("rejects Google as untrusted issuer when GOOGLE_CLIENT_ID is unset", async () => {
    // Even with aud=notme.bot, which every baseline issuer accepts: trust is
    // per issuer, and Google has no entry.
    const token = makeJwt({
      iss: "https://accounts.google.com",
      sub: "alice@gmail.com",
      aud: "notme.bot",
      exp: FUTURE_EXP,
    });
    await expect(verifyOIDC(token, issuerAudiences({}))).rejects.toThrow(
      /untrusted issuer/,
    );
  });

  // These two used to send a junk-signed token and assert the error was NOT
  // the trust error, which meant fetching live JWKS from the real issuer and
  // passing on whatever the network did (notme-3fc74b). Now the issuer is a
  // local fixture: the token verifies end to end, and the verifier asked the
  // fixture for keys. That is positive evidence the issuer was trusted.
  it("accepts auth.notme.bot as trusted issuer: the token verifies against its JWKS", async () => {
    const issuer = await fakeIssuer("https://auth.notme.bot");
    const token = await issuer.token({ sub: "principal-test", aud: "notme.bot" });
    const id = await verifyOIDC(token, issuerAudiences({}));
    expect(id).toMatchObject({ type: "oidc", issuer: "https://auth.notme.bot", subject: "principal-test" });
    expect(issuer.requests).toContain("https://auth.notme.bot/.well-known/jwks");
  });

  it("accepts GHA token issuer as trusted (workflow can request aud=notme.bot)", async () => {
    const issuer = await fakeIssuer("https://token.actions.githubusercontent.com");
    const sub = "repo:agentic-research/notme:ref:refs/heads/main";
    const token = await issuer.token({ sub, aud: "notme.bot" });
    const id = await verifyOIDC(token, issuerAudiences({}));
    expect(id).toMatchObject({ issuer: "https://token.actions.githubusercontent.com", subject: sub });
    expect(issuer.requests).toContain("https://token.actions.githubusercontent.com/.well-known/jwks");
  });

  it("rejects an attacker-controlled iss that's not in the allowlist", async () => {
    const token = makeJwt({
      iss: "https://attacker.example",
      sub: "anyone",
      aud: "notme.bot",
      exp: FUTURE_EXP,
    });
    await expect(verifyOIDC(token, issuerAudiences({}))).rejects.toThrow(
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
      verifyProof({ type: "oidc", token }, undefined, issuerAudiences({ GOOGLE_CLIENT_ID: "notme-client.apps.googleusercontent.com" })),
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
      verifyProof({ type: "oidc", token }, undefined, issuerAudiences({ GOOGLE_CLIENT_ID: "notme-client.apps.googleusercontent.com" })),
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

    // Carries OID_EPOCH because verifyX509 now REFUSES a cert that cannot be
    // checked against rotation (notme-77a024). This suite is about the CA-PEM
    // SHAPE, so the cert is made epoch-bearing rather than the epoch check
    // relaxed — weakening a revocation control to keep an unrelated test green
    // is how controls get lost.
    const { Extension } = await import("@peculiar/x509");
    const leafCert = await X509CertificateGenerator.create({
      subject: "CN=test-principal",
      issuer: "CN=test-ca",
      notBefore: now,
      notAfter: expires,
      signingAlgorithm: ED25519,
      publicKey: leaf.publicKey,
      signingKey: ca.privateKey,
      serialNumber: "02",
      extensions: [
        // DER INTEGER 1 — matches TEST_EPOCH below.
        new Extension(OID_EPOCH, false, new Uint8Array([0x02, 0x01, 0x01])),
      ],
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
      issuerAudiences({}),
      TEST_EPOCH,
    );
    expect(identity.type).toBe("x509");
    expect(identity.subject).toBe("test-principal");
  });

  it("rejects when caPublicKeyPem is SPKI 'PUBLIC KEY' instead of CERTIFICATE", async () => {
    // The leaf cert IS valid, so verifyX509 reaches the CA-parse step.
    // Passing SPKI there throws inside `new X509Certificate(...)` with
    // a recognisable parse error — the bug class rosary-9b7d67 fixed.
    await expect(
      verifyProof(
        { type: "x509", cert: leafCertPem },
        caSpkiPem,
        issuerAudiences({}),
        TEST_EPOCH,
      ),
    ).rejects.toThrow();
  });
});

describe("oidc.issuer.audience-map — each issuer carries its own audience pin (notme-0a1ee8)", () => {
  const CLIENT_ID = "1234567890-notme.apps.googleusercontent.com";

  it("the baseline map is the old single pin, per issuer: GitHub and auth.notme.bot both pin notme.bot", () => {
    // Byte-identical GitHub behaviour: same issuers, same audience, nothing else.
    expect(issuerAudiences({})).toEqual({
      "https://auth.notme.bot": "notme.bot",
      "https://token.actions.githubusercontent.com": "notme.bot",
    });
  });

  it("adds Google only when GOOGLE_CLIENT_ID is set, pinned to that client id", () => {
    expect(issuerAudiences({ GOOGLE_CLIENT_ID: CLIENT_ID })).toEqual({
      "https://auth.notme.bot": "notme.bot",
      "https://token.actions.githubusercontent.com": "notme.bot",
      "https://accounts.google.com": CLIENT_ID,
    });
    // Blank or not a string is unset, never "trusted with no audience".
    for (const v of ["", "   ", undefined, 42]) {
      expect(issuerAudiences({ GOOGLE_CLIENT_ID: v })).not.toHaveProperty(["https://accounts.google.com"]);
    }
  });

  it("verifies a Google token whose aud is the configured client id", async () => {
    const google = await fakeIssuer("https://accounts.google.com");
    const token = await google.token({ sub: "alice-google-sub", aud: CLIENT_ID });
    const id = await verifyOIDC(token, issuerAudiences({ GOOGLE_CLIENT_ID: CLIENT_ID }));
    expect(id).toMatchObject({ issuer: "https://accounts.google.com", subject: "alice-google-sub" });
  });

  it("refuses that same Google token as untrusted when GOOGLE_CLIENT_ID is unset", async () => {
    const google = await fakeIssuer("https://accounts.google.com");
    const token = await google.token({ sub: "alice-google-sub", aud: CLIENT_ID });
    await expect(verifyOIDC(token, issuerAudiences({}))).rejects.toThrow(/untrusted issuer/);
  });

  it("pins do not bleed across issuers: a GitHub token with Google's audience is refused", async () => {
    const gha = await fakeIssuer("https://token.actions.githubusercontent.com");
    const token = await gha.token({ sub: "repo:o/r:ref:refs/heads/main", aud: CLIENT_ID });
    await expect(verifyOIDC(token, issuerAudiences({ GOOGLE_CLIENT_ID: CLIENT_ID }))).rejects.toThrow(
      "wrong audience: expected notme.bot, got " + CLIENT_ID,
    );
  });

  it("a Google token carrying aud=notme.bot is refused: Google's pin is its client id", async () => {
    const google = await fakeIssuer("https://accounts.google.com");
    const token = await google.token({ sub: "alice-google-sub", aud: "notme.bot" });
    await expect(verifyOIDC(token, issuerAudiences({ GOOGLE_CLIENT_ID: CLIENT_ID }))).rejects.toThrow(
      /wrong audience/,
    );
  });

  it.each(["constructor", "__proto__", "toString", "hasOwnProperty"])(
    "an iss of %j does not resolve through Object.prototype",
    async (iss) => {
      const token = makeJwt({ iss, sub: "x", aud: "notme.bot", exp: FUTURE_EXP });
      await expect(verifyOIDC(token, issuerAudiences({}))).rejects.toThrow(/untrusted issuer/);
    },
  );

  it("an INHERITED entry is not trust: only the map's own issuers count (prototype pollution)", async () => {
    const polluted = Object.create({ "https://inherited.example": "notme.bot" }) as Record<string, string>;
    const token = makeJwt({ iss: "https://inherited.example", sub: "x", aud: "notme.bot", exp: FUTURE_EXP });
    await expect(verifyOIDC(token, polluted)).rejects.toThrow(/untrusted issuer/);
  });

  it("an entry with no usable audience is untrusted, not a wildcard", async () => {
    const token = makeJwt({ iss: "https://idp.example", sub: "x", aud: "", exp: FUTURE_EXP });
    for (const aud of ["", [] as string[], [""]]) {
      await expect(verifyOIDC(token, { "https://idp.example": aud })).rejects.toThrow(/untrusted issuer/);
    }
  });
});

describe("selectVerifyingKey — kid selection / key-confusion guard (notme-692274)", () => {
  const k = (kid: string) => ({ kid, kty: "OKP" });

  it("selects the key whose kid matches the header", () => {
    expect(selectVerifyingKey([k("a"), k("b")], "b")).toEqual(k("b"));
  });

  it("single-key JWKS: an omitted kid unambiguously uses the one key", () => {
    expect(selectVerifyingKey([k("only")], undefined)).toEqual(k("only"));
  });

  it("multi-key JWKS + omitted kid THROWS — no silent keys[0] key-confusion", () => {
    // The rotation-grace case: current + previous key both published. Picking
    // keys[0] could verify a token against the wrong key.
    expect(() => selectVerifyingKey([k("current"), k("prev")], undefined)).toThrow(
      /kid required/,
    );
  });

  it("present kid matching no key returns undefined (caller: unknown key id)", () => {
    expect(selectVerifyingKey([k("a"), k("b")], "z")).toBeUndefined();
  });
});
