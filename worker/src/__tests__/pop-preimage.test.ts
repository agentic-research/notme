/**
 * pop-preimage.test.ts — proof-of-possession is computed over the binding
 * PRE-IMAGE, not over its digest (notme-a011d2).
 *
 * THE DEFECT, found by signet's v0.3.0-rc.2 release run against production
 * (run 31065683262, 2026-08-06T02:29Z): every PoP site handed
 * `crypto.subtle.verify({name:"ECDSA", hash:"SHA-256"}, …)` the value
 * `bindingPayload = SHA-256(bindingInput)`. WebCrypto applies SHA-256 to
 * whatever it is given, so the message actually verified was
 * SHA-256(SHA-256(bindingInput)) — hashed twice.
 *
 * Go's `ecdsa.Sign(rand, priv, digest)` takes a digest, so a conformant Go
 * signer computing `sha256(bindingInput)` produces a signature over ONE hash.
 * It could never verify here, and no non-WebCrypto signer ever could.
 *
 * WHY IT SURVIVED: notme's own action signs with `wc.subtle.sign` over the
 * same `bindingPayload`, so it double-hashes too. Signer and verifier were
 * consistently wrong, and a round trip between them passes. That is a fixed
 * point, not a conformance check — the identical failure recorded for the
 * receipt encoder in receipts/canonical-cbor.ts, where fixtures were built
 * with the encoder under test.
 *
 * WHICH IS WHY THE FIXTURE BELOW IS STATIC AND FOREIGN. It was produced by
 * node:crypto — a non-WebCrypto signer that hashes exactly once, matching Go —
 * and pasted in. Nothing in this repo can regenerate it, so a change that
 * reintroduces double-hashing on BOTH sides cannot make this test pass again.
 *
 *   P-256:   sign("sha256", bindingInput, {dsaEncoding: "ieee-p1363"})
 *   Ed25519: sign(null, bindingInput, key)          // PureEdDSA over message
 *
 * `ieee-p1363` is raw r||s, which is what WebCrypto ECDSA expects; node's
 * default is DER, which would fail for an unrelated reason and mask this one.
 */

import { describe, expect, it } from "vitest";
import { ED25519 } from "../platform";

/** Generated once by node:crypto (see notme-a011d2). Do not regenerate. */
const FIXTURE = {
  mtlsPem: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErQC/YXebA2HRat4HXTpVzxPvPVRi
rTPHgW1xcwvWXSx+hQx5FM1W6GMbimAWjoS8ebmi59igaw70BSsmRN+3dA==
-----END PUBLIC KEY-----`,
  signingPem: `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAUf4uLZXWRlI+iqYmj4V0JcbCRIhc8gM5J+7cZ7DyUxo=
-----END PUBLIC KEY-----`,
  mtlsProof:
    "lnBr1n-meWFJ7HSPHHrvkHQlNG9t_uUgjwco75BlVx8nlhfeyPmcwaYw_OdyUwplQt6n9OLGzx1jwh_qiB5uqg",
  signingProof:
    "KTSOfUHZkQBaNvtaOihWLc-1kHeVrPEXrWq-oJUn6ieHRlccFHSKKFRbkMm3FtyNHo2WxpCSd9gpIsdpeBjJBw",
};

function b64uToBytes(s: string): Uint8Array {
  const norm = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(norm + "=".repeat((4 - (norm.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function pemToDer(pem: string): Uint8Array {
  return Uint8Array.from(
    atob(pem.replace(/-----[^-]+-----/g, "").replace(/\s/g, "")),
    (c) => c.charCodeAt(0),
  );
}

/**
 * The fixture's binding, rebuilt the way the /cert path does:
 * bindingInput = mtls_spki || signing_spki (no OIDC JWT on that path).
 */
async function fixtureBinding(): Promise<{
  bindingInput: Uint8Array;
  mtlsKey: CryptoKey;
  signingKey: CryptoKey;
}> {
  const mtlsSpki = pemToDer(FIXTURE.mtlsPem);
  const signingSpki = pemToDer(FIXTURE.signingPem);
  const bindingInput = new Uint8Array(mtlsSpki.length + signingSpki.length);
  bindingInput.set(mtlsSpki, 0);
  bindingInput.set(signingSpki, mtlsSpki.length);

  return {
    bindingInput,
    mtlsKey: await crypto.subtle.importKey(
      "spki",
      mtlsSpki,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    ),
    signingKey: await crypto.subtle.importKey("spki", signingSpki, ED25519, false, [
      "verify",
    ]),
  };
}

describe("PoP binding pre-image (notme-a011d2)", () => {
  it("is the DIGEST that fails and the PRE-IMAGE that verifies", async () => {
    // The root cause, asserted directly against WebCrypto rather than argued.
    // If this ever inverts, the diagnosis behind the fix was wrong.
    const { bindingInput, mtlsKey } = await fixtureBinding();
    const proof = b64uToBytes(FIXTURE.mtlsProof);
    const algo = { name: "ECDSA", hash: "SHA-256" };

    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-256", bindingInput),
    );

    expect(
      await crypto.subtle.verify(algo, mtlsKey, proof, digest),
      "verifying over the digest double-hashes — this is the shipped bug",
    ).toBe(false);
    expect(
      await crypto.subtle.verify(algo, mtlsKey, proof, bindingInput),
      "verifying over the pre-image is what a Go signer produces",
    ).toBe(true);
  });

  it("accepts a foreign-signed proof through the shared verifier", async () => {
    // The contract. Three handlers (/cert/gha, /cert, /cert/passkey) each had
    // their own inline copy of this check, which is how the convention
    // diverged unnoticed; the fix is one verifier they all call.
    const { verifyPopProofs } = await import("../auth/pop");
    const { bindingInput, mtlsKey, signingKey } = await fixtureBinding();

    await expect(
      verifyPopProofs(bindingInput, mtlsKey, signingKey, {
        mtls: FIXTURE.mtlsProof,
        signing: FIXTURE.signingProof,
      }),
    ).resolves.toEqual({ ok: true });
  });

  it("rejects a proof over the wrong binding, and names which key failed", async () => {
    const { verifyPopProofs } = await import("../auth/pop");
    const { mtlsKey, signingKey } = await fixtureBinding();

    const result = await verifyPopProofs(
      new TextEncoder().encode("a different binding entirely"),
      mtlsKey,
      signingKey,
      { mtls: FIXTURE.mtlsProof, signing: FIXTURE.signingProof },
    );
    expect(result).toEqual({ ok: false, algorithm: "P-256" });
  });

  it("treats undecodable proof bytes as a failed proof, not a crash", async () => {
    // Every call site wrapped verify in try/catch and turned a throw into a
    // 401. Keeping that behaviour inside the verifier is what lets the call
    // sites drop their duplicated error handling.
    const { verifyPopProofs } = await import("../auth/pop");
    const { bindingInput, mtlsKey, signingKey } = await fixtureBinding();

    const result = await verifyPopProofs(bindingInput, mtlsKey, signingKey, {
      mtls: "!!!not base64!!!",
      signing: FIXTURE.signingProof,
    });
    expect(result).toEqual({ ok: false, algorithm: "P-256" });
  });
});
