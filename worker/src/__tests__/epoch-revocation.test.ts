/**
 * epoch-revocation.test.ts — rotating the CA epoch must actually invalidate
 * certificates issued under the old one (notme-77a024).
 *
 * WHAT THE AUDIT FOUND. `OID_EPOCH` is WRITTEN into every certificate
 * (`cert-authority.ts:326`) and READ NOWHERE. `rotate()` bumps the authority's
 * epoch and archives the outgoing public key. And `verifyX509` — the function
 * that decides whether a presented certificate is acceptable — checks
 * `notBefore`/`notAfter` and the CA signature, and never looks at the epoch.
 *
 * So the emergency lever ADR-008 documents does nothing:
 *
 *   §418: "For emergency revocation (CA compromise, credential theft within
 *          the 5-minute window): increment the CA epoch. All certs signed with
 *          the previous epoch are immediately invalid."
 *   §420: "Epoch verification policy: if cert.epoch < bundle.epoch, the cert
 *          is REJECTED. The grace window (if any) is a deployment-time
 *          configuration, not a protocol-level default."
 *
 * Two documents describe revocation as working. Nothing revoked anything.
 *
 * ── DESIGN NOTES THIS PINS ──
 *
 * STRICT, NO DEFAULT GRACE. §420 is explicit that grace is deployment
 * configuration rather than a protocol default, so the default is `<` and a
 * cert one epoch behind is refused. A default grace would mean the emergency
 * lever does not take effect at the moment it is pulled, which is the only
 * moment it matters.
 *
 * THE EPOCH IS REQUIRED, NOT OPTIONAL. A verifier that does not know the
 * current epoch cannot make a revocation decision, so it must REFUSE rather
 * than skip. An optional parameter would reproduce this repo's most common
 * defect — a control that silently does nothing when unwired, which is exactly
 * how `checkRevocation` came to have zero call sites while two documents
 * claimed it ran.
 *
 * A CERT WITH NO EPOCH IS REFUSED for the same reason: it cannot be evaluated
 * against rotation, and "cannot evaluate" must not read as "passes".
 */

import { describe, expect, it } from "vitest";
import { X509Certificate } from "@peculiar/x509";
import { mintBridgeCertPair } from "../cert-authority";
import { certEpoch, verifyX509 } from "../auth/verify-proof";
import { ED25519 } from "../platform";

async function spkiPem(key: CryptoKey): Promise<string> {
  const spki = (await crypto.subtle.exportKey("spki", key)) as ArrayBuffer;
  const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
  return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
}

/** Mint a real cert pair at a chosen epoch, plus the CA cert that signed it. */
async function mintAtEpoch(epoch: number) {
  const ca = (await crypto.subtle.generateKey(ED25519, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const mtls = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const signing = (await crypto.subtle.generateKey(ED25519, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;

  const pair = await mintBridgeCertPair(
    "principal-under-test",
    "wimse://notme.bot/passkey/principal-under-test",
    await spkiPem(mtls.publicKey),
    await spkiPem(signing.publicKey),
    ca.privateKey,
    { scopes: ["bridgeCert"], epoch, authMethod: "passkey" },
  );

  // Self-signed CA cert carrying the same key, so verifyX509's signature
  // check passes and the epoch is the only variable under test.
  const { X509CertificateGenerator } = await import("@peculiar/x509");
  const caCert = await X509CertificateGenerator.createSelfSigned({
    name: "CN=test-ca",
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 3_600_000),
    signingAlgorithm: ED25519,
    keys: { privateKey: ca.privateKey, publicKey: ca.publicKey },
    serialNumber: "01",
  });

  return { certPem: pair.certificates.mtls, caPem: caCert.toString("pem") };
}

describe("epoch revocation (notme-77a024, ADR-008 §418-420)", () => {
  it("reads the epoch a certificate was issued under", async () => {
    const { certPem } = await mintAtEpoch(7);
    expect(certEpoch(new X509Certificate(certPem))).toBe(7);
  });

  it("accepts a cert whose epoch matches the authority's", async () => {
    const { certPem, caPem } = await mintAtEpoch(3);
    await expect(verifyX509(certPem, caPem, 3)).resolves.toBeDefined();
  });

  it("REJECTS a cert from a superseded epoch — rotation now revokes", async () => {
    // The whole point. Before this, rotating bumped a number nothing compared.
    const { certPem, caPem } = await mintAtEpoch(3);
    await expect(verifyX509(certPem, caPem, 4)).rejects.toThrow(/epoch/i);
  });

  it("rejects one epoch behind — no default grace window (§420)", async () => {
    // §420: grace is deployment configuration, not a protocol default. A
    // default grace means the emergency lever does not take effect at the
    // moment it is pulled, which is the only moment it matters.
    const { certPem, caPem } = await mintAtEpoch(9);
    await expect(verifyX509(certPem, caPem, 10)).rejects.toThrow(/epoch/i);
  });

  it("rejects a cert from a FUTURE epoch", async () => {
    // Not a rotation case — a cert claiming an epoch the authority has not
    // reached is either forged or from a different authority. Accepting it
    // would let an attacker who could influence the epoch field outrun every
    // future rotation at once.
    const { certPem, caPem } = await mintAtEpoch(11);
    await expect(verifyX509(certPem, caPem, 5)).rejects.toThrow(/epoch/i);
  });

  it("refuses a certificate carrying no epoch at all", async () => {
    // "Cannot evaluate" must not read as "passes". A cert without the
    // extension cannot be judged against rotation.
    const ca = (await crypto.subtle.generateKey(ED25519, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const { X509CertificateGenerator } = await import("@peculiar/x509");
    const bare = await X509CertificateGenerator.createSelfSigned({
      name: "CN=no-epoch",
      notBefore: new Date(Date.now() - 60_000),
      notAfter: new Date(Date.now() + 3_600_000),
      signingAlgorithm: ED25519,
      keys: { privateKey: ca.privateKey, publicKey: ca.publicKey },
      serialNumber: "02",
    });
    const pem = bare.toString("pem");
    expect(certEpoch(new X509Certificate(pem))).toBeNull();
    await expect(verifyX509(pem, pem, 1)).rejects.toThrow(/epoch/i);
  });

  it("still rejects an expired cert, and says expiry — not epoch", async () => {
    // The pre-existing checks must survive and keep their own messages: an
    // operator debugging an expiry must not be sent hunting a rotation.
    const { caPem } = await mintAtEpoch(1);
    const ca = (await crypto.subtle.generateKey(ED25519, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const { X509CertificateGenerator } = await import("@peculiar/x509");
    const expired = await X509CertificateGenerator.createSelfSigned({
      name: "CN=expired",
      notBefore: new Date(Date.now() - 7_200_000),
      notAfter: new Date(Date.now() - 3_600_000),
      signingAlgorithm: ED25519,
      keys: { privateKey: ca.privateKey, publicKey: ca.publicKey },
      serialNumber: "03",
    });
    await expect(
      verifyX509(expired.toString("pem"), caPem, 1),
    ).rejects.toThrow(/expired/i);
  });
});
