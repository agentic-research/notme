/**
 * cert-extensions.test.ts — Verify leaf certs declare BasicConstraints +
 * KeyUsage + ExtendedKeyUsage so strict X.509 validators (rustls,
 * boringssl, openssl 3) accept them.
 *
 * Maps to THREAT_MODEL.md / future cert-authority section.
 *
 * Without these extensions, ley-line manifest receivers and other
 * validators that enforce KeyUsage would reject signing certs as
 * "key not authorized for signing." This test locks the invariant.
 */

import { describe, expect, it } from "vitest";
import {
  X509Certificate,
  BasicConstraintsExtension,
  KeyUsagesExtension,
  KeyUsageFlags,
  ExtendedKeyUsageExtension,
} from "@peculiar/x509";
import { mintBridgeCertPair, mintGHABridgeCert } from "../cert-authority";
import { ED25519 } from "../platform";

async function generateCAKeyPair(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey(ED25519, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
}

async function generateLeafKey(
  algo: "ECDSA" | "Ed25519",
): Promise<CryptoKeyPair> {
  const params =
    algo === "ECDSA"
      ? { name: "ECDSA", namedCurve: "P-256" }
      : ED25519;
  return (await crypto.subtle.generateKey(params, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
}

async function spkiToPem(key: CryptoKey): Promise<string> {
  const spki = (await crypto.subtle.exportKey("spki", key)) as ArrayBuffer;
  const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
  const lines = b64.match(/.{1,64}/g)!.join("\n");
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`;
}

describe("cert-authority.leaf-extensions", () => {
  it("mintBridgeCertPair sets BasicConstraints CA=false on both certs", async () => {
    const ca = await generateCAKeyPair();
    const mtls = await generateLeafKey("ECDSA");
    const signing = await generateLeafKey("Ed25519");

    const result = await mintBridgeCertPair(
      "principal-test",
      "wimse://notme.bot/test/principal-test",
      await spkiToPem(mtls.publicKey),
      await spkiToPem(signing.publicKey),
      ca.privateKey,
      { scopes: ["bridgeCert"], epoch: 1, authMethod: "test" },
    );

    const mtlsCert = new X509Certificate(result.certificates.mtls);
    const signingCert = new X509Certificate(result.certificates.signing);

    const mtlsBC = mtlsCert.getExtension(BasicConstraintsExtension);
    const signingBC = signingCert.getExtension(BasicConstraintsExtension);
    expect(mtlsBC?.ca).toBe(false);
    expect(signingBC?.ca).toBe(false);
    // RFC 5280 §4.2.1.9: BasicConstraints SHOULD be critical when ca is true
    // and MAY be either when ca is false. We mark it critical to make the
    // not-a-CA claim stronger against permissive validators.
    expect(mtlsBC?.critical).toBe(true);
    expect(signingBC?.critical).toBe(true);
  });

  it("mtls cert has digitalSignature + keyAgreement KeyUsage and clientAuth EKU", async () => {
    const ca = await generateCAKeyPair();
    const mtls = await generateLeafKey("ECDSA");
    const signing = await generateLeafKey("Ed25519");

    const result = await mintBridgeCertPair(
      "principal-test",
      "wimse://notme.bot/test/principal-test",
      await spkiToPem(mtls.publicKey),
      await spkiToPem(signing.publicKey),
      ca.privateKey,
      { scopes: ["bridgeCert"], epoch: 1, authMethod: "test" },
    );

    const cert = new X509Certificate(result.certificates.mtls);

    const ku = cert.getExtension(KeyUsagesExtension);
    expect(ku).toBeTruthy();
    expect(ku!.usages & KeyUsageFlags.digitalSignature).toBeTruthy();
    expect(ku!.usages & KeyUsageFlags.keyAgreement).toBeTruthy();
    expect(ku!.critical).toBe(true);

    const eku = cert.getExtension(ExtendedKeyUsageExtension);
    expect(eku).toBeTruthy();
    expect(eku!.usages).toContain("1.3.6.1.5.5.7.3.2"); // id-kp-clientAuth
  });

  it("signing cert has digitalSignature KeyUsage (no keyAgreement, no EKU)", async () => {
    const ca = await generateCAKeyPair();
    const mtls = await generateLeafKey("ECDSA");
    const signing = await generateLeafKey("Ed25519");

    const result = await mintBridgeCertPair(
      "principal-test",
      "wimse://notme.bot/test/principal-test",
      await spkiToPem(mtls.publicKey),
      await spkiToPem(signing.publicKey),
      ca.privateKey,
      { scopes: ["bridgeCert"], epoch: 1, authMethod: "test" },
    );

    const cert = new X509Certificate(result.certificates.signing);

    const ku = cert.getExtension(KeyUsagesExtension);
    expect(ku).toBeTruthy();
    expect(ku!.usages & KeyUsageFlags.digitalSignature).toBeTruthy();
    // Signing cert is for arbitrary payload signing — no TLS KeyAgreement
    // (it doesn't participate in TLS handshakes) and no EKU constraint (so
    // it can be used for git commits, manifests, attestations without each
    // receiver enumerating an OID).
    expect(ku!.usages & KeyUsageFlags.keyAgreement).toBeFalsy();
    expect(cert.getExtension(ExtendedKeyUsageExtension)).toBeFalsy();
  });

  it("mintGHABridgeCert single-cert path also sets leaf extensions", async () => {
    const ca = await generateCAKeyPair();
    const leaf = await generateLeafKey("ECDSA");

    const result = await mintGHABridgeCert(
      "repo:agentic-research/notme:ref:refs/heads/main",
      await spkiToPem(leaf.publicKey),
      ca.privateKey,
    );

    const cert = new X509Certificate(result.certificate);

    expect(cert.getExtension(BasicConstraintsExtension)?.ca).toBe(false);
    const ku = cert.getExtension(KeyUsagesExtension);
    expect(ku).toBeTruthy();
    expect(ku!.usages & KeyUsageFlags.digitalSignature).toBeTruthy();
    expect(ku!.usages & KeyUsageFlags.keyAgreement).toBeTruthy();
    expect(
      cert.getExtension(ExtendedKeyUsageExtension)?.usages,
    ).toContain("1.3.6.1.5.5.7.3.2");
  });
});
