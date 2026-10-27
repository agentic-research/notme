/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * llo-profile-contract.do.test.ts — `.1.1`/`.1.2` are a CROSS-REPO CONTRACT,
 * not spare metadata (notme-6070fa, relayed from ley-line-open-9ac66d / LLO
 * PR #489).
 *
 * notme, signet and ley-line-open all allocate under the IANA
 * example/private-experiment arc `1.3.6.1.4.1.99999` with no registry
 * between them, and `.1.5`/`.1.6` mean DIFFERENT things in the two
 * allocations (notme: authMethod and peer binding; LLO/cloister:
 * interlace-peer and interlace-scope). LLO #489 resolves that by deciding a
 * certificate's PROFILE from its signed extensions, quoting its own module
 * docs:
 *
 *     Signet profile iff it carries at least one of `.1.1`, `.1.2`, …
 *     Interlace profile otherwise.
 *     Under the Signet profile `.1.5` and `.1.6` are never reported.
 *
 * So the presence of `.1.1`/`.1.2` is what tells a third-party verifier it is
 * holding a notme certificate rather than a cloister one. **Drop them from a
 * mint path and that path's certificates get classified as cloister's
 * profile, at which point `.1.5` and `.1.6` ARE read — silently, with the
 * wrong meaning, in an identity-correlation field.** Nothing in notme would
 * fail; the misread happens in another repo, against a certificate this one
 * signed.
 *
 * They look like decorative audit metadata — a subject string the SAN
 * already carries, and an issuance time `notBefore` already carries — which
 * is exactly why a tidy-up could remove them. Hence a test whose failure
 * message says what actually breaks.
 *
 * ALL FOUR MINT PATHS, because the discriminator is per-certificate: one
 * path quietly dropping an extension is enough.
 */
import { X509Certificate, X509CertificateGenerator, BasicConstraintsExtension, KeyUsagesExtension, KeyUsageFlags } from "@peculiar/x509";
import { describe, expect, it } from "vitest";
import {
  OID_SUBJECT,
  OID_ISSUANCE_TIME,
  mintGHABridgeCert,
  mintBridgeCertPair,
  mintIssuingCaCert,
  mintTaskCertPair,
} from "./cert-authority";
import { ED25519 } from "./platform";

const gen = async () =>
  (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
const genP256 = async () =>
  (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;

async function pem(key: CryptoKey): Promise<string> {
  const spki = (await crypto.subtle.exportKey("spki", key)) as ArrayBuffer;
  const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
  return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
}

/** Assert both discriminator extensions are present on one certificate. */
function expectDiscriminator(certPem: string, path: string) {
  const cert = new X509Certificate(certPem);
  for (const [oid, label] of [
    [OID_SUBJECT, "OID_SUBJECT (.1.1)"],
    [OID_ISSUANCE_TIME, "OID_ISSUANCE_TIME (.1.2)"],
  ] as const) {
    expect(
      cert.getExtension(oid),
      `${path} emitted no ${label}. LLO decides a cert's PROFILE from these: ` +
        `with neither present it classifies this certificate as cloister's ` +
        `Interlace profile and reads .1.5/.1.6 with the wrong meaning. ` +
        `See notme-6070fa / LLO PR #489.`,
    ).toBeTruthy();
  }
}

const MACHINE_ID = "wimse://notme.bot/passkey/alice";
const GOAL = "a".repeat(64);

describe("every mint path carries the LLO profile discriminator (notme-6070fa)", () => {
  it("mintGHABridgeCert", async () => {
    const ca = await gen();
    const subject = await gen();
    const r = await mintGHABridgeCert(
      "repo:agentic-research/notme:ref:refs/heads/main",
      await pem(subject.publicKey),
      ca.privateKey,
    );
    expectDiscriminator(r.certificate, "mintGHABridgeCert");
  });

  it("mintBridgeCertPair — BOTH certificates of the pair", async () => {
    const ca = await gen();
    const mtls = await genP256();
    const signing = await gen();
    const r = await mintBridgeCertPair(
      "alice",
      MACHINE_ID,
      await pem(mtls.publicKey),
      await pem(signing.publicKey),
      ca.privateKey,
      { scopes: ["bridgeCert"], epoch: 1, authMethod: "passkey" },
    );
    // The pair is two independently-signed certificates; a verifier may hold
    // either one, so the contract has to hold for both.
    expectDiscriminator(r.certificates.mtls, "mintBridgeCertPair (mtls)");
    expectDiscriminator(r.certificates.signing, "mintBridgeCertPair (signing)");
  });

  it("mintIssuingCaCert", async () => {
    const ca = await gen();
    const tierKeys = await gen();
    const r = await mintIssuingCaCert(
      "alice",
      MACHINE_ID,
      await pem(tierKeys.publicKey),
      ca.privateKey,
      { scopes: ["bridgeCert"], epoch: 1, authMethod: "passkey" },
    );
    expectDiscriminator(r.certificate, "mintIssuingCaCert");
  });

  it("mintTaskCertPair — BOTH certificates, minted offline under a tier", async () => {
    const ca = await gen();
    await X509CertificateGenerator.createSelfSigned({
      name: "CN=signet-authority,O=notme",
      notBefore: new Date(Date.now() - 60_000),
      notAfter: new Date(Date.now() + 3600_000),
      signingAlgorithm: ED25519,
      keys: ca,
      serialNumber: "01",
      extensions: [
        new BasicConstraintsExtension(true, 1, true),
        new KeyUsagesExtension(KeyUsageFlags.keyCertSign, true),
      ],
    });
    const tierKeys = await gen();
    const tier = await mintIssuingCaCert(
      "alice",
      MACHINE_ID,
      await pem(tierKeys.publicKey),
      ca.privateKey,
      { scopes: ["bridgeCert"], epoch: 1, authMethod: "passkey" },
    );
    const mtls = await genP256();
    const signing = await gen();
    const task = await mintTaskCertPair(
      tier.certificate,
      tierKeys.privateKey,
      await pem(mtls.publicKey),
      await pem(signing.publicKey),
      { task: "t", goalHash: GOAL, scopes: ["bridgeCert"], epoch: 1 },
    );
    expectDiscriminator(task.certificates.mtls, "mintTaskCertPair (mtls)");
    expectDiscriminator(task.certificates.signing, "mintTaskCertPair (signing)");
  });
});
