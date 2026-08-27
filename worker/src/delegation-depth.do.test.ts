/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * delegation-depth.do.test.ts — the delegation chain notme ADVERTISES must be
 * the one it can actually ISSUE (notme-600df1, notme-77a024).
 *
 * THE DESIRED OUTCOME, stated as a chain: the bridge delegates the human to
 * the MACHINE, and the machine delegates to each TASK. Two hops, each with a
 * different granter and a different revocation blast radius.
 *
 * That outcome is not new — ADR-008 §"BasicConstraints and path length"
 * already specifies it as a normative three-level table:
 *
 *   CA                  CA=true   pathlen=1   keyCertSign, cRLSign
 *   Orchestrator bridge CA=true   pathlen=0   keyCertSign      <- the MACHINE
 *   Agent session       CA=false  (leaf)      digitalSignature <- the TASK
 *
 * The root was widened to pathlen=1 for exactly this (notme-20f88b, closed,
 * "blocks orchestrator→agent delegation"). The middle tier landed 2026-08-27
 * as `mintIssuingCaCert` — the Issuing CA per the signet-9dfb44 naming
 * decision — resolving the fork these tests were written to pin: BUILD the
 * tier, so a mint path produces CA=true/pathlen=0 and the root's budget of 1
 * is exactly spent.
 *
 * WHY BUDGET-EQUALS-TIERS IS THE THING TO TEST, rather than "does hop 2
 * exist": a pathlen budget is a statement to VERIFIERS about what chains they
 * should accept. Before the tier existed, the root told every verifier "an
 * intermediate below me is legitimate" while nothing legitimate ever occupied
 * that slot — so the only cert that could fill it was one nobody meant to
 * issue. These began as `it.fails` pinning that unbuilt state; the polarity
 * flipped on 2026-08-27 and the `.fails` markers came off, per the protocol
 * they were written with.
 */
import { env, runInDurableObject } from "cloudflare:test";
import {
  BasicConstraintsExtension,
  X509Certificate,
  X509CertificateGenerator,
} from "@peculiar/x509";
import { describe, expect, it } from "vitest";
import {
  mintBridgeCertPair,
  mintGHABridgeCert,
  mintIssuingCaCert,
} from "./cert-authority";
import { ED25519 } from "./platform";
import type { SigningAuthority } from "./signing-authority";

async function spkiToPem(key: CryptoKey): Promise<string> {
  const spki = (await crypto.subtle.exportKey("spki", key)) as ArrayBuffer;
  const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
  return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
}

/**
 * Every certificate notme can issue, minted through its real mint paths.
 *
 * Enumerated rather than sampled: the claim under test is about what the
 * authority is CAPABLE of issuing, so a path left out would silently weaken
 * it. If a new mint path is added, it belongs here.
 */
async function mintEverything(): Promise<X509Certificate[]> {
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
    await spkiToPem(mtls.publicKey),
    await spkiToPem(signing.publicKey),
    ca.privateKey,
    { scopes: ["certMint"], epoch: 1, authMethod: "passkey" },
  );
  const gha = await mintGHABridgeCert(
    "repo:agentic-research/notme:ref:refs/heads/main",
    await spkiToPem(mtls.publicKey),
    ca.privateKey,
  );

  const machine = (await crypto.subtle.generateKey(ED25519, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const issuing = await mintIssuingCaCert(
    "machine-under-test",
    "wimse://notme.bot/passkey/machine-under-test",
    await spkiToPem(machine.publicKey),
    ca.privateKey,
    { scopes: ["bridgeCert"], epoch: 1, authMethod: "passkey" },
  );

  return [
    new X509Certificate(pair.certificates.mtls),
    new X509Certificate(pair.certificates.signing),
    new X509Certificate(gha.certificate),
    new X509Certificate(issuing.certificate),
  ];
}

/** How many tiers below the root may themselves issue certificates. */
function intermediateTiers(certs: X509Certificate[]): number {
  return certs.filter((c) => c.getExtension(BasicConstraintsExtension)?.ca)
    .length;
}

describe("delegation depth (notme-600df1 / ADR-008 §BasicConstraints)", () => {
  it("issues a machine tier that may delegate to tasks", async () => {
    // Hop 2 of the desired outcome. ADR-008 calls this the orchestrator
    // bridge, the naming decision calls it the Issuing CA: CA=true so it can
    // sign task certs, pathlen=0 so a task cannot sign anything in turn.
    const certs = await mintEverything();
    expect(
      intermediateTiers(certs),
      "no mint path produces a CA=true machine tier — hop 2 (machine→task) cannot be issued",
    ).toBeGreaterThan(0);
  });

  it("never lets a task delegate onward — the chain is two hops, not N", async () => {
    // The depth CAP, and the half that must survive hop 2 landing. A task
    // credential that can mint is an unbounded delegation the human never
    // agreed to; pathlen=0 on the machine tier is what makes X.509 verifiers
    // enforce that for us instead of trusting notme to refuse.
    for (const cert of await mintEverything()) {
      const bc = cert.getExtension(BasicConstraintsExtension);
      if (bc?.ca) {
        expect(
          bc.pathLength,
          "a delegating tier must cap depth at 0 so its tasks are terminal",
        ).toBe(0);
      }
    }
  });

  it("advertises a pathlen budget equal to the tiers it can issue", async () => {
    // The asymmetry itself. A budget larger than the tiers that exist tells
    // verifiers to accept an intermediate that notme never legitimately mints.
    const stub = env.SIGNING_AUTHORITY.get(
      env.SIGNING_AUTHORITY.idFromName("delegation-depth-test"),
    );
    const caPem = await runInDurableObject(stub, (auth) =>
      (auth as SigningAuthority).getCACertificatePem(),
    );
    const budget =
      new X509Certificate(caPem).getExtension(BasicConstraintsExtension)
        ?.pathLength ?? 0;

    expect(
      budget,
      "the root reserves room for intermediates the authority cannot issue",
    ).toBe(intermediateTiers(await mintEverything()));
  });
});

describe("chain verification is deliberately unbuilt (ADR-019 D5 gate)", () => {
  // The tier can be MINTED; nothing yet ACCEPTS what it signs. verifyX509 is
  // single-hop — leaf against the root key, no path building — so a task
  // cert signed by a machine tier is rejected everywhere in notme today,
  // even on a fully legitimate chain. That is deliberate: a chain-walking
  // verifier must ship WITH the namespace bound — decided 2026-08-27 as
  // URI-SAN segment-prefix confinement (ADR-019 D5) — and the chain scope
  // rule, or a tier holder could name identities it has no business naming. This test pins the boundary — the day someone builds
  // path validation, it fails, and this comment is what they must answer.
  it("REJECTS a task cert signed by the machine tier, even on a legitimate chain", async () => {
    const ca = (await crypto.subtle.generateKey(ED25519, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const machine = (await crypto.subtle.generateKey(ED25519, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const task = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const taskEd = (await crypto.subtle.generateKey(ED25519, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;

    const rootCert = await X509CertificateGenerator.createSelfSigned({
      name: "CN=signet-authority,O=notme",
      notBefore: new Date(),
      notAfter: new Date(Date.now() + 3600_000),
      signingAlgorithm: ED25519,
      keys: ca,
      serialNumber: "01",
    });
    await mintIssuingCaCert(
      "machine-under-test",
      "wimse://notme.bot/passkey/machine-under-test",
      await spkiToPem(machine.publicKey),
      ca.privateKey,
      { scopes: ["bridgeCert"], epoch: 1, authMethod: "passkey" },
    );
    // Hop 2: the MACHINE signs a task cert — legitimate use of the tier.
    const taskPair = await mintBridgeCertPair(
      "task-under-test",
      "wimse://notme.bot/passkey/task-under-test",
      await spkiToPem(task.publicKey),
      await spkiToPem(taskEd.publicKey),
      machine.privateKey,
      { scopes: ["bridgeCert"], epoch: 1, authMethod: "passkey" },
    );

    const { verifyX509 } = await import("./auth/verify-proof");
    await expect(
      verifyX509(taskPair.certificates.mtls, rootCert.toString("pem"), 1),
    ).rejects.toThrow(/not signed by trusted CA/);
  });
});

