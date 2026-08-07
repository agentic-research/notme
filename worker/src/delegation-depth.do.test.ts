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
 * "blocks orchestrator→agent delegation"). The middle tier was never built:
 * cert-authority.ts stamps BASIC_CONSTRAINTS_LEAF (CA=false) on every cert
 * notme mints, so the authority issues two levels while its root advertises
 * room for three.
 *
 * WHY THAT ASYMMETRY IS THE THING TO TEST, rather than "does hop 2 exist":
 * a pathlen budget is a statement to VERIFIERS about what chains they should
 * accept. The root currently tells every verifier "an intermediate below me is
 * legitimate" while nothing legitimate ever occupies that slot — so the only
 * cert that could ever fill it is one nobody meant to issue. Whichever way the
 * fork is resolved, the budget and the tiers have to agree:
 *
 *   BUILD the tier   -> a mint path produces CA=true/pathlen=0, budget 1 is spent
 *   DROP the tier    -> the root narrows to pathlen=0 and hop 2 lives elsewhere
 *
 * Both exits satisfy these tests. Neither presupposes the design decision,
 * which is why they can be written before it is made.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { BasicConstraintsExtension, X509Certificate } from "@peculiar/x509";
import { describe, expect, it } from "vitest";
import { mintBridgeCertPair, mintGHABridgeCert } from "./cert-authority";
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

  return [
    new X509Certificate(pair.certificates.mtls),
    new X509Certificate(pair.certificates.signing),
    new X509Certificate(gha.certificate),
  ];
}

/** How many tiers below the root may themselves issue certificates. */
function intermediateTiers(certs: X509Certificate[]): number {
  return certs.filter((c) => c.getExtension(BasicConstraintsExtension)?.ca)
    .length;
}

describe("delegation depth (notme-600df1 / ADR-008 §BasicConstraints)", () => {
  // `it.fails` rather than `it.todo`: these assert the gap is STILL OPEN, so
  // they execute on every run and go red the moment hop 2 lands — which is
  // the signal to delete the `.fails` and let them stand as normal tests. A
  // todo would sit inert and tell nobody. The unusual polarity is the point:
  // the unbuilt state is the one being pinned, not the built one.
  it.fails("issues a machine tier that may delegate to tasks", async () => {
    // Hop 2 of the desired outcome. ADR-008 calls this the orchestrator
    // bridge: CA=true so it can sign task certs, pathlen=0 so a task cannot
    // sign anything in turn. Today every mint path stamps CA=false, so the
    // machine cannot delegate and the chain stops one hop short.
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

  it.fails("advertises a pathlen budget equal to the tiers it can issue", async () => {
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
