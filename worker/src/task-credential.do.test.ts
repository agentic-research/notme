/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * task-credential.do.test.ts — hop 2: the MACHINE mints task credentials,
 * offline, and everything downstream can still tell what happened (A5;
 * ADR-019 D3/D4/D5, notme-9f84e6).
 *
 * Every rejection asserts its EXACT reason. Every "accepts" also asserts
 * what the chain verifier and the correlation key derive from the result —
 * a producer whose output nothing can read is shelf-ware.
 */
import { X509Certificate, X509CertificateGenerator, BasicConstraintsExtension, KeyUsagesExtension, KeyUsageFlags } from "@peculiar/x509";
import { describe, expect, it } from "vitest";
import { mintIssuingCaCert, mintTaskCertPair, certTaskScope } from "./cert-authority";
import { ED25519 } from "./platform";
import { verifyCertChain } from "./auth/verify-chain";
import { correlationKey, parseCorrelationKey, taskCorrelationKey } from "./auth/correlation-key";

async function pem(key: CryptoKey): Promise<string> {
  const spki = (await crypto.subtle.exportKey("spki", key)) as ArrayBuffer;
  const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
  return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
}
const gen = async () => (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
const genP256 = async () => (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
const MACHINE_ID = "wimse://notme.bot/passkey/alice";
const GOAL = "a".repeat(64);

async function machine(tierScopes = ["bridgeCert", "sign:git"]) {
  const ca = await gen();
  const rootCert = await X509CertificateGenerator.createSelfSigned({
    name: "CN=signet-authority,O=notme",
    notBefore: new Date(Date.now() - 60_000), notAfter: new Date(Date.now() + 3600_000),
    signingAlgorithm: ED25519, keys: ca, serialNumber: "01",
    extensions: [new BasicConstraintsExtension(true, 1, true), new KeyUsagesExtension(KeyUsageFlags.keyCertSign, true)],
  });
  const keys = await gen();
  const tier = await mintIssuingCaCert("alice", MACHINE_ID, await pem(keys.publicKey), ca.privateKey,
    { scopes: tierScopes, epoch: 1, authMethod: "passkey" });
  return { rootPem: rootCert.toString("pem"), keys, tier };
}

async function taskKeys() {
  const mtls = await genP256(); const signing = await gen();
  return { mtls, signing, mtlsPem: await pem(mtls.publicKey), signingPem: await pem(signing.publicKey) };
}

describe("mintTaskCertPair — the machine's offline producer", () => {
  it("mints a chain-verifiable task pair; identity, scopes and task scope round-trip", async () => {
    const m = await machine();
    const k = await taskKeys();
    const task = await mintTaskCertPair(m.tier.certificate, m.keys.privateKey, k.mtlsPem, k.signingPem, {
      task: "bead-1234", goalHash: GOAL, scopes: ["sign:git"], epoch: 1,
    });
    expect(task.identity).toBe(`${MACHINE_ID}/bead-1234`);

    const v = await verifyCertChain(task.certificates.signing, [m.tier.certificate], m.rootPem, 1);
    expect(v.identity).toBe(`${MACHINE_ID}/bead-1234`);
    expect(v.scopes).toEqual(["sign:git"]);
    expect(v.depth).toBe(1);

    // Task scope is IN the certificate, readable without the producer.
    const ts = certTaskScope(new X509Certificate(task.certificates.signing));
    expect(ts).toEqual({ task: "bead-1234", goalHash: GOAL });
  });

  it("the issuer NAME chains — the task cert names the tier, not the root, as its issuer", async () => {
    const m = await machine();
    const k = await taskKeys();
    const task = await mintTaskCertPair(m.tier.certificate, m.keys.privateKey, k.mtlsPem, k.signingPem, {
      task: "t", goalHash: GOAL, scopes: ["bridgeCert"], epoch: 1,
    });
    const cert = new X509Certificate(task.certificates.mtls);
    const tierCert = new X509Certificate(m.tier.certificate);
    expect(cert.issuer).toBe(tierCert.subject);
  });

  it("REFUSES scopes the tier does not hold — narrowing happens at the producer, not just the verifier", async () => {
    const m = await machine(["bridgeCert"]);
    const k = await taskKeys();
    await expect(
      mintTaskCertPair(m.tier.certificate, m.keys.privateKey, k.mtlsPem, k.signingPem, {
        task: "t", goalHash: GOAL, scopes: ["bridgeCert", "certMint"], epoch: 1,
      }),
    ).rejects.toThrow(/scope escalation.*certMint/);
  });

  it("REFUSES a task id that would escape the tier's subtree", async () => {
    const m = await machine();
    const k = await taskKeys();
    for (const bad of ["../bob", "t/../../x", "", "a/b"]) {
      await expect(
        mintTaskCertPair(m.tier.certificate, m.keys.privateKey, k.mtlsPem, k.signingPem, {
          task: bad, goalHash: GOAL, scopes: ["bridgeCert"], epoch: 1,
        }),
        `task id ${JSON.stringify(bad)}`,
      ).rejects.toThrow(/task id/);
    }
  });

  it("REFUSES a private key that is not the tier's — the producer must hold the tier", async () => {
    const m = await machine();
    const other = await gen();
    const k = await taskKeys();
    await expect(
      mintTaskCertPair(m.tier.certificate, other.privateKey, k.mtlsPem, k.signingPem, {
        task: "t", goalHash: GOAL, scopes: ["bridgeCert"], epoch: 1,
      }),
    ).rejects.toThrow(/does not match the tier/);
  });

  it("cannot outlive its tier — TTL is clamped to the tier's expiry", async () => {
    const m = await machine();
    const k = await taskKeys();
    const task = await mintTaskCertPair(m.tier.certificate, m.keys.privateKey, k.mtlsPem, k.signingPem, {
      task: "t", goalHash: GOAL, scopes: ["bridgeCert"], epoch: 1, ttlMs: 365 * 24 * 3600_000,
    });
    const tierExp = new X509Certificate(m.tier.certificate).notAfter.getTime();
    expect(new X509Certificate(task.certificates.mtls).notAfter.getTime()).toBeLessThanOrEqual(tierExp);
  });

  it("refuses a malformed goal hash — the task scope is a commitment, not a label", async () => {
    const m = await machine();
    const k = await taskKeys();
    await expect(
      mintTaskCertPair(m.tier.certificate, m.keys.privateKey, k.mtlsPem, k.signingPem, {
        task: "t", goalHash: "not-a-hash", scopes: ["bridgeCert"], epoch: 1,
      }),
    ).rejects.toThrow(/goal hash/);
  });
});

describe("the correlation key gets its third segment from the certificates", () => {
  it("taskCorrelationKey derives <principal>/<bridge>/<task> from a task cert + its tier", async () => {
    const m = await machine();
    const k = await taskKeys();
    const task = await mintTaskCertPair(m.tier.certificate, m.keys.privateKey, k.mtlsPem, k.signingPem, {
      task: "bead-9", goalHash: GOAL, scopes: ["bridgeCert"], epoch: 1,
    });
    const key = taskCorrelationKey(new X509Certificate(task.certificates.signing), new X509Certificate(m.tier.certificate));
    const parts = parseCorrelationKey(key)!;
    expect(parts.principal).toBe(MACHINE_ID);
    expect(parts.binding).toBe(task.binding);
    expect(parts.task).toBe("bead-9");
    // Same key the pure function would build — one closure, two derivations.
    expect(key).toBe(correlationKey({ principal: MACHINE_ID, binding: task.binding, task: "bead-9" }));
  });
});

describe("verifyCertChain — name chaining is checked (found while building A5)", () => {
  it("REJECTS a cert whose issuer NAME is not its signer's subject, even with a valid signature", async () => {
    // Before A5 the walker verified by KEY only; a cert lying about its
    // issuer name (claiming the root while signed by the tier) passed. RFC
    // 5280 §6.1.3(a)(4) requires the name to chain; stock validators enforce
    // it, and a verifier that is laxer than openssl is not "cooperative", it
    // is wrong.
    const m = await machine();
    const k = await taskKeys();
    const { mintBridgeCertPair } = await import("./cert-authority");
    const lying = await mintBridgeCertPair("t", `${MACHINE_ID}/t`, k.mtlsPem, k.signingPem, m.keys.privateKey,
      { scopes: ["bridgeCert"], epoch: 1, authMethod: "passkey" }); // default issuer = root's name
    await expect(
      verifyCertChain(lying.certificates.signing, [m.tier.certificate], m.rootPem, 1),
    ).rejects.toThrow(/issuer name/);
  });
});
