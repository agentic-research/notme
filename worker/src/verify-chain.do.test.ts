/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * verify-chain.do.test.ts — the chain walker carries all three bounds, or it
 * does not ship (ADR-019 D4/D5, notme-acc822).
 *
 * Every rejection asserts its EXACT reason: a chain that fails for the wrong
 * reason is a bound that silently is not there.
 */
import { X509CertificateGenerator, BasicConstraintsExtension, KeyUsagesExtension, KeyUsageFlags } from "@peculiar/x509";
import { describe, expect, it } from "vitest";
import { mintBridgeCertPair, mintIssuingCaCert } from "./cert-authority";
import { ED25519 } from "./platform";
import { verifyCertChain } from "./auth/verify-chain";

async function pem(key: CryptoKey): Promise<string> {
  const spki = (await crypto.subtle.exportKey("spki", key)) as ArrayBuffer;
  const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
  return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
}
const gen = async () =>
  (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
const genP256 = async () =>
  (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;

const MACHINE_ID = "wimse://notme.bot/passkey/alice";

/** Root with the production shape: CA=true, pathlen=1 (notme-20f88b). */
async function makeRoot(pathLen = 1) {
  const ca = await gen();
  const cert = await X509CertificateGenerator.createSelfSigned({
    name: "CN=signet-authority,O=notme",
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 3600_000),
    signingAlgorithm: ED25519,
    keys: ca,
    serialNumber: "01",
    extensions: [
      new BasicConstraintsExtension(true, pathLen, true),
      new KeyUsagesExtension(KeyUsageFlags.keyCertSign, true),
    ],
  });
  return { ca, pem: cert.toString("pem") };
}

async function makeChain(opts?: {
  taskId?: string;
  taskScopes?: string[];
  tierScopes?: string[];
  tierTtlMs?: number;
  epoch?: number;
}) {
  const root = await makeRoot();
  const machine = await gen();
  const tier = await mintIssuingCaCert(
    "alice",
    MACHINE_ID,
    await pem(machine.publicKey),
    root.ca.privateKey,
    {
      scopes: opts?.tierScopes ?? ["bridgeCert"],
      epoch: opts?.epoch ?? 1,
      authMethod: "passkey",
      ttlMs: opts?.tierTtlMs,
    },
  );
  const taskKeys = { mtls: await genP256(), signing: await gen() };
  const task = await mintBridgeCertPair(
    "alice-task",
    opts?.taskId ?? `${MACHINE_ID}/task-1`,
    await pem(taskKeys.mtls.publicKey),
    await pem(taskKeys.signing.publicKey),
    machine.privateKey,
    { scopes: opts?.taskScopes ?? ["bridgeCert"], epoch: opts?.epoch ?? 1, authMethod: "passkey" },
  );
  return { root, machine, tier, task };
}

describe("verifyCertChain — the legitimate chain", () => {
  it("ACCEPTS root → issuing tier → task, and reports what was verified", async () => {
    const { root, tier, task } = await makeChain();
    const result = await verifyCertChain(
      task.certificates.signing,
      [tier.certificate],
      root.pem,
      1,
    );
    expect(result.identity).toBe(`${MACHINE_ID}/task-1`);
    expect(result.scopes).toEqual(["bridgeCert"]);
    expect(result.depth).toBe(1);
    expect(result.subject).toBe("alice-task");
  });

  it("refuses an empty chain — root-signed certs belong to verifyX509", async () => {
    const { root, task } = await makeChain();
    await expect(
      verifyCertChain(task.certificates.signing, [], root.pem, 1),
    ).rejects.toThrow(/use verifyX509/);
  });
});

describe("verifyCertChain — the three bounds", () => {
  it("AUTHORITY: rejects a task claiming scopes its tier does not hold, naming them", async () => {
    const { root, tier, task } = await makeChain({
      taskScopes: ["bridgeCert", "certMint"],
    });
    await expect(
      verifyCertChain(task.certificates.signing, [tier.certificate], root.pem, 1),
    ).rejects.toThrow(/scope escalation in chain: certMint/);
  });

  it("NAMESPACE: rejects a task naming another principal", async () => {
    const { root, tier, task } = await makeChain({
      taskId: "wimse://notme.bot/passkey/bob/task-1",
    });
    await expect(
      verifyCertChain(task.certificates.signing, [tier.certificate], root.pem, 1),
    ).rejects.toThrow(/namespace escape/);
  });

  it("NAMESPACE: rejects a task claiming to BE the machine — equality is impersonation", async () => {
    const { root, tier, task } = await makeChain({ taskId: MACHINE_ID });
    await expect(
      verifyCertChain(task.certificates.signing, [tier.certificate], root.pem, 1),
    ).rejects.toThrow(/namespace escape/);
  });

  it("DEPTH: rejects a tier below a tier — pathlen=0 means terminal children", async () => {
    const { root, machine, tier } = await makeChain();
    const machine2 = await gen();
    const tier2 = await mintIssuingCaCert(
      "alice-sub",
      `${MACHINE_ID}/sub`,
      await pem(machine2.publicKey),
      machine.privateKey, // signed by tier 1's key — a tier minting a tier
      { scopes: ["bridgeCert"], epoch: 1, authMethod: "passkey" },
    );
    const taskKeys = { mtls: await genP256(), signing: await gen() };
    const task = await mintBridgeCertPair(
      "deep-task",
      `${MACHINE_ID}/sub/task`,
      await pem(taskKeys.mtls.publicKey),
      await pem(taskKeys.signing.publicKey),
      machine2.privateKey,
      { scopes: ["bridgeCert"], epoch: 1, authMethod: "passkey" },
    );
    await expect(
      verifyCertChain(
        task.certificates.signing,
        [tier2.certificate, tier.certificate],
        root.pem,
        1,
      ),
    ).rejects.toThrow(/pathlen exceeded/);
  });

  it("DEPTH: a root advertising no budget admits no tiers at all", async () => {
    const root0 = await makeRoot(0);
    const machine = await gen();
    const tier = await mintIssuingCaCert(
      "alice", MACHINE_ID, await pem(machine.publicKey), root0.ca.privateKey,
      { scopes: ["bridgeCert"], epoch: 1, authMethod: "passkey" },
    );
    const taskKeys = { mtls: await genP256(), signing: await gen() };
    const task = await mintBridgeCertPair(
      "t", `${MACHINE_ID}/t`,
      await pem(taskKeys.mtls.publicKey), await pem(taskKeys.signing.publicKey),
      machine.privateKey,
      { scopes: ["bridgeCert"], epoch: 1, authMethod: "passkey" },
    );
    await expect(
      verifyCertChain(task.certificates.signing, [tier.certificate], root0.pem, 1),
    ).rejects.toThrow(/pathlen exceeded/);
  });
});

describe("verifyCertChain — signatures, rotation, expiry", () => {
  it("rejects a chain that does not reach the trusted root", async () => {
    const { tier, task } = await makeChain();
    const otherRoot = await makeRoot();
    await expect(
      verifyCertChain(task.certificates.signing, [tier.certificate], otherRoot.pem, 1),
    ).rejects.toThrow(/does not reach the trusted CA/);
  });

  it("rejects a task not actually signed by its stated tier", async () => {
    const a = await makeChain();
    const b = await makeChain(); // different machine key, same identity shape
    await expect(
      verifyCertChain(a.task.certificates.signing, [b.tier.certificate], b.root.pem, 1),
    ).rejects.toThrow(/not signed by its stated tier/);
  });

  it("rejects the whole generation on rotation — every tier checks the epoch", async () => {
    const { root, tier, task } = await makeChain({ epoch: 1 });
    await expect(
      verifyCertChain(task.certificates.signing, [tier.certificate], root.pem, 2),
    ).rejects.toThrow(/revoked by rotation/);
  });

  it("rejects an expired tier even when the task itself is fresh", async () => {
    const { root, tier, task } = await makeChain({ tierTtlMs: -60_000 });
    await expect(
      verifyCertChain(task.certificates.signing, [tier.certificate], root.pem, 1),
    ).rejects.toThrow(/expired/);
  });
});
