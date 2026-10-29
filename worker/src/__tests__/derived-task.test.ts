/**
 * derived-task.test.ts — subtasks are derived from a parent task, and can only
 * narrow (notme-9f84e6).
 *
 * Re-minting and subtasks are one problem: issuing a credential derived from
 * an existing task credential. A re-mint keeps the parent's name; a subtask
 * extends it. Both are minted by the TIER HOLDER — the agent holds only a task
 * key, which can sign nothing a verifier accepts (CA:FALSE under pathlen=0) —
 * and both may only narrow: scopes ⊆ parent, lifetime ≤ parent, and the
 * child's name and identity are prefixed by the parent's, so revoking a task
 * by prefix reaches everything derived from it.
 */
import { X509Certificate, X509CertificateGenerator, BasicConstraintsExtension, KeyUsagesExtension, KeyUsageFlags } from "@peculiar/x509";
import { describe, expect, it } from "vitest";
import { certTaskScope, mintIssuingCaCert, mintTaskCertPair } from "../cert-authority";
import { ED25519 } from "../platform";

const GOAL_A = "a".repeat(64);
const GOAL_B = "b".repeat(64);

async function pubPem(k: CryptoKey) {
  const b = new Uint8Array((await crypto.subtle.exportKey("spki", k)) as ArrayBuffer);
  return `-----BEGIN PUBLIC KEY-----\n${btoa(String.fromCharCode(...b)).match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
}
const ed = () => crypto.subtle.generateKey(ED25519, true, ["sign", "verify"]) as Promise<CryptoKeyPair>;
const p256 = () => crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as Promise<CryptoKeyPair>;

async function tier(scopes = ["bridgeCert", "sign:git"]) {
  const root = await ed();
  await X509CertificateGenerator.createSelfSigned({
    name: "CN=signet-authority,O=notme", notBefore: new Date(Date.now() - 864e5), notAfter: new Date(Date.now() + 864e5),
    signingAlgorithm: ED25519, keys: root, serialNumber: "01",
    extensions: [new BasicConstraintsExtension(true, 1, true), new KeyUsagesExtension(KeyUsageFlags.keyCertSign, true)],
  });
  const tk = await ed();
  const t = await mintIssuingCaCert("alice", "wimse://notme.bot/principal/alice", await pubPem(tk.publicKey), root.privateKey,
    { scopes, epoch: 1, authMethod: "passkey" });
  return { pem: t.certificate, key: tk.privateKey };
}

async function task(t: { pem: string; key: CryptoKey }, name: string, opts: { scopes?: string[]; ttlMs?: number; parent?: string; goalHash?: string } = {}) {
  return mintTaskCertPair(t.pem, t.key, await pubPem((await p256()).publicKey), await pubPem((await ed()).publicKey), {
    task: name, goalHash: opts.goalHash ?? GOAL_A, scopes: opts.scopes ?? ["bridgeCert"], epoch: 1, ttlMs: opts.ttlMs, parent: opts.parent,
  });
}

describe("a subtask is derived from its parent", () => {
  it("names extend the parent's — identity, CN and the .1.9 task path", async () => {
    const t = await tier();
    const parent = await task(t, "rosary-056d96");
    const child = await task(t, "step-2", { parent: parent.certificates.signing, goalHash: GOAL_B });
    expect(child.identity).toBe("wimse://notme.bot/principal/alice/rosary-056d96/step-2");
    const c = new X509Certificate(child.certificates.signing);
    expect(certTaskScope(c)).toEqual({ task: "rosary-056d96/step-2", goalHash: GOAL_B });
    expect(c.subject).toContain("rosary-056d96/step-2");
  });

  it("nests: a grandchild extends the child", async () => {
    const t = await tier();
    const p = await task(t, "build");
    const c = await task(t, "compile", { parent: p.certificates.signing });
    const g = await task(t, "linker", { parent: c.certificates.signing });
    expect(g.identity).toBe("wimse://notme.bot/principal/alice/build/compile/linker");
  });

  it("is signed by the TIER, not by the parent task — tasks still sign nothing", async () => {
    const t = await tier();
    const p = await task(t, "build");
    const c = await task(t, "compile", { parent: p.certificates.signing });
    const tierCert = new X509Certificate(t.pem);
    expect(new X509Certificate(c.certificates.signing).issuer).toBe(tierCert.subject);
  });
});

describe("a subtask can only narrow", () => {
  it("refuses scopes the parent does not hold, even if the tier does", async () => {
    const t = await tier(["bridgeCert", "sign:git"]);
    const p = await task(t, "build", { scopes: ["bridgeCert"] });
    await expect(task(t, "sign-it", { parent: p.certificates.signing, scopes: ["sign:git"] })).rejects.toThrow(/escalation/);
  });

  it("never outlives the parent", async () => {
    const t = await tier();
    const p = await task(t, "build", { ttlMs: 60_000 });
    const c = await task(t, "compile", { parent: p.certificates.signing, ttlMs: 30 * 60_000 });
    const parentEnd = new X509Certificate(p.certificates.signing).notAfter.getTime();
    expect(new X509Certificate(c.certificates.signing).notAfter.getTime()).toBeLessThanOrEqual(parentEnd);
  });

  it("refuses a parent from a DIFFERENT tier", async () => {
    const a = await tier();
    const b = await tier();
    const foreign = await task(b, "build");
    await expect(task(a, "compile", { parent: foreign.certificates.signing })).rejects.toThrow(/parent/);
  });

  it("refuses a parent that is not a task cert", async () => {
    const t = await tier();
    await expect(task(t, "compile", { parent: t.pem })).rejects.toThrow(/parent/);
  });

  it("the child name is still one segment — no smuggling a path through it", async () => {
    const t = await tier();
    const p = await task(t, "build");
    await expect(task(t, "a/b", { parent: p.certificates.signing })).rejects.toThrow(/segment/);
    await expect(task(t, "..", { parent: p.certificates.signing })).rejects.toThrow(/segment/);
  });
});

describe("a re-mint is the same task, again", () => {
  it("same name, same identity, new serial — what a resumed machine does", async () => {
    const t = await tier();
    const a = await task(t, "rosary-056d96");
    const b = await task(t, "rosary-056d96");
    expect(b.identity).toBe(a.identity);
    expect(new X509Certificate(b.certificates.signing).serialNumber).not.toBe(new X509Certificate(a.certificates.signing).serialNumber);
  });
});
