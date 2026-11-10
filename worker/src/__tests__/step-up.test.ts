/**
 * step-up.test.ts — step-up presence certificates (ADR-024, notme-d92ba1).
 *
 * The offline half: the `.1.11` approval extension, the action's canonical
 * bytes and digest, minting a `step-up/1` certificate for a task's signing
 * key, and the verifier's two-certificate check (D7 steps 2-4; chain and
 * epoch are the caller's, as for every notme certificate).
 */
import {
  BasicConstraintsExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  X509Certificate,
  X509CertificateGenerator,
} from "@peculiar/x509";
import { beforeAll, describe, expect, it } from "vitest";
import { mintIssuingCaCert, mintTaskCertPair } from "../cert-authority";
import { checkCriteria } from "../criteria";
import { ED25519 } from "../platform";
import {
  type Approval,
  type StepUpAction,
  type StepUpPolicy,
  actionCanonical,
  actionDigest,
  checkStepUp,
  encodeApproval,
  mintStepUpCert,
  readApproval,
  stepUpChallenge,
} from "../step-up";

const GOAL = "a".repeat(64);
const ed = () => crypto.subtle.generateKey(ED25519, true, ["sign", "verify"]) as Promise<CryptoKeyPair>;
const p256 = () =>
  crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as Promise<CryptoKeyPair>;
async function pubPem(k: CryptoKey): Promise<string> {
  const b = new Uint8Array((await crypto.subtle.exportKey("spki", k)) as ArrayBuffer);
  return `-----BEGIN PUBLIC KEY-----\n${btoa(String.fromCharCode(...b)).match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
}
const sha256 = async (b: Uint8Array | ArrayBuffer) => new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(b)));
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

let rootKeys: CryptoKeyPair;
let tierPem: string;
let tierKey: CryptoKey;

beforeAll(async () => {
  rootKeys = await ed();
  await X509CertificateGenerator.createSelfSigned({
    name: "CN=signet-authority,O=notme",
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 864e5),
    signingAlgorithm: ED25519,
    keys: rootKeys,
    serialNumber: "01",
    extensions: [new BasicConstraintsExtension(true, 1, true), new KeyUsagesExtension(KeyUsageFlags.keyCertSign, true)],
  });
  const t = await ed();
  const minted = await mintIssuingCaCert("alice", "wimse://notme.bot/principal/alice", await pubPem(t.publicKey), rootKeys.privateKey, {
    scopes: ["bridgeCert"],
    epoch: 3,
    authMethod: "passkey",
  });
  tierPem = minted.certificate;
  tierKey = t.privateKey;
});

/** A task (its signing certificate) and an action it requests. */
async function taskAndAction(name = "deploy-task", params: Record<string, string> = { env: "prod", commit: "abc" }) {
  const signing = await ed();
  const pair = await mintTaskCertPair(tierPem, tierKey, await pubPem((await p256()).publicKey), await pubPem(signing.publicKey), {
    task: name,
    goalHash: GOAL,
    scopes: ["bridgeCert"],
    epoch: 3,
  });
  const taskCert = new X509Certificate(pair.certificates.signing);
  const action: StepUpAction = {
    type: "deploy",
    params,
    taskId: name,
    requesterSpkiSha256: await sha256(taskCert.publicKey.rawData),
    nonce: crypto.getRandomValues(new Uint8Array(16)),
  };
  return { taskPem: pair.certificates.signing, taskCert, action };
}

const UV = (assertedAt = new Date()): Approval => ({ approver: "alice-principal", method: "passkey-uv", assertedAt });
const POLICY: StepUpPolicy = { method: "passkey-uv", maxAgeS: 300 };

describe("the action's canonical bytes (ADR-024 D2)", () => {
  it("step-up.action.canonical — RFC 8949 §4.2 CBOR, integer keys, params sorted shorter-first then bytewise", () => {
    const a: StepUpAction = {
      type: "deploy",
      params: { commit: "abc", env: "prod" },
      taskId: "t1",
      requesterSpkiSha256: new Uint8Array(32).fill(0x11),
      nonce: new Uint8Array(16).fill(0x22),
    };
    const t = (s: string) => [0x60 + s.length, ...new TextEncoder().encode(s)];
    const want = new Uint8Array([
      0xa5,
      0x01, ...t("deploy"),
      0x02, 0xa2, ...t("env"), ...t("prod"), ...t("commit"), ...t("abc"),
      0x03, ...t("t1"),
      0x04, 0x58, 0x20, ...new Array(32).fill(0x11),
      0x05, 0x50, ...new Array(16).fill(0x22),
    ]);
    expect(hex(actionCanonical(a))).toBe(hex(want));
  });

  it("step-up.action.challenge — the WebAuthn challenge is SHA-256('notme-step-up-v1:' || canonical), the goal hash SHA-256(canonical)", async () => {
    const { action } = await taskAndAction();
    const c = actionCanonical(action);
    const prefixed = new Uint8Array([...new TextEncoder().encode("notme-step-up-v1:"), ...c]);
    expect(hex(await stepUpChallenge(action))).toBe(hex(await sha256(prefixed)));
    expect(await actionDigest(action)).toBe(hex(await sha256(c)));
  });
});

describe(".1.11 approval (ADR-024 D4)", () => {
  it("step-up.approval.round-trip — approver, method and assertedAt read back", async () => {
    const { taskPem, action } = await taskAndAction();
    const at = new Date(Math.floor(Date.now() / 1000) * 1000);
    const cert = new X509Certificate(await mintStepUpCert(rootKeys.privateKey, taskPem, { action, approval: UV(at), epoch: 3 }));
    const r = readApproval(cert);
    expect(r).toEqual({ present: true, ok: true, approval: { approver: "alice-principal", method: "passkey-uv", assertedAt: at } });
  });

  it("step-up.approval.malformed — an unknown method, a bad time or trailing bytes is reported, never thrown", () => {
    const tlv = (tag: number, body: number[]) => [tag, body.length, ...body];
    const utf8 = (x: string) => tlv(0x0c, [...new TextEncoder().encode(x)]);
    const gt = (x: string) => tlv(0x18, [...new TextEncoder().encode(x)]);
    const der = (...parts: number[][]) => new Uint8Array(tlv(0x30, parts.flat()));
    const src = (v: Uint8Array) => ({ getExtension: () => ({ value: v.slice().buffer }) });

    const good = der(utf8("alice"), utf8("passkey-uv"), gt("20261109120000Z"));
    expect(hex(encodeApproval({ approver: "alice", method: "passkey-uv", assertedAt: new Date("2026-11-09T12:00:00Z") }))).toBe(hex(good));
    expect(readApproval(src(good))).toMatchObject({ present: true, ok: true });

    for (const bad of [
      der(utf8("alice"), utf8("password"), gt("20261109120000Z")),
      der(utf8("alice"), utf8("passkey-uv"), gt("2026-11-09")),
      der(utf8("alice"), utf8("passkey-uv")),
      new Uint8Array([...good, 0x00]),
      der(utf8(""), utf8("passkey-uv"), gt("20261109120000Z")),
    ]) {
      expect(readApproval(src(bad))).toMatchObject({ present: true, ok: false });
    }
    expect(readApproval({ getExtension: () => null })).toEqual({ present: false });
  });
});

describe("minting a step-up certificate (ADR-024 D1, D3)", () => {
  it("step-up.mint.shape — certifies the task's signing key, chains to the root, and is a valid step-up/1 for at most 300 s", async () => {
    const { taskPem, taskCert, action } = await taskAndAction();
    const cert = new X509Certificate(await mintStepUpCert(rootKeys.privateKey, taskPem, { action, approval: UV(), epoch: 3 }));
    expect(hex(new Uint8Array(cert.publicKey.rawData))).toBe(hex(new Uint8Array(taskCert.publicKey.rawData)));
    expect(await cert.verify({ publicKey: rootKeys.publicKey, signatureOnly: true })).toBe(true);
    const verdict = checkCriteria(null, cert);
    expect(verdict).toMatchObject({ ok: true, criteria: { name: "step-up", version: 1 } });
    expect(cert.notAfter.getTime() - cert.notBefore.getTime()).toBeLessThanOrEqual(300_000);
  });

  it("step-up.mint.refuses-mismatch — an action naming another task or another key is not minted", async () => {
    const { taskPem, action } = await taskAndAction();
    await expect(
      mintStepUpCert(rootKeys.privateKey, taskPem, { action: { ...action, taskId: "other" }, approval: UV(), epoch: 3 }),
    ).rejects.toThrow(/task/);
    await expect(
      mintStepUpCert(rootKeys.privateKey, taskPem, {
        action: { ...action, requesterSpkiSha256: new Uint8Array(32) },
        approval: UV(),
        epoch: 3,
      }),
    ).rejects.toThrow(/key/);
  });
});

describe("the verifier's two-certificate check (ADR-024 D7)", () => {
  async function minted(approval = UV()) {
    const t = await taskAndAction();
    const stepUp = new X509Certificate(await mintStepUpCert(rootKeys.privateKey, t.taskPem, { action: t.action, approval, epoch: 3 }));
    return { ...t, stepUp };
  }

  it("step-up.check.accepts — the task, its step-up and the same action pass", async () => {
    const m = await minted();
    expect(await checkStepUp(m.taskCert, m.stepUp, m.action, POLICY, new Date())).toEqual({ ok: true });
  });

  it("step-up.check.wrong-action — another action (changed params) is refused", async () => {
    const m = await minted();
    const other = { ...m.action, params: { ...m.action.params, env: "staging" } };
    expect(await checkStepUp(m.taskCert, m.stepUp, other, POLICY, new Date())).toMatchObject({ ok: false });
  });

  it("step-up.check.spki-mismatch — a step-up presented with a different task's certificate is refused", async () => {
    const m = await minted();
    const other = await taskAndAction();
    expect(await checkStepUp(other.taskCert, m.stepUp, m.action, POLICY, new Date())).toMatchObject({ ok: false });
  });

  it("step-up.check.other-task — a step-up for another task id is refused", async () => {
    const a = await taskAndAction("task-a");
    const b = await taskAndAction("task-b");
    const stepUpB = new X509Certificate(await mintStepUpCert(rootKeys.privateKey, b.taskPem, { action: b.action, approval: UV(), epoch: 3 }));
    expect(await checkStepUp(a.taskCert, stepUpB, b.action, POLICY, new Date())).toMatchObject({ ok: false });
  });

  it("step-up.check.weaker-method — passkey-up does not satisfy a passkey-uv policy; it satisfies passkey-up", async () => {
    const m = await minted({ approver: "alice-principal", method: "passkey-up", assertedAt: new Date() });
    expect(await checkStepUp(m.taskCert, m.stepUp, m.action, POLICY, new Date())).toMatchObject({ ok: false });
    expect(await checkStepUp(m.taskCert, m.stepUp, m.action, { method: "passkey-up", maxAgeS: 300 }, new Date())).toEqual({ ok: true });
  });

  it("step-up.check.max-age — refused once assertedAt + maxAge is before the action's time", async () => {
    const m = await minted();
    const asserted = readApproval(m.stepUp) as { approval: { assertedAt: Date } };
    const late = new Date(asserted.approval.assertedAt.getTime() + 61_000);
    expect(await checkStepUp(m.taskCert, m.stepUp, m.action, { method: "passkey-uv", maxAgeS: 60 }, late)).toMatchObject({ ok: false });
    // Control: inside the window.
    const inside = new Date(asserted.approval.assertedAt.getTime() + 59_000);
    expect(await checkStepUp(m.taskCert, m.stepUp, m.action, { method: "passkey-uv", maxAgeS: 60 }, inside)).toEqual({ ok: true });
  });

  it("step-up.check.no-approval — a step-up/1 certificate without .1.11 is refused", async () => {
    const m = await minted();
    // The same certificate, re-signed by the root without its approval extension.
    const stripped = await X509CertificateGenerator.create({
      subject: m.stepUp.subject,
      issuer: m.stepUp.issuer,
      notBefore: m.stepUp.notBefore,
      notAfter: m.stepUp.notAfter,
      signingAlgorithm: ED25519,
      publicKey: await m.stepUp.publicKey.export(),
      signingKey: rootKeys.privateKey,
      serialNumber: "02",
      extensions: m.stepUp.extensions.filter((e) => !e.type.endsWith(".1.11")),
    });
    expect(await checkStepUp(m.taskCert, stripped, m.action, POLICY, new Date())).toEqual({
      ok: false,
      reason: "step-up carries no approval (.1.11)",
    });
  });
});
