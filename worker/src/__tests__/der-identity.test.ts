/**
 * der-identity.test.ts — every certificate shape notme mints, byte for byte
 * (notme-3ee3b0).
 *
 * WHY. @peculiar/x509 builds every certificate this authority issues, and a
 * dependency bump that re-encodes a single field changes what verifiers in
 * other repos (signet, ley-line, gen/go/verify) receive without any of our
 * own round-trip tests noticing: ours read back what ours wrote. So each mint
 * path runs here under a pinned clock, fixed keys and a deterministic
 * getRandomValues (serials), and the SHA-256 of its DER is pinned. Ed25519
 * signatures are deterministic (RFC 8032), so the whole certificate,
 * signature included, is reproducible.
 *
 * A failure here means the bytes changed. Find out which field and why
 * before touching the table: regenerating it is how a silent re-encoding
 * would ship.
 *
 *   DER_OUT=/some/dir pnpm exec vitest run src/__tests__/der-identity.test.ts
 *
 * writes each DER plus a SHA256SUMS file there, for a byte diff across two
 * trees.
 *
 * The CA root is not minted through the Durable Object (this suite runs in
 * plain Node); it repeats SigningAuthority.getCACertificatePem's
 * createSelfSigned call with the same name, extensions and validity rule.
 */
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  BasicConstraintsExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  X509Certificate,
  X509CertificateGenerator,
} from "@peculiar/x509";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  mintBridgeCertPair,
  mintGHABridgeCert,
  mintIssuingCaCert,
  mintTaskCertPair,
} from "../cert-authority";
import { ctPoisonExtension, serialiseSct, sctListExtension } from "../ct/sct";
import { precertTbs } from "../ct/verify-sct";

const ED = { name: "Ed25519" } as any;
const T0 = new Date("2026-11-04T12:00:00.000Z");

/** Ed25519 PKCS#8 for a 32-byte seed (RFC 8410 §7). */
function edPkcs8(seedByte: number): Uint8Array {
  const prefix = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
  return new Uint8Array([...prefix, ...new Array(32).fill(seedByte)]);
}

async function edKeyPair(seedByte: number): Promise<{ privateKey: CryptoKey; publicKey: CryptoKey; pem: string }> {
  const privateKey = await crypto.subtle.importKey("pkcs8", edPkcs8(seedByte), ED, true, ["sign"]);
  const jwk = (await crypto.subtle.exportKey("jwk", privateKey)) as JsonWebKey;
  const publicKey = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: jwk.x }, ED, true, ["verify"]);
  return { privateKey, publicKey, pem: await spkiPem(publicKey) };
}

async function spkiPem(key: CryptoKey): Promise<string> {
  const der = new Uint8Array((await crypto.subtle.exportKey("spki", key)) as ArrayBuffer);
  return `-----BEGIN PUBLIC KEY-----\n${Buffer.from(der).toString("base64").match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----\n`;
}

/** TEST-ONLY public key. The private half was discarded. */
const MTLS_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "qvhjBABP4WE1u07Iz2FhCUpMPRbymLsqhagLJ7p5gog",
  y: "IbTolQC7JxWcb8hH5VJKE0S90Z-dBSaT6C7kTxcWUTs",
};

const pemDer = (pem: string): Uint8Array =>
  new Uint8Array(Buffer.from(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64"));
const sha256 = (b: Uint8Array): string => createHash("sha256").update(b).digest("hex");

/**
 * Pinned 2026-11-04 on goalzero 5e35a2e with @peculiar/x509 1.14.3, before
 * the 3.x bump.
 */
const EXPECTED: Record<string, string> = {
  "root": "9370a0c5b3fd67880eb6402a2d0155dab5516c5330a461dc9d0877ead2fabfc8",
  "gha": "380fd29c2fa9cf76b160ebd7854779353b8279d99ce0cbd2dc59bb52ba560a99",
  "bridge-mtls": "b191b86f41edfd311e9065709cb778b298d5290fb3ab5d2f8ee9a847faa4e590",
  "bridge-signing": "fab7bdcbfe6fbc0b34b740855523bb67c6e602d6dfc5eff2240983a0f9c8dd00",
  "tier": "e860b11e000b6048886a8602aee98694fea3634dd84f39cc90d0b8d0fd4fe4e7",
  "tier-criteria": "afec5b2f9e60d6ea1e84fb11d74501d6d7cc317ce6612bba3512ec3a72f15bab",
  "task-mtls": "bdcde9fc172f780b8e2c1bf126036d8d6f1deb6aefc18ae293607df65f6f3b3d",
  "task-signing": "545799182035d70f5baaf979dca014c1e6d920d924ef7486f26a555e544d1b18",
  "task-criteria-mtls": "832e1b64614121513ad0975d612ef92cc1db0a6e5089dadddcc0f075d34bea9a",
  "task-criteria-signing": "5e4e23c928b115c9506c24e1513689f38b6ba7193c7db99aaaa23374a412daaf",
  "subtask-signing": "08fb8ef66e28acce1d43351b2940e0e5f5816bca4b31d553a2cf65313485d550",
  "precert-mtls": "55b5a999a4a00ff11bb2b6d686058bfac1815a54f2cad0f1ecf40896ba0da80d",
  "precert-mtls-tbs": "359fd5fda63dd561666a5b6b798900c0cf60891d5220618e1502e720dbb962a5",
  "precert-signing-tbs": "a0b89e6ebc57afdbfc5b570e1e061f115805925fde4b47b201cb6fcfd7d4f42a",
  "final-sct-mtls": "58002b5c08f6f370789d60d5443f380ebf679b5f699adfe4b492d81347f94540",
  "tier-precert-tbs": "2676c412be9f182731aa66f44cd392bde956e36f6f4121a2c588d26675f3dd86",
};

const minted: Record<string, Uint8Array> = {};

describe("DER byte identity of every mint path (notme-3ee3b0)", () => {
  beforeAll(async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(T0);
    // Deterministic serials: a counter stream, so each call gets distinct bytes.
    let n = 0;
    vi.spyOn(crypto, "getRandomValues").mockImplementation(((a: ArrayBufferView) => {
      const u = new Uint8Array(a.buffer, a.byteOffset, a.byteLength);
      for (let i = 0; i < u.length; i++) u[i] = (n * 31 + i * 7 + 1) & 0xff;
      n++;
      return a;
    }) as typeof crypto.getRandomValues);

    const root = await edKeyPair(0x01);
    const tierKey = await edKeyPair(0x02);
    const signingLeaf = await edKeyPair(0x03);
    const mtlsPub = await crypto.subtle.importKey("jwk", MTLS_JWK, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
    const mtlsPem = await spkiPem(mtlsPub);
    const ROOT_NAME = "CN=signet-authority,O=notme";

    // CA root: SigningAuthority.getCACertificatePem (CA_PATH_LEN = 1, 10 y).
    const rootCert = await X509CertificateGenerator.createSelfSigned({
      name: ROOT_NAME,
      notBefore: T0,
      notAfter: new Date(T0.getTime() + 10 * 365.25 * 24 * 60 * 60 * 1000),
      signingAlgorithm: ED,
      keys: { privateKey: root.privateKey, publicKey: root.publicKey },
      serialNumber: "0102030405060708090a0b0c0d0e0f10",
      extensions: [
        new BasicConstraintsExtension(true, 1, true),
        new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign, true),
      ],
    });
    minted["root"] = new Uint8Array(rootCert.rawData);

    const gha = await mintGHABridgeCert("repo:agentic-research/notme:ref:refs/heads/main", mtlsPem, root.privateKey);
    minted["gha"] = pemDer(gha.certificate);

    const pairOpts = { scopes: ["bridgeCert", "sign:git"], epoch: 3, authMethod: "passkey" };
    const pair = await mintBridgeCertPair("alice", "wimse://notme.bot/principal/alice", mtlsPem, signingLeaf.pem, root.privateKey, pairOpts);
    minted["bridge-mtls"] = pemDer(pair.certificates.mtls);
    minted["bridge-signing"] = pemDer(pair.certificates.signing);

    const tierOpts = { scopes: ["bridgeCert", "sign:git", "certMint"], epoch: 3, authMethod: "passkey" };
    const tier = await mintIssuingCaCert("alice", "wimse://notme.bot/principal/alice", tierKey.pem, root.privateKey, tierOpts);
    minted["tier"] = pemDer(tier.certificate);
    const tierCrit = await mintIssuingCaCert("alice", "wimse://notme.bot/principal/alice", tierKey.pem, root.privateKey, {
      ...tierOpts,
      criteria: [{ name: "agent-session", version: 1 }],
    });
    minted["tier-criteria"] = pemDer(tierCrit.certificate);

    const goalHash = "ab".repeat(32);
    const task = await mintTaskCertPair(tier.certificate, tierKey.privateKey, mtlsPem, signingLeaf.pem, {
      task: "rosary-056d96",
      goalHash,
      scopes: ["bridgeCert"],
      epoch: 3,
    });
    minted["task-mtls"] = pemDer(task.certificates.mtls);
    minted["task-signing"] = pemDer(task.certificates.signing);
    const taskCrit = await mintTaskCertPair(tierCrit.certificate, tierKey.privateKey, mtlsPem, signingLeaf.pem, {
      task: "rosary-056d96",
      goalHash,
      scopes: ["bridgeCert"],
      epoch: 3,
      criteria: { name: "agent-session", version: 1 },
    });
    minted["task-criteria-mtls"] = pemDer(taskCrit.certificates.mtls);
    minted["task-criteria-signing"] = pemDer(taskCrit.certificates.signing);
    // A subtask: the parent-derived path of mintTaskCertPair.
    const sub = await mintTaskCertPair(tier.certificate, tierKey.privateKey, mtlsPem, signingLeaf.pem, {
      task: "step-1",
      goalHash,
      scopes: ["bridgeCert"],
      epoch: 3,
      parent: task.certificates.signing,
    });
    minted["subtask-signing"] = pemDer(sub.certificates.signing);

    // CT: the precertificate pair under a pin, its TBS as the log signs it,
    // and the final certificate with an embedded SCT list.
    const pin = {
      serialMtls: "11".repeat(16),
      serialSigning: "22".repeat(16),
      notBefore: T0,
      notAfter: new Date(T0.getTime() + 5 * 60 * 1000),
    };
    const pre = await mintBridgeCertPair("alice", "wimse://notme.bot/principal/alice", mtlsPem, signingLeaf.pem, root.privateKey, {
      ...pairOpts,
      pin,
      perCertExtensions: { mtls: [ctPoisonExtension()], signing: [ctPoisonExtension()] },
    });
    minted["precert-mtls"] = pemDer(pre.certificates.mtls);
    minted["precert-mtls-tbs"] = precertTbs(minted["precert-mtls"]);
    minted["precert-signing-tbs"] = precertTbs(pemDer(pre.certificates.signing));
    const sct = serialiseSct({
      sct_version: 0,
      id: Buffer.alloc(32, 0x42).toString("base64"),
      timestamp: T0.getTime(),
      extensions: "AAAFAAAAAAA=",
      signature: Buffer.from([4, 3, 0, 2, 0xaa, 0xbb]).toString("base64"),
    });
    const fin = await mintBridgeCertPair("alice", "wimse://notme.bot/principal/alice", mtlsPem, signingLeaf.pem, root.privateKey, {
      ...pairOpts,
      pin,
      perCertExtensions: { mtls: [sctListExtension([sct])], signing: [sctListExtension([sct])] },
    });
    minted["final-sct-mtls"] = pemDer(fin.certificates.mtls);
    const tierPre = await mintIssuingCaCert("alice", "wimse://notme.bot/principal/alice", tierKey.pem, root.privateKey, {
      ...tierOpts,
      pin: { serial: "33".repeat(16), notBefore: T0, notAfter: new Date(T0.getTime() + 60 * 60 * 1000) },
      extraExtensions: [ctPoisonExtension()],
    });
    minted["tier-precert-tbs"] = precertTbs(pemDer(tierPre.certificate));

    const out = process.env.DER_OUT;
    if (out) {
      mkdirSync(out, { recursive: true });
      const sums: string[] = [];
      for (const [name, der] of Object.entries(minted)) {
        writeFileSync(join(out, `${name}.der`), der);
        sums.push(`${sha256(der)}  ${name}.der`);
      }
      writeFileSync(join(out, "SHA256SUMS"), sums.join("\n") + "\n");
    }
  });

  afterAll(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("covers every mint path", () => {
    expect(Object.keys(minted).sort()).toEqual(Object.keys(EXPECTED).sort());
  });

  it.each(Object.keys(EXPECTED))("%s is byte-identical to the pinned DER", (name) => {
    expect(sha256(minted[name]!)).toBe(EXPECTED[name]);
  });

  it("every certificate still parses (sanity, not identity)", () => {
    for (const [name, der] of Object.entries(minted)) {
      if (name.endsWith("-tbs")) continue;
      expect(() => new X509Certificate(der), name).not.toThrow();
    }
  });
});
