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
import { mintIssuingCaCert, mintTaskCertPair, certTaskScope, OID_CRITERIA } from "./cert-authority";
import { checkCriteria, encodeCriteria, type Criteria } from "./criteria";
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

async function machine(tierScopes = ["bridgeCert", "sign:git"], criteria?: Criteria[]) {
  const ca = await gen();
  const rootCert = await X509CertificateGenerator.createSelfSigned({
    name: "CN=signet-authority,O=notme",
    notBefore: new Date(Date.now() - 60_000), notAfter: new Date(Date.now() + 3600_000),
    signingAlgorithm: ED25519, keys: ca, serialNumber: "01",
    extensions: [new BasicConstraintsExtension(true, 1, true), new KeyUsagesExtension(KeyUsageFlags.keyCertSign, true)],
  });
  const keys = await gen();
  const tier = await mintIssuingCaCert("alice", MACHINE_ID, await pem(keys.publicKey), ca.privateKey,
    { scopes: tierScopes, epoch: 1, authMethod: "passkey", criteria });
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

// ── Resuming after a long pause: the tier has expired ───────────────────────
//
// THE PAUSE/RESUME QUESTION, asked of the code. A microVM suspended for
// longer than its tier's lifetime (default 1h) resumes holding a tier that is
// already past `notAfter`. The TTL clamp is
// `Math.max(0, Math.min(requestedTtl, untilTierExpiry))`, so a negative
// remaining lifetime floors to ZERO and the mint SUCCEEDS — handing back a
// certificate whose notBefore equals its notAfter. Valid for zero seconds,
// indistinguishable at the call site from a working credential, and it fails
// later at whatever first tries to use it, with an expiry error that points
// at the task rather than at the expired tier that actually caused it.
//
// Minting a corpse is worse than refusing: the caller's recovery for "my
// tier expired" is to re-enrol the machine, and nothing in a zero-second
// certificate tells it that.
describe("a tier past its own notAfter cannot mint (pause/resume)", () => {
  async function expiredTier(ageMs: number) {
    const ca = await gen();
    const keys = await gen();
    const tier = await mintIssuingCaCert(
      "alice", MACHINE_ID, await pem(keys.publicKey), ca.privateKey,
      { scopes: ["bridgeCert"], epoch: 1, authMethod: "passkey", ttlMs: -ageMs },
    );
    return { tier, keys };
  }

  const taskOpts = { task: "t", goalHash: GOAL, scopes: ["bridgeCert"], epoch: 1 };

  it("refuses, naming the tier's expiry rather than minting a zero-second cert", async () => {
    const { tier, keys } = await expiredTier(60_000);
    const mtls = await genP256();
    const signing = await gen();

    await expect(
      mintTaskCertPair(
        tier.certificate, keys.privateKey,
        await pem(mtls.publicKey), await pem(signing.publicKey), taskOpts,
      ),
    ).rejects.toThrow(/tier certificate expired/i);
  });

  it("still mints while the tier has life left, clamped to it", async () => {
    // The control: the refusal must be about EXPIRY, not about a short tier.
    // A tier with 30s left is usable, and the task inherits that bound.
    const ca = await gen();
    const keys = await gen();
    const tier = await mintIssuingCaCert(
      "alice", MACHINE_ID, await pem(keys.publicKey), ca.privateKey,
      { scopes: ["bridgeCert"], epoch: 1, authMethod: "passkey", ttlMs: 30_000 },
    );
    const mtls = await genP256();
    const signing = await gen();

    const task = await mintTaskCertPair(
      tier.certificate, keys.privateKey,
      await pem(mtls.publicKey), await pem(signing.publicKey),
      { ...taskOpts, ttlMs: 5 * 60_000 },
    );
    const tierExp = new X509Certificate(tier.certificate).notAfter.getTime();
    const taskExp = new X509Certificate(task.certificates.mtls).notAfter.getTime();
    expect(taskExp).toBeLessThanOrEqual(tierExp);
    expect(taskExp).toBeGreaterThan(Date.now()); // genuinely usable, not a corpse
  });
});

describe("criteria: the minter refuses criteria its tier did not grant (notme-bdc850)", () => {
  const AS: Criteria = { name: "agent-session", version: 1 };
  const LLO: Criteria = { name: "llo-run", version: 1 };
  const DEP: Criteria = { name: "deploy", version: 1 };
  const mint = async (m: Awaited<ReturnType<typeof machine>>, o: { criteria?: Criteria; scopes?: string[]; ttlMs?: number } = {}) => {
    const k = await taskKeys();
    return mintTaskCertPair(m.tier.certificate, m.keys.privateKey, k.mtlsPem, k.signingPem, {
      task: "bead-1", goalHash: GOAL, scopes: o.scopes ?? ["bridgeCert"], epoch: 1, ttlMs: o.ttlMs, criteria: o.criteria,
    });
  };

  it("an honest mint under an agent-session/1 tier stamps .1.10 and checks as not legacy", async () => {
    const m = await machine(undefined, [AS]);
    const task = await mint(m, { criteria: AS, scopes: ["sign:git"] });
    const tier = new X509Certificate(m.tier.certificate);
    for (const pem of [task.certificates.signing, task.certificates.mtls]) {
      const c = new X509Certificate(pem);
      const ext = c.getExtension(OID_CRITERIA)!;
      expect(ext.critical).toBe(false);
      expect(new Uint8Array(ext.value)).toEqual(encodeCriteria([AS]));
      expect(checkCriteria(tier, c)).toEqual({ ok: true, criteria: AS, legacy: false });
    }
  });

  it("a legacy tier with no criteria mints a task that checks as legacy", async () => {
    const m = await machine();
    const task = await mint(m);
    const c = new X509Certificate(task.certificates.signing);
    expect(c.getExtension(OID_CRITERIA)).toBeNull();
    expect(checkCriteria(new X509Certificate(m.tier.certificate), c)).toEqual({ ok: true, criteria: null, legacy: true });
  });

  it("rule 6: the tier carries criteria and the task names none", async () => {
    const m = await machine(undefined, [AS]);
    await expect(mint(m)).rejects.toThrow(/^tier carries criteria; the task names none$/);
  });

  it("rule 5: the task names criteria its tier does not carry", async () => {
    const m = await machine();
    await expect(mint(m, { criteria: AS })).rejects.toThrow(/^task claims criteria its tier does not carry$/);
  });

  it("rule 9: criteria not in the tier's list", async () => {
    const m = await machine(undefined, [AS]);
    await expect(mint(m, { criteria: LLO })).rejects.toThrow(/^task criteria llo-run\/1 is not granted by its tier$/);
  });

  it("rule 8: deploy/1 is the authority's to mint, never a tier's", async () => {
    const m = await machine(undefined, [DEP]);
    await expect(mint(m, { criteria: DEP })).rejects.toThrow(/^deploy\/1 is minted by the authority only$/);
  });

  it("llo-run/1 is refused until LLO supplies the confinementDigest", async () => {
    const m = await machine(undefined, [LLO]);
    await expect(mint(m, { criteria: LLO })).rejects.toThrow(
      "llo-run/1 needs the run's confinementDigest from the LLO host; supplied from phase 5 (notme-bdffc7)",
    );
  });

  it("rule 10: a lifetime past the criteria's maximum", async () => {
    const m = await machine(undefined, [AS]);
    await expect(mint(m, { criteria: AS, ttlMs: 301_000 })).rejects.toThrow(
      /^agent-session\/1 allows at most 300s, this certificate spans 301s$/,
    );
    await expect(mint(m, { criteria: AS, ttlMs: 300_000 })).resolves.toBeDefined();
  });

  it("rule 11: a scope the tier holds but the criteria's ceiling does not", async () => {
    const m = await machine(["bridgeCert", "certMint"], [AS]);
    await expect(mint(m, { criteria: AS, scopes: ["certMint"] })).rejects.toThrow(
      /^agent-session\/1 does not allow scope certMint$/,
    );
  });
});
