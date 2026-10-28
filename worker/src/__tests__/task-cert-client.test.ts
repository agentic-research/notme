/**
 * task-cert-client.test.ts — the client a MACHINE runs to hold a tier and mint
 * task certificates offline (notme-486e8a).
 *
 * The authority half is covered end to end in tier-enrolment.do.test.ts. This
 * file covers what runs on the machine: the proof it sends, the device-flow
 * poll, minting offline, and the chain check — against a locally built root
 * and tier, because the point of a task cert is that minting needs no
 * authority at all.
 */
import { X509Certificate, X509CertificateGenerator, BasicConstraintsExtension, KeyUsagesExtension, KeyUsageFlags } from "@peculiar/x509";
import { describe, expect, it } from "vitest";
import { mintIssuingCaCert } from "../cert-authority";
import { ED25519 } from "../platform";
import { deviceCodeHash, tierEnrolmentBinding } from "../auth/tier-enrolment-binding";
import {
  generateTierKey, enrolProof, pollEnrolment, mintTask, verifyChain, groupFingerprint,
  exportPrivateKeyPem, importPrivateKeyPem,
} from "../../../scripts/task-cert/lib";

const ROOT_NAME = "CN=signet-authority,O=notme";

async function rootAndTier(opts: { tierTtlMs?: number } = {}) {
  const root = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
  const rootCert = await X509CertificateGenerator.createSelfSigned({
    name: ROOT_NAME,
    notBefore: new Date(Date.now() - 86_400_000),
    notAfter: new Date(Date.now() + 86_400_000 * 365),
    signingAlgorithm: ED25519,
    keys: root,
    serialNumber: "01",
    extensions: [
      new BasicConstraintsExtension(true, 1, true),
      new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign, true),
    ],
  });
  const tier = await generateTierKey();
  const tierCert = await mintIssuingCaCert(
    "alice",
    "wimse://notme.bot/principal/alice",
    tier.pem,
    root.privateKey,
    { scopes: ["bridgeCert"], epoch: 3, authMethod: "passkey", ttlMs: opts.tierTtlMs },
  );
  return { rootPem: rootCert.toString("pem"), tier, tierPem: tierCert.certificate };
}

describe("the enrolment proof", () => {
  it("verifies under the SHARED binding the authority checks", async () => {
    const k = await generateTierKey();
    const proof = await enrolProof(k.privateKey, k.spki, "device-code-1");
    const sig = Uint8Array.from(atob(proof.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (proof.length % 4)) % 4)), (c) => c.charCodeAt(0));
    const input = tierEnrolmentBinding(k.spki, await deviceCodeHash("device-code-1"));
    expect(await crypto.subtle.verify(ED25519, k.publicKey, sig, input)).toBe(true);
    // Bound to the device code: the same key over a different code fails.
    const other = tierEnrolmentBinding(k.spki, await deviceCodeHash("device-code-2"));
    expect(await crypto.subtle.verify(ED25519, k.publicKey, sig, other)).toBe(false);
  });

  it("fingerprints group in fours, matching the approval page", () => {
    expect(groupFingerprint("546b822cdad7f8c9aaaa")).toBe("546b 822c dad7 f8c9");
  });
});

describe("the private key survives a round trip to disk format", () => {
  it("PKCS#8 PEM out, non-extractable key back, still signs", async () => {
    const k = await generateTierKey();
    const back = await importPrivateKeyPem(await exportPrivateKeyPem(k.privateKey));
    expect(back.extractable).toBe(false);
    const msg = new TextEncoder().encode("x");
    const sig = await crypto.subtle.sign(ED25519, back, msg);
    expect(await crypto.subtle.verify(ED25519, k.publicKey, sig, msg)).toBe(true);
  });
});

describe("polling the device flow", () => {
  const reply = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });

  it("waits through authorization_pending, then returns the tier", async () => {
    const seq = [
      reply(400, { error: "authorization_pending" }),
      reply(400, { error: "authorization_pending" }),
      reply(200, { certificate: "PEM", authority: { epoch: 3 } }),
    ];
    let calls = 0;
    const r = await pollEnrolment("https://a.example", "dc", "proof", {
      interval: 0, expiresIn: 60, fetchFn: (async () => seq[calls++]!) as any, sleep: async () => {},
    });
    expect(calls).toBe(3);
    expect(r.certificate).toBe("PEM");
  });

  it("stops on a terminal error instead of polling forever", async () => {
    for (const error of ["expired_token", "invalid_grant", "invalid_proof"]) {
      let calls = 0;
      await expect(
        pollEnrolment("https://a.example", "dc", "p", {
          interval: 0, expiresIn: 60,
          fetchFn: (async () => { calls++; return reply(error === "invalid_proof" ? 401 : 400, { error }); }) as any,
          sleep: async () => {},
        }),
      ).rejects.toThrow(error);
      expect(calls).toBe(1);
    }
  });
});

describe("minting a task certificate offline", () => {
  it("produces a pair that chains root → tier → task, named for the task", async () => {
    const { rootPem, tier, tierPem } = await rootAndTier();
    const t = await mintTask(tierPem, tier.privateKey, { task: "rosary-056d96", goal: "dispatch identity", epoch: 3 });
    expect(t.identity).toBe("wimse://notme.bot/principal/alice/rosary-056d96");
    for (const leaf of [t.certificates.signing, t.certificates.mtls]) {
      expect(await verifyChain(rootPem, tierPem, leaf)).toEqual({ ok: true });
    }
  });

  it("commits to the goal: the goal hash is SHA-256 of the goal text", async () => {
    const { tier, tierPem } = await rootAndTier();
    const t = await mintTask(tierPem, tier.privateKey, { task: "t1", goal: "the goal", epoch: 3 });
    const want = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("the goal"))))
      .map((b) => b.toString(16).padStart(2, "0")).join("");
    expect(t.goalHash).toBe(want);
  });

  it("verifyChain refuses a task cert from a DIFFERENT tier", async () => {
    const a = await rootAndTier();
    const b = await rootAndTier();
    const t = await mintTask(b.tierPem, b.tier.privateKey, { task: "t1", goal: "g", epoch: 3 });
    const r = await verifyChain(a.rootPem, a.tierPem, t.certificates.signing);
    expect(r.ok).toBe(false);
  });

  it("verifyChain refuses a task cert outside its validity window", async () => {
    const { rootPem, tier, tierPem } = await rootAndTier();
    const t = await mintTask(tierPem, tier.privateKey, { task: "t1", goal: "g", epoch: 3 });
    const later = new Date(Date.now() + 24 * 3600_000);
    const r = await verifyChain(rootPem, tierPem, t.certificates.signing, later);
    expect(r).toMatchObject({ ok: false });
  });

  it("refuses to mint under a tier whose key it does not hold", async () => {
    const { tierPem } = await rootAndTier();
    const wrong = await generateTierKey();
    await expect(mintTask(tierPem, wrong.privateKey, { task: "t1", goal: "g", epoch: 3 })).rejects.toThrow();
  });
});

// ── renewal, subtasks, ledger, revocation (notme-337d82, notme-9f84e6) ──────
import { renewProof, isRevokedTask, taskOutDir } from "../../../scripts/task-cert/lib";
import { tierRenewalBinding } from "../auth/tier-enrolment-binding";

describe("renewal proof", () => {
  it("verifies under the SHARED renewal binding, bound to its timestamp", async () => {
    const k = await generateTierKey();
    const iat = 1_800_000_000;
    const proof = await renewProof(k.privateKey, k.spki, iat);
    const sig = Uint8Array.from(atob(proof.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (proof.length % 4)) % 4)), (c) => c.charCodeAt(0));
    expect(await crypto.subtle.verify(ED25519, k.publicKey, sig, tierRenewalBinding(k.spki, iat))).toBe(true);
    expect(await crypto.subtle.verify(ED25519, k.publicKey, sig, tierRenewalBinding(k.spki, iat + 1))).toBe(false);
  });
});

describe("local revocation is by task PREFIX, on segment boundaries", () => {
  const revoked = ["build", "deploy/prod"];
  it("revokes the task itself and everything derived from it", () => {
    expect(isRevokedTask("build", revoked)).toBe(true);
    expect(isRevokedTask("build/compile", revoked)).toBe(true);
    expect(isRevokedTask("build/compile/linker", revoked)).toBe(true);
    expect(isRevokedTask("deploy/prod/canary", revoked)).toBe(true);
  });
  it("does not revoke a sibling that merely shares characters", () => {
    expect(isRevokedTask("build2", revoked)).toBe(false);
    expect(isRevokedTask("deploy/production", revoked)).toBe(false);
  });
  it("does not revoke an ancestor of a revoked task", () => {
    expect(isRevokedTask("deploy", revoked)).toBe(false);
  });
});

describe("task output paths", () => {
  it("nest subtasks under their parent, one directory per segment", () => {
    expect(taskOutDir("/home/u/.notme/tasks", "build/compile")).toBe("/home/u/.notme/tasks/build/compile");
  });
});
