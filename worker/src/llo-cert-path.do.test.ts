/// <reference types="@cloudflare/vitest-plugin/types" />
/**
 * llo-cert-path.do.test.ts — LLO's released verifier, running in workerd,
 * accepts a task chain under a REAL SigningAuthority's root (notme-bc4cd2).
 *
 * The plain-pool twin (src/__tests__/llo-cert-path.test.ts) mints the tier
 * with mintIssuingCaCert directly and carries the full refusal matrix. This
 * file closes the two gaps that one leaves:
 *
 *   - the ROOT is the Durable Object's own: its key, its subject (via
 *     #rootForMint) and its epoch, through SigningAuthority.mintIssuingCa —
 *     the call POST /cert/issuing-ca makes — and the anchor is the raw key
 *     the authority publishes in CABundle.keys (getPublicKeyRawB64);
 *   - the HOST is workerd, where cloister runs the same artifact. The wasm
 *     lives in an auxiliary worker reached as env.LLO_SIGN; see
 *     vitest.workers.config.mts for why, and for the pin check on its bytes.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { X509Certificate } from "@peculiar/x509";
import { describe, expect, it } from "vitest";
import { PROFILE_SIGNET } from "./__tests__/helpers/llo-sign";
import { mintTaskCertPair } from "./cert-authority";
import { ED25519 } from "./platform";

interface AuthLike {
  mintIssuingCa(p: {
    subject: string;
    identity: string;
    publicKeyPem: string;
    scopes: string[];
    authMethod: string;
  }): Promise<{ certificate: string; authority: { epoch: number } }>;
  getPublicKeyRawB64(): Promise<string>;
}

async function spkiPem(k: CryptoKey): Promise<string> {
  const b = new Uint8Array((await crypto.subtle.exportKey("spki", k)) as ArrayBuffer);
  return `-----BEGIN PUBLIC KEY-----\n${btoa(String.fromCharCode(...b)).match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
}
const der = (pem: string) => new Uint8Array(new X509Certificate(pem).rawData);
const fromB64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const ed = () => crypto.subtle.generateKey(ED25519, true, ["sign", "verify"]) as Promise<CryptoKeyPair>;

describe("LLO leyline_sign.wasm in workerd, under a real SigningAuthority root (notme-bc4cd2)", () => {
  it("verifies root → issuing CA → task with expected_profile=2", async () => {
    const llo = env.LLO_SIGN;
    if (!llo) throw new Error("LLO_SIGN is not bound (vitest.workers.config.mts)");

    const name = `llo-path-${crypto.randomUUID()}`;
    const tierKey = await ed();
    const stub = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(name));
    const { tier, epoch, anchor } = await runInDurableObject(stub, async (auth) => {
      const a = auth as unknown as AuthLike;
      const t = await a.mintIssuingCa({
        subject: name,
        identity: `wimse://notme.bot/principal/${name}/machine`,
        publicKeyPem: await spkiPem(tierKey.publicKey),
        scopes: ["bridgeCert"],
        authMethod: "passkey",
      });
      return { tier: t.certificate, epoch: t.authority.epoch, anchor: await a.getPublicKeyRawB64() };
    });

    const signing = await ed();
    const p256 = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const task = await mintTaskCertPair(tier, tierKey.privateKey, await spkiPem(p256.publicKey), await spkiPem(signing.publicKey), {
      task: "build",
      goalHash: "a".repeat(64),
      scopes: ["bridgeCert"],
      epoch,
    });

    const leaf = der(task.certificates.signing);
    const res = await llo.verifyCertPath(leaf, [der(tier)], fromB64(anchor), PROFILE_SIGNET);
    expect(res.ok, "LLO (in workerd) refused a chain under the authority's own root").toBe(true);
    if (!res.ok) return;
    expect(res.claims.pr).toBe("signet");
    expect(res.claims.ep).toBe(epoch);
    expect(res.claims.pf).toBeUndefined();
    expect(res.claims.sc).toBeUndefined();

    // The anchor is load-bearing here too: another authority's root key does
    // not verify this chain.
    const otherStub = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(`${name}-other`));
    const otherAnchor = await runInDurableObject(otherStub, (auth) => (auth as unknown as AuthLike).getPublicKeyRawB64());
    expect(otherAnchor).not.toBe(anchor);
    expect((await llo.verifyCertPath(leaf, [der(tier)], fromB64(otherAnchor), PROFILE_SIGNET)).ok).toBe(false);
  });
});
