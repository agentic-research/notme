/**
 * llo-cert-path.test.ts — ley-line-open's RELEASED verifier accepts the
 * chains notme mints, and refuses the ones it should (notme-bc4cd2).
 *
 * Third-party verifiers of notme credentials (cloister, browsers via
 * notme-396aff) do not run notme's TypeScript. They run LLO's
 * `leyline_sign.wasm`, so the claim "a notme task credential verifies" is
 * only as good as that artifact's agreement with notme's mint paths. This
 * file runs the exact bytes LLO released — vendored under wasm/, pinned by
 * sha256 in wasm/llo-release.json and re-checked here before compiling —
 * against a chain minted by notme's own cert-authority.ts:
 *
 *   root (Ed25519, the anchor: a bare 32-byte public key)
 *     └─ issuing CA tier   mintIssuingCaCert   CA:TRUE pathlen 0
 *          └─ task          mintTaskCertPair    CA:FALSE (the Ed25519 signing cert)
 *
 * with leyline_verify_cert_path(expected_profile = 2, Signet). The same
 * check against the PRODUCTION root (a real SigningAuthority) runs in the
 * workers pool: llo-cert-path.do.test.ts.
 */
import {
  BasicConstraintsExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  X509Certificate,
  X509CertificateGenerator,
} from "@peculiar/x509";
import { beforeAll, describe, expect, it } from "vitest";
import { mintBridgeCertPair, mintGHABridgeCert, mintIssuingCaCert, mintTaskCertPair } from "../cert-authority";
import { ED25519 } from "../platform";
import { PROFILE_ANY, PROFILE_INTERLACE, PROFILE_SIGNET, type LloSign } from "./helpers/llo-sign";
import { loadLloSignVendored } from "./helpers/llo-sign-node";

const GOAL = "a".repeat(64);

const ed = () => crypto.subtle.generateKey(ED25519, true, ["sign", "verify"]) as Promise<CryptoKeyPair>;
const p256 = () =>
  crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as Promise<CryptoKeyPair>;

async function pubPem(k: CryptoKey): Promise<string> {
  const b = new Uint8Array((await crypto.subtle.exportKey("spki", k)) as ArrayBuffer);
  return `-----BEGIN PUBLIC KEY-----\n${btoa(String.fromCharCode(...b)).match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
}
const rawPub = async (k: CryptoKey) => new Uint8Array((await crypto.subtle.exportKey("raw", k)) as ArrayBuffer);
const der = (pem: string) => new Uint8Array(new X509Certificate(pem).rawData);

/** A root, exactly as SigningAuthority creates its own (signing-authority.ts). */
async function root() {
  const keys = await ed();
  await X509CertificateGenerator.createSelfSigned({
    name: "CN=signet-authority,O=notme",
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 864e5),
    signingAlgorithm: ED25519,
    keys,
    serialNumber: "01",
    extensions: [
      new BasicConstraintsExtension(true, 1, true),
      new KeyUsagesExtension(KeyUsageFlags.keyCertSign, true),
    ],
  });
  return { keys, anchor: await rawPub(keys.publicKey) };
}

async function tier(rootKey: CryptoKey, epoch: number, who = "alice") {
  const keys = await ed();
  const t = await mintIssuingCaCert(who, `wimse://notme.bot/principal/${who}`, await pubPem(keys.publicKey), rootKey, {
    scopes: ["bridgeCert"],
    epoch,
    authMethod: "passkey",
  });
  return { pem: t.certificate, key: keys.privateKey };
}

async function task(t: { pem: string; key: CryptoKey }, epoch: number, name = "build") {
  const signing = await ed();
  const pair = await mintTaskCertPair(t.pem, t.key, await pubPem((await p256()).publicKey), await pubPem(signing.publicKey), {
    task: name,
    goalHash: GOAL,
    scopes: ["bridgeCert"],
    epoch,
  });
  return { pair, signingPub: await rawPub(signing.publicKey) };
}

const b64url = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

let llo: LloSign;
beforeAll(async () => {
  llo = await loadLloSignVendored();
});

describe("LLO leyline_verify_cert_path accepts a notme root → tier → task chain (notme-bc4cd2)", () => {
  it("verifies under expected_profile=2 and reports the Signet profile", async () => {
    const r = await root();
    const t = await tier(r.keys.privateKey, 7);
    const k = await task(t, 7);

    const res = llo.verifyCertPath(der(k.pair.certificates.signing), [der(t.pem)], r.anchor, PROFILE_SIGNET);
    expect(res.ok, "LLO refused a chain notme minted").toBe(true);
    if (!res.ok) return;
    expect(res.claims.pr).toBe("signet");
    // The leaf's key is the one the task holds, and nothing Interlace-only
    // was read out of notme's .1.5/.1.6 (notme-6070fa).
    expect(res.claims.epk).toBe(b64url(k.signingPub));
    expect(res.claims.pf).toBeUndefined();
    expect(res.claims.sc).toBeUndefined();
    expect(res.claims.ep).toBe(7);
    // nb/na are the intersection over the path: never wider than the leaf.
    const leaf = new X509Certificate(k.pair.certificates.signing);
    expect(res.claims.na).toBeLessThanOrEqual(Math.floor(leaf.notAfter.getTime() / 1000));
    expect(res.claims.nb).toBeGreaterThanOrEqual(Math.floor(leaf.notBefore.getTime() / 1000));
  });

  it("ep is the MINIMUM epoch over the path, whichever certificate holds it", async () => {
    const r = await root();
    // The task's epoch is the caller's to supply (an offline machine stamps
    // the epoch it enrolled under), so both orders are reachable.
    const older = await tier(r.keys.privateKey, 3);
    const a = await task(older, 9);
    const ra = llo.verifyCertPath(der(a.pair.certificates.signing), [der(older.pem)], r.anchor, PROFILE_SIGNET);
    expect(ra.ok && ra.claims.ep).toBe(3);

    const newer = await tier(r.keys.privateKey, 9);
    const b = await task(newer, 4);
    const rb = llo.verifyCertPath(der(b.pair.certificates.signing), [der(newer.pem)], r.anchor, PROFILE_SIGNET);
    expect(rb.ok && rb.claims.ep).toBe(4);
  });

  it("the anchor binds the profile: the same chain under expected_profile=1 (Interlace) is refused", async () => {
    const r = await root();
    const t = await tier(r.keys.privateKey, 1);
    const k = await task(t, 1);
    const leaf = der(k.pair.certificates.signing);
    expect(llo.verifyCertPath(leaf, [der(t.pem)], r.anchor, PROFILE_INTERLACE).ok).toBe(false);
    // ...and "either" still reads it as Signet, so the refusal above is the
    // profile binding and not some other defect.
    const any = llo.verifyCertPath(leaf, [der(t.pem)], r.anchor, PROFILE_ANY);
    expect(any.ok && any.claims.pr).toBe("signet");
  });
});

describe("LLO leyline_verify_cert_path refuses what it should", () => {
  it("a wrong root", async () => {
    const r = await root();
    const other = await root();
    const t = await tier(r.keys.privateKey, 1);
    const k = await task(t, 1);
    const leaf = der(k.pair.certificates.signing);
    // Positive control first: every refusal below is paired with the
    // acceptance it differs from by one thing, so a verifier that refuses
    // everything cannot pass this file.
    expect(llo.verifyCertPath(leaf, [der(t.pem)], r.anchor, PROFILE_SIGNET).ok).toBe(true);
    expect(llo.verifyCertPath(leaf, [der(t.pem)], other.anchor, PROFILE_SIGNET).ok).toBe(false);
  });

  it("a tampered leaf — one bit flipped inside the signed TBSCertificate", async () => {
    const r = await root();
    const t = await tier(r.keys.privateKey, 1);
    const k = await task(t, 1);
    const leaf = der(k.pair.certificates.signing);
    expect(llo.verifyCertPath(leaf, [der(t.pem)], r.anchor, PROFILE_SIGNET).ok).toBe(true);

    // Flip a bit in the task name (.1.9 / subject) — inside the TBS, so the
    // DER still parses and only the signature can catch it.
    const name = new TextEncoder().encode("build");
    const at = indexOf(leaf, name);
    expect(at).toBeGreaterThan(0);
    const bad = leaf.slice();
    bad[at] ^= 0x01;
    expect(llo.verifyCertPath(bad, [der(t.pem)], r.anchor, PROFILE_SIGNET).ok).toBe(false);
  });

  it("a task presented under a DIFFERENT tier of the same root, same principal", async () => {
    const r = await root();
    const t1 = await tier(r.keys.privateKey, 1);
    const t2 = await tier(r.keys.privateKey, 1);
    // Same principal → same tier subject name, so only the signature on the
    // task can tell the tiers apart.
    expect(new X509Certificate(t1.pem).subject).toBe(new X509Certificate(t2.pem).subject);
    const k = await task(t2, 1);
    const leaf = der(k.pair.certificates.signing);
    expect(llo.verifyCertPath(leaf, [der(t2.pem)], r.anchor, PROFILE_SIGNET).ok).toBe(true);
    expect(llo.verifyCertPath(leaf, [der(t1.pem)], r.anchor, PROFILE_SIGNET).ok).toBe(false);
  });

  it("a task with its tier omitted (presented as if the root signed it)", async () => {
    const r = await root();
    const t = await tier(r.keys.privateKey, 1);
    const k = await task(t, 1);
    const leaf = der(k.pair.certificates.signing);
    expect(llo.verifyCertPath(leaf, [der(t.pem)], r.anchor, PROFILE_SIGNET).ok).toBe(true);
    expect(llo.verifyCertPath(leaf, [], r.anchor, PROFILE_SIGNET).ok).toBe(false);
  });

  it("a tier presented as the leaf (CA:TRUE is not an end entity)", async () => {
    const r = await root();
    const t = await tier(r.keys.privateKey, 1);
    const k = await task(t, 1);
    expect(llo.verifyCertPath(der(k.pair.certificates.signing), [der(t.pem)], r.anchor, PROFILE_SIGNET).ok).toBe(true);
    expect(llo.verifyCertPath(der(t.pem), [], r.anchor, PROFILE_SIGNET).ok).toBe(false);
  });

  it("the mTLS half of the pair is not an Ed25519 leaf and does not verify as one", async () => {
    // Observed, not assumed: LLO's path verifier reads an Ed25519 leaf key
    // (`epk`). The P-256 mTLS certificate is signed by the same tier, so this
    // pins which half of the pair a third party is meant to hand LLO.
    const r = await root();
    const t = await tier(r.keys.privateKey, 1);
    const k = await task(t, 1);
    expect(llo.verifyCertPath(der(k.pair.certificates.signing), [der(t.pem)], r.anchor, PROFILE_SIGNET).ok).toBe(true);
    expect(llo.verifyCertPath(der(k.pair.certificates.mtls), [der(t.pem)], r.anchor, PROFILE_SIGNET).ok).toBe(false);
  });
});

/**
 * notme-6070fa, closed against LLO's CLASSIFIER rather than notme's emitter.
 * llo-profile-contract.do.test.ts asserts every mint path writes .1.1/.1.2/
 * .1.8; this asks the released verifier itself, with expected_profile=0
 * ("either"), which profile it reads each root-signed Ed25519 certificate
 * under. Anything but "signet" means LLO would read notme's .1.5 authMethod
 * and .1.6 peer binding as Interlace peer/scope.
 */
describe("LLO reads EVERY notme mint path as the Signet profile (notme-6070fa)", () => {
  it("mintGHABridgeCert, mintBridgeCertPair (signing), and a tier-issued task", async () => {
    const r = await root();
    const subject = await ed();
    const gha = await mintGHABridgeCert(
      "repo:agentic-research/notme:ref:refs/heads/main",
      await pubPem(subject.publicKey),
      r.keys.privateKey,
    );
    const signing = await ed();
    const pair = await mintBridgeCertPair(
      "alice",
      "wimse://notme.bot/principal/alice",
      await pubPem((await p256()).publicKey),
      await pubPem(signing.publicKey),
      r.keys.privateKey,
      { scopes: ["bridgeCert"], epoch: 2, authMethod: "passkey" },
    );
    const t = await tier(r.keys.privateKey, 2);
    const k = await task(t, 2);

    for (const [label, leaf, path] of [
      ["mintGHABridgeCert", der(gha.certificate), []],
      ["mintBridgeCertPair (signing)", der(pair.certificates.signing), []],
      ["mintTaskCertPair under mintIssuingCaCert", der(k.pair.certificates.signing), [der(t.pem)]],
    ] as const) {
      const res = llo.verifyCertPath(leaf, [...path], r.anchor, PROFILE_ANY);
      expect(res.ok, `${label}: LLO refused it`).toBe(true);
      expect(res.ok && res.claims.pr, `${label}: LLO did not read it as Signet`).toBe("signet");
      expect(res.ok && (res.claims.pf ?? res.claims.sc), `${label}: LLO reported .1.5/.1.6`).toBeUndefined();
    }
  });
});

function indexOf(hay: Uint8Array, needle: Uint8Array): number {
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}
