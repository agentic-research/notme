/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * issuer-name.do.test.ts — every root-issued certificate names its signing
 * CA's subject as issuer (notme-7ec6fb).
 *
 * notme-1532eb gave a non-production authority its own CA subject
 * (`caSubjectForEnv`: `CN=signet-authority <host>,O=notme`), but the three
 * root-issued mint paths still defaulted the ISSUER name to the production
 * literal. A staging leaf was signed by a CA whose subject it did not name,
 * so anything that builds a chain by name refused it: openssl, Go x509 path
 * building, a CT log's add-chain, and this repo's own verifyCertChain, which
 * checks issuer === signer.subject at every hop (RFC 5280 §6.1.3(a)(4)).
 *
 * Production was unaffected because its CA subject IS the literal, and that
 * must stay true to the byte: the last describe pins production's issuer
 * DER to the encoding the literal has always produced.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { Name, X509Certificate } from "@peculiar/x509";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type GhaSigner, installGhaSigner, spkiPem } from "./__tests__/helpers/gha-token";
import { verifyCertChain } from "./auth/verify-chain";
import { mintTaskCertPair } from "./cert-authority";
import { ED25519 } from "./platform";

const OWNER = "agentic-research";
const REPO = "notme";
const AUDIENCE = "notme.bot";

const STAGING_URL = "https://auth-staging.notme.bot";
const PRODUCTION_URL = "https://auth.notme.bot";

/**
 * The DER of `CN=signet-authority,O=notme` as every production cert has
 * carried it: SEQUENCE { SET { CN PrintableString }, SET { O PrintableString } },
 * read from a production-shaped mint BEFORE the notme-7ec6fb fix. A literal,
 * not recomputed from the library, so a change in how the name is
 * built or encoded cannot move production's bytes and still pass.
 */
const PRODUCTION_ISSUER_DER_HEX =
  "302b31193017060355040313107369676e65742d617574686f72697479310e300c060355040a13056e6f746d65";

/** Minting generates several keypairs and drives the DO; see staging-impersonation. */
const MINT_TIMEOUT_MS = 20_000;

type Minted = { root: string; pair: [string, string]; gha: string; tier: string; tierKey: CryptoKeyPair; epoch: number };

interface AuthLike {
  env: Record<string, unknown>;
  getCACertificatePem(): Promise<string>;
  getAuthorityState(): Promise<{ epoch: number }>;
  mintBridgeCertPair(p: {
    subject: string;
    identity: string;
    mtlsPublicKeyPem: string;
    signingPublicKeyPem: string;
    scopes: string[];
    authMethod: string;
  }): Promise<{ certificates: { mtls: string; signing: string } }>;
  mintIssuingCa(p: {
    subject: string;
    identity: string;
    publicKeyPem: string;
    scopes: string[];
    authMethod: string;
  }): Promise<{ certificate: string }>;
  mintBridgeCert(
    proof: { kind: "gha-oidc"; token: string },
    publicKeyPem: string,
  ): Promise<{ ok: true; certificate: string } | { ok: false; reason: string }>;
}

let signer: GhaSigner;
// ONE signer per file: validateGHAToken caches JWKS at module scope.
beforeAll(async () => {
  signer = await installGhaSigner({ owner: OWNER, repo: REPO, audience: AUDIENCE });
}, MINT_TIMEOUT_MS);
afterAll(() => signer.restore());

const derHex = (der: ArrayBuffer) =>
  [...new Uint8Array(der)].map((b) => b.toString(16).padStart(2, "0")).join("");

const issuerDer = (pem: string) => derHex(new X509Certificate(pem).issuerName.toArrayBuffer());
const subjectDer = (pem: string) => derHex(new X509Certificate(pem).subjectName.toArrayBuffer());

/**
 * Mint through all three root-issued paths on a fresh authority whose OWN env
 * is `authorityUrl`. `rootUrl`, when given, is the env the root is CREATED
 * under — an authority whose root predates its current env.
 */
async function mintAll(name: string, authorityUrl: string, rootUrl?: string): Promise<Minted> {
  const mtls = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const sign = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
  const tierKey = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
  const mtlsPem = await spkiPem(mtls.publicKey);
  const signPem = await spkiPem(sign.publicKey);
  const tierPem = await spkiPem(tierKey.publicKey);
  const token = await signer.token();

  const stub = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(name));
  return runInDurableObject(stub, async (auth) => {
    const a = auth as unknown as AuthLike;
    // The CA subject comes from the DO's OWN env, so patch it before the
    // root exists — the root is created once, by whichever call comes first.
    if (rootUrl) {
      a.env = { ...a.env, SIGNET_AUTHORITY_URL: rootUrl };
      await a.getCACertificatePem();
    }
    a.env = { ...a.env, SIGNET_AUTHORITY_URL: authorityUrl };
    const pair = await a.mintBridgeCertPair({
      subject: name,
      identity: `wimse://notme.bot/principal/${name}`,
      mtlsPublicKeyPem: mtlsPem,
      signingPublicKeyPem: signPem,
      scopes: ["bridgeCert"],
      authMethod: "passkey",
    });
    const tier = await a.mintIssuingCa({
      subject: `${name}-machine`,
      identity: `wimse://notme.bot/principal/${name}/machine`,
      publicKeyPem: tierPem,
      scopes: ["bridgeCert"],
      authMethod: "passkey",
    });
    const gha = await a.mintBridgeCert({ kind: "gha-oidc", token }, signPem);
    if (!gha.ok) throw new Error(`gha mint refused: ${gha.reason}`);
    return {
      root: await a.getCACertificatePem(),
      pair: [pair.certificates.mtls, pair.certificates.signing],
      gha: gha.certificate,
      tier: tier.certificate,
      tierKey,
      epoch: (await a.getAuthorityState()).epoch,
    };
  });
}

describe("issuer name (notme-7ec6fb)", () => {
  let staging: Minted;
  let production: Minted;
  beforeAll(async () => {
    staging = await mintAll("issuer-name-staging", STAGING_URL);
    production = await mintAll("issuer-name-production", PRODUCTION_URL);
  }, MINT_TIMEOUT_MS * 2);

  it("the staging-shaped authority really has its own CA subject (premise)", () => {
    const root = new X509Certificate(staging.root);
    expect(root.subject).toContain("auth-staging.notme.bot");
    expect(subjectDer(staging.root)).not.toBe(PRODUCTION_ISSUER_DER_HEX);
  });

  it("a non-production authority's bridge pair names its own root as issuer", async () => {
    const root = new X509Certificate(staging.root);
    for (const pem of staging.pair) {
      expect(issuerDer(pem), "bridge pair issuer is not the root's subject").toBe(subjectDer(staging.root));
      expect(await new X509Certificate(pem).verify({ publicKey: root.publicKey, signatureOnly: true })).toBe(true);
    }
  });

  it("a non-production authority's GHA cert names its own root as issuer", () => {
    expect(issuerDer(staging.gha), "GHA cert issuer is not the root's subject").toBe(subjectDer(staging.root));
  });

  it("a non-production authority's Issuing CA tier names its own root as issuer", () => {
    expect(issuerDer(staging.tier), "tier issuer is not the root's subject").toBe(subjectDer(staging.root));
  });

  it("a non-production task chain verifies by name to its own root", async () => {
    // The end-to-end consequence: verifyCertChain checks issuer === signer
    // subject at each hop, so a misnamed tier refused every staging task.
    const mtls = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const sign = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
    const task = await mintTaskCertPair(
      staging.tier,
      staging.tierKey.privateKey,
      await spkiPem(mtls.publicKey),
      await spkiPem(sign.publicKey),
      { task: "t1", goalHash: "a".repeat(64), scopes: ["bridgeCert"], epoch: staging.epoch },
    );
    const verified = await verifyCertChain(task.certificates.signing, [staging.tier], staging.root, staging.epoch);
    expect(verified.depth).toBe(1);
  });

  it("an authority whose root predates notme-1532eb keeps naming THAT root", async () => {
    // caSubjectForEnv only shapes a root when it is created; an existing
    // staging DO keeps a production-shaped root. Naming the env-derived
    // subject would break its chains the other way, so the issuer is read
    // from the stored root, not recomputed from the env.
    const old = await mintAll("issuer-name-old-root", STAGING_URL, PRODUCTION_URL);
    expect(subjectDer(old.root)).toBe(PRODUCTION_ISSUER_DER_HEX);
    for (const pem of [...old.pair, old.gha, old.tier]) {
      expect(issuerDer(pem), "issuer recomputed from env, not read from the root").toBe(subjectDer(old.root));
    }
  }, MINT_TIMEOUT_MS);

  it("production's issuer DN is byte-identical to the historical literal, on every path", () => {
    expect(subjectDer(production.root)).toBe(PRODUCTION_ISSUER_DER_HEX);
    for (const pem of [...production.pair, production.gha, production.tier]) {
      expect(issuerDer(pem)).toBe(PRODUCTION_ISSUER_DER_HEX);
    }
    // And the literal is what the string has always encoded to.
    expect(derHex(new Name("CN=signet-authority,O=notme").toArrayBuffer())).toBe(PRODUCTION_ISSUER_DER_HEX);
  });
});
