/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * staging-impersonation.do.test.ts — a staging-issued credential must not be
 * string-identical to a production one (notme-1532eb, red-team:trust-root).
 *
 * ADR-018 says "staging state is disposable by design (its CA is not trusted
 * by anything)". That was true of the KEY and false of every NAME the CA
 * emitted: same WIMSE trust domain, same CA subject DN, same owner scope,
 * production audience allowlist. A staging-minted credential differed from a
 * production one only in raw key bytes — so any verifier authorizing on the
 * identity string, the issuer DN, or "fetch the bundle from the authority
 * that issued this leaf" accepted it. The required capability was a workflow
 * in the org, nothing more.
 *
 * Four fixes landed: wimseTrustDomain() derives from SITE_URL,
 * caSubjectForEnv() appends a non-production host, GHA_ALLOWED_OWNERS lost
 * its production default, and staging pins ALLOWED_AUDIENCES.
 * `authority-host.test.ts` asserts those four FUNCTIONS return different
 * strings, and `staging-isolation.test.ts` asserts wrangler.toml declares the
 * vars.
 *
 * Neither proves the wiring. A helper that returns the right string and a
 * mint path that ignores it is precisely the shape of defect this bead was
 * filed about, so these cases mint REAL credentials from a staging-shaped
 * configuration and a production-shaped one and require the fields a verifier
 * reads to differ.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { X509Certificate } from "@peculiar/x509";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import worker from "../worker";
import {
  type GhaSigner,
  ghaPopBody,
  installGhaSigner,
} from "./__tests__/helpers/gha-token";

const OWNER = "agentic-research";
const REPO = "notme";
const AUDIENCE = "notme.bot";

const PROD = {
  SITE_URL: "https://notme.bot",
  SIGNET_AUTHORITY_URL: "https://auth.notme.bot",
  GHA_ALLOWED_OWNERS: OWNER,
  GHA_CERT_AUDIENCE: AUDIENCE,
};
const STAGING = {
  SITE_URL: "https://staging.notme.bot",
  SIGNET_AUTHORITY_URL: "https://auth-staging.notme.bot",
  GHA_ALLOWED_OWNERS: OWNER, // deliberately the SAME org — the attack's premise
  GHA_CERT_AUDIENCE: AUDIENCE,
};

/**
 * Minting is genuinely slow: each case generates an RSA-2048 keypair for the
 * OIDC signer plus a P-256 and an Ed25519 pair for the proof of possession,
 * then drives a full cert-pair mint through the DO. Two mints in one case
 * exceeded vitest's 5s default about one run in six — a timeout, never an
 * assertion failure. Stated as a constant with this note rather than a
 * global bump, so the next slow test has to make its own case.
 */
const MINT_TIMEOUT_MS = 20_000;

let signer: GhaSigner;
beforeAll(async () => {
  signer = await installGhaSigner({ owner: OWNER, repo: REPO, audience: AUDIENCE });
}, MINT_TIMEOUT_MS);
afterAll(() => signer.restore());

async function mint(vars: Record<string, string>) {
  const token = await signer.token();
  const res = await worker.fetch(
    new Request(`${vars.SIGNET_AUTHORITY_URL}/cert/gha`, {
      method: "POST",
      headers: {
        host: new URL(vars.SIGNET_AUTHORITY_URL!).host,
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(await ghaPopBody(token)),
    }),
    { ...env, ...vars } as never,
  );
  expect(res.status, await res.clone().text()).toBe(200);
  return (await res.json()) as { identity: string; certificates: { signing: string } };
}

describe("staging.impersonation.identity", () => {
  it("a staging mint does not claim production's trust domain", async () => {
    // The attack in one line: if these match, a staging-issued credential
    // satisfies `--certificate-identity <production identity>` exactly.
    const prod = await mint(PROD);
    const staging = await mint(STAGING);

    expect(prod.identity).toContain("wimse://notme.bot/");
    expect(staging.identity).toContain("wimse://staging.notme.bot/");
    expect(staging.identity).not.toBe(prod.identity);
  }, MINT_TIMEOUT_MS);

  it("the identity is DERIVED, not a literal that happens to differ", async () => {
    // A third, arbitrary domain: a hardcode matching two known environments
    // by coincidence would pass the case above.
    const other = await mint({
      ...STAGING,
      SITE_URL: "https://notme.example",
      SIGNET_AUTHORITY_URL: "https://auth.notme.example",
    });
    expect(other.identity).toContain("wimse://notme.example/");
    expect(other.identity).not.toContain("notme.bot");
  }, MINT_TIMEOUT_MS);
});

describe("staging.impersonation.issuer", () => {
  it("a non-production authority's CA subject is distinguishable", async () => {
    // Detection, which the bead recorded as absent: an auditor holding a leaf
    // could not tell which CA minted it without already having both keys.
    const read = async (name: string, vars: Record<string, string>) => {
      const stub = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(name));
      return runInDurableObject(stub, async (auth) => {
        const a = auth as unknown as {
          env: Record<string, unknown>;
          getCACertificatePem(): Promise<string>;
        };
        // The CA subject comes from the DO's OWN env, which is why it cannot
        // be reached by varying the request env the way identity is above.
        a.env = { ...a.env, ...vars };
        return a.getCACertificatePem();
      });
    };
    const prodPem = await read("impersonation-prod", PROD);
    const stagingPem = await read("impersonation-staging", STAGING);

    const prodSubject = new X509Certificate(prodPem).subject;
    const stagingSubject = new X509Certificate(stagingPem).subject;

    expect(prodSubject).toContain("CN=signet-authority");
    expect(prodSubject).not.toContain("auth-staging");
    expect(stagingSubject).toContain("auth-staging.notme.bot");
    expect(stagingSubject).not.toBe(prodSubject);
  }, MINT_TIMEOUT_MS);

  it("the CA is self-signed, so issuer and subject move together", async () => {
    // Guards against a fix that renames the subject and leaves the issuer —
    // a verifier pinning on issuer DN would still be fooled.
    const stub = env.SIGNING_AUTHORITY.get(
      env.SIGNING_AUTHORITY.idFromName("impersonation-staging"),
    );
    const pem = await runInDurableObject(stub, (auth) =>
      (auth as unknown as { getCACertificatePem(): Promise<string> }).getCACertificatePem(),
    );
    const cert = new X509Certificate(pem);
    expect(cert.issuer).toBe(cert.subject);
    expect(cert.issuer).toContain("auth-staging.notme.bot");
  });
});
