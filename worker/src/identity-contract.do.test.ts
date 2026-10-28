/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * identity-contract.do.test.ts — the identity a caller is HANDED must be the
 * identity a verifier READS (notme-729801).
 *
 * WHY THIS EXISTS. signet's published release-verification procedure pins the
 * identity URI and requires equality:
 *
 *     IDENTITY=wimse://notme.bot/gha/agentic-research/signet
 *     cosign verify-blob --certificate-identity "$IDENTITY" ...
 *
 * That value is stale — notme emits `principal/<urlencode(sub)>` now, since
 * ADR-019 D2 / notme-77438b moved the attestation mechanism out of the
 * identity slot. So the documented command cannot pass, and its deliberately
 * tolerant fallback regexp in verify_release.sh cannot either, because the
 * separator in `agentic-research/signet` becomes `%2F`. Filed as
 * signet-751af3.
 *
 * The durable fix is that a consumer should never CONSTRUCT the string:
 * `POST /cert/gha` already returns `identity` in its response, so CI can
 * capture it and pass it straight to cosign. That advice is only safe if the
 * returned value is byte-identical to what verification reads out of the
 * certificate, and NOTHING tested that — no test in this repo compared the
 * response field to the certificate's URI SAN. A divergence there would send
 * every consumer following the documented path to pin a value verification
 * rejects, which is the same failure one layer deeper.
 *
 * Two things are therefore pinned:
 *   1. response.identity === the URI SAN of BOTH certificates in the pair.
 *   2. it equals the documented rule, so a consumer who must derive it
 *      offline gets the same answer as one who reads the response.
 */
import { X509Certificate, SubjectAlternativeNameExtension } from "@peculiar/x509";
import { env } from "cloudflare:test";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import worker from "../worker";
import { type GhaSigner, ghaPopBody, installGhaSigner } from "./__tests__/helpers/gha-token";

const ORIGIN = "http://localhost:8788";
const OWNER = "agentic-research";
const REPO = "notme";
const AUDIENCE = "notme.bot";
const BASE_ENV = {
  SITE_URL: ORIGIN,
  SIGNET_AUTHORITY_URL: ORIGIN,
  GHA_ALLOWED_OWNERS: OWNER,
  GHA_CERT_AUDIENCE: AUDIENCE,
};

/**
 * Minting is genuinely slow: a real RSA JWKS verification, two keypair
 * generations and two certificate signings per call, and the first case also
 * pays the JWKS cold start. Measured at ~3.4s alone and TIMING OUT at
 * vitest's 5s default inside the full suite. Named rather than bumped
 * globally so a future slow test is still caught by the default
 * (same treatment as the staging-impersonation mints).
 */
const MINT_TIMEOUT_MS = 20_000;

let signer: GhaSigner;
beforeAll(async () => {
  signer = await installGhaSigner({ owner: OWNER, repo: REPO, audience: AUDIENCE });
});
afterAll(() => signer.restore());

async function mint(token: string) {
  const res = await worker.fetch(
    new Request(`${ORIGIN}/cert/gha`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify(await ghaPopBody(token)),
    }),
    { ...env, ...BASE_ENV } as never,
  );
  return { res, body: (await res.json()) as Record<string, any> };
}

/** The URI entry of a certificate's SubjectAltName — what cosign matches. */
function sanUri(pem: string): string | undefined {
  const ext = new X509Certificate(pem).getExtension(SubjectAlternativeNameExtension);
  return ext?.names.items.find((n) => n.type === "url")?.value;
}

describe("the returned identity is the identity in the certificate (notme-729801)", () => {
  it("response.identity matches the URI SAN of BOTH certificates", async () => {
    const token = await signer.token();
    const { res, body } = await mint(token);
    expect(res.status).toBe(200);
    expect(body.identity).toBeTruthy();

    // BOTH, because the pair is two independently-signed certificates and a
    // verifier may hold either. If they could differ, "the identity" would
    // be ambiguous and a consumer pinning the response value would be right
    // about one certificate and wrong about the other.
    expect(sanUri(body.certificates.mtls)).toBe(body.identity);
    expect(sanUri(body.certificates.signing)).toBe(body.identity);
  }, MINT_TIMEOUT_MS);

  it("matches the documented derivation rule, so deriving it offline agrees", async () => {
    // The rule a consumer must use when it cannot read the response:
    //   wimse://<trust-domain>/principal/<urlencode(oidc sub)>
    // Written out here rather than imported, deliberately: importing
    // principalIdentity would compare the implementation to itself and pass
    // however the shape changed. This is the published contract restated,
    // so a change to the shape fails HERE and the reviewer has to update the
    // documented rule and the consumers with it.
    const token = await signer.token();
    const { body } = await mint(token);
    const sub = `repo:${OWNER}/${REPO}:ref:refs/heads/main`;
    // THE TRUST DOMAIN IS DEPLOYMENT-DERIVED, from SITE_URL's host — here
    // `localhost:8788`, in production `notme.bot`. An earlier version of this
    // test hardcoded `notme.bot` and failed, which is the same mistake
    // signet's README makes one level up: a consumer running its own
    // authority cannot hardcode the domain either, so the rule has to be
    // stated with the domain as a parameter rather than a constant.
    const trustDomain = new URL(ORIGIN).host;
    expect(body.identity).toBe(
      `wimse://${trustDomain}/principal/${encodeURIComponent(sub)}`,
    );
    // And the percent-encoding is the part that broke signet's fallback
    // regexp, so it is asserted explicitly rather than left implicit.
    expect(body.identity).toContain("%2F");
    expect(body.identity).not.toContain(`${OWNER}/${REPO}`);
  }, MINT_TIMEOUT_MS);

  it("no longer emits the /gha/<owner>/<repo> shape consumers still pin", async () => {
    // The shape signet's README and verify_release.sh expect. Asserting its
    // ABSENCE records that the break is deliberate: if someone restores it
    // for compatibility, this test is where they state that decision.
    const token = await signer.token();
    const { body } = await mint(token);
    expect(body.identity).not.toContain(`/gha/`);
  }, MINT_TIMEOUT_MS);
});
