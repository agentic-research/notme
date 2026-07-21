/**
 * OAuth 2.0 AS metadata (RFC 8414) — discovery-document contract tests.
 *
 * These pin the things a REAL client breaks on, not the things that merely
 * look tidy. Every assertion here exists because of a specific failure mode:
 *
 *   - issuer mismatch is the ONLY condition that makes go-oidc's
 *     NewProvider fail. It ignores every endpoint field, but does:
 *       if p.Issuer != issuerURL && !skipIssuerValidation {
 *         return nil, &IssuerMismatchError{...}
 *       }
 *     So issuer must be byte-identical to the discovery origin — no trailing
 *     slash, no scheme/host drift between environments.
 *   - The deliberate OMISSIONS are guarded, because the failure mode of this
 *     document is over-claiming: a discovery doc that advertises a capability
 *     the server lacks sends clients into a flow that does not exist.
 *   - scopes/grants are asserted against their single sources of truth,
 *     because both previously drifted into publishing values that were never
 *     implemented (github_pat, oidc_token_exchange) or were never scopes at
 *     all (a KV cache key, a module import specifier).
 */

import { describe, expect, it } from "vitest";
import { ALL_SCOPES } from "@notme/contract";
import {
  AUTHORITY_GRANT_TYPES,
  DEFAULT_SIGNING_ALGS,
  DPOP_PROOF_ALGS,
  FORBIDDEN_METADATA_FIELDS,
  buildAsMetadata,
  getSigningAlgs,
} from "../as-metadata";

const AUTHORITY = "https://auth.notme.bot";
const SITE = "https://notme.bot";

describe("AS metadata — issuer (the only field that breaks go-oidc)", () => {
  it("issuer is byte-identical to the discovery origin", () => {
    const m = buildAsMetadata(AUTHORITY, SITE);
    // go-oidc compares p.Issuer != issuerURL exactly. Any drift here breaks
    // NewProvider for every OIDC client.
    expect(m.issuer).toBe(AUTHORITY);
  });

  it("issuer carries no trailing slash", () => {
    const m = buildAsMetadata(AUTHORITY, SITE);
    expect(m.issuer.endsWith("/")).toBe(false);
  });

  it("issuer is https", () => {
    expect(buildAsMetadata(AUTHORITY, SITE).issuer.startsWith("https://")).toBe(
      true,
    );
  });

  it("endpoints are absolute URLs under the issuer", () => {
    const m = buildAsMetadata(AUTHORITY, SITE);
    for (const url of [m.token_endpoint, m.jwks_uri]) {
      expect(url.startsWith(`${AUTHORITY}/`)).toBe(true);
      expect(() => new URL(url)).not.toThrow();
    }
  });

  it("jwks_uri points at the served JWKS path", () => {
    // go-oidc fetches this lazily for verification; a wrong path fails at
    // token-verify time rather than discovery time, which is worse.
    expect(buildAsMetadata(AUTHORITY, SITE).jwks_uri).toBe(
      `${AUTHORITY}/.well-known/jwks.json`,
    );
  });
});

describe("AS metadata — deliberate omissions stay omitted", () => {
  it.each(FORBIDDEN_METADATA_FIELDS)("does not advertise %s", (field) => {
    const m = buildAsMetadata(AUTHORITY, SITE) as unknown as Record<string, unknown>;
    expect(Object.keys(m)).not.toContain(field);
  });

  it("omitting authorization_endpoint does not break go-oidc discovery", () => {
    // Documenting the verified behaviour: go-oidc's providerJSON unmarshals
    // authorization_endpoint but NEVER validates presence — NewProvider
    // succeeds with it absent. RFC 8414 §2 permits omission when no grant
    // type uses the authorization endpoint, which is the case here.
    const m = buildAsMetadata(AUTHORITY, SITE) as unknown as Record<string, unknown>;
    expect(m.authorization_endpoint).toBeUndefined();
    // The two fields go-oidc actually needs downstream are present.
    expect(m.issuer).toBeDefined();
    expect(m.jwks_uri).toBeDefined();
  });

  it("advertises no OIDC-provider capability", () => {
    const m = buildAsMetadata(AUTHORITY, SITE);
    // No id_token is ever minted and scope=openid is not honoured, so neither
    // may be implied.
    expect(m.scopes_supported).not.toContain("openid");
    expect(m.response_types_supported).not.toContain("id_token");
  });

  it("does not claim PKCE — code_challenge/verifier are unimplemented", () => {
    const m = buildAsMetadata(AUTHORITY, SITE) as unknown as Record<string, unknown>;
    expect(m.code_challenge_methods_supported).toBeUndefined();
  });
});

describe("AS metadata — no hand-listed values (drift guards)", () => {
  it("scopes_supported IS @notme/contract's ALL_SCOPES", () => {
    // Previously hand-listed, and 2 of 4 values were not scopes at all.
    expect(buildAsMetadata(AUTHORITY, SITE).scopes_supported).toEqual(
      ALL_SCOPES,
    );
  });

  it("advertises only grant types with a verified implementation", () => {
    // github_pat and oidc_token_exchange were advertised publicly for months
    // with no implementation anywhere. Keep this list honest.
    expect(buildAsMetadata(AUTHORITY, SITE).grant_types_supported).toEqual(
      AUTHORITY_GRANT_TYPES,
    );
    for (const dead of ["github_pat", "oidc_token_exchange"]) {
      expect(AUTHORITY_GRANT_TYPES as readonly string[]).not.toContain(dead);
    }
  });

  it("response_types_supported is an array (RFC 8414 §2) and is empty", () => {
    const m = buildAsMetadata(AUTHORITY, SITE);
    expect(Array.isArray(m.response_types_supported)).toBe(true);
    // Empty is truthful: no authorization-code issuance, no code->token
    // exchange. RFC 8414 requires the field be an array, not a non-empty one.
    expect(m.response_types_supported).toHaveLength(0);
  });
});

describe("AS metadata — signing algorithms", () => {
  it("dpop_signing_alg_values_supported is the client PROOF alg", () => {
    // ES256 = client-generated P-256 proof. EdDSA = this authority's token
    // signature. Transposing these is exactly the interop bug that made
    // cloister's verifier unable to talk to this mint.
    expect(buildAsMetadata(AUTHORITY, SITE).dpop_signing_alg_values_supported)
      .toEqual(DPOP_PROOF_ALGS);
    expect(DPOP_PROOF_ALGS).toContain("ES256");
  });

  it("publishes the issuer's JWS alg — absence makes go-oidc assume RS256", () => {
    // go-oidc verifyJWT: "If no algorithms were specified by both the config
    // and discovery, default to the one mandatory algorithm RS256."
    //   if len(supportedSigAlgs) == 0 { supportedSigAlgs = {jose.RS256} }
    // With this field absent, every EdDSA token we issue is rejected as
    // "oidc: malformed jwt". Publishing it is a correctness requirement.
    const algs = buildAsMetadata(AUTHORITY, SITE)
      .id_token_signing_alg_values_supported;
    expect(algs).toEqual(DEFAULT_SIGNING_ALGS);
    expect(algs).toContain("EdDSA");
    expect(algs.length).toBeGreaterThan(0);
  });

  it('uses the JWA alg name "EdDSA", never the curve name "Ed25519"', () => {
    // RFC 8037 §3.1: EdDSA is the algorithm; Ed25519 is the crv. The JWK is
    // {kty:"OKP", crv:"Ed25519", alg:"EdDSA"}.
    const algs = buildAsMetadata(AUTHORITY, SITE)
      .id_token_signing_alg_values_supported;
    expect(algs).not.toContain("Ed25519");
  });

  it("the proof and token algorithm lists stay disjoint", () => {
    const proof = new Set<string>(DPOP_PROOF_ALGS);
    for (const alg of DEFAULT_SIGNING_ALGS) expect(proof.has(alg)).toBe(false);
  });
});

describe("AS metadata — signing algs are deployer-configurable", () => {
  it("defaults to EdDSA when unset", () => {
    expect(getSigningAlgs({})).toEqual(DEFAULT_SIGNING_ALGS);
    expect(getSigningAlgs({ ID_TOKEN_SIGNING_ALGS: "   " })).toEqual(
      DEFAULT_SIGNING_ALGS,
    );
  });

  it("accepts a CSV override and trims it", () => {
    expect(getSigningAlgs({ ID_TOKEN_SIGNING_ALGS: "EdDSA, ES256" })).toEqual([
      "EdDSA",
      "ES256",
    ]);
  });

  it("NEVER yields an empty list, even from a malformed override", () => {
    // An empty list is the precise state that makes go-oidc fall back to
    // RS256-only. A misconfigured env must not be able to break every client.
    for (const bad of [",", " , , ", ""]) {
      expect(getSigningAlgs({ ID_TOKEN_SIGNING_ALGS: bad }).length)
        .toBeGreaterThan(0);
    }
  });

  it("threads the configured algs into the document", () => {
    const m = buildAsMetadata(AUTHORITY, SITE, ["EdDSA", "ES256"]);
    expect(m.id_token_signing_alg_values_supported).toEqual([
      "EdDSA",
      "ES256",
    ]);
  });
});

describe("AS metadata — token endpoint auth", () => {
  it('is "none" — session cookie + DPoP, no client credential', () => {
    expect(
      buildAsMetadata(AUTHORITY, SITE).token_endpoint_auth_methods_supported,
    ).toEqual(["none"]);
  });

  it("does not advertise tls_client_auth", () => {
    // The X-Client-Cert path was REMOVED because, without CF mTLS bindings,
    // the header is attacker-controlled. Re-advertising it here would claim a
    // deliberately-removed verification path.
    const methods = buildAsMetadata(AUTHORITY, SITE)
      .token_endpoint_auth_methods_supported as readonly string[];
    expect(methods).not.toContain("tls_client_auth");
    expect(methods).not.toContain("self_signed_tls_client_auth");
  });
});

describe("AS metadata — both discovery paths serve identical bodies", () => {
  it("is a pure function of (authorityUrl, siteUrl)", () => {
    // worker.ts serves one object at both paths; purity is what guarantees
    // the two documents can never disagree.
    expect(buildAsMetadata(AUTHORITY, SITE)).toEqual(
      buildAsMetadata(AUTHORITY, SITE),
    );
  });

  it("tracks a non-production authority URL (staging must not leak prod)", () => {
    const staging = "https://auth.staging.notme.bot";
    const m = buildAsMetadata(staging, SITE);
    expect(m.issuer).toBe(staging);
    expect(m.token_endpoint.startsWith(staging)).toBe(true);
    expect(m.jwks_uri.startsWith(staging)).toBe(true);
  });

  it("serialises to JSON without undefined holes", () => {
    const m = buildAsMetadata(AUTHORITY, SITE);
    const round = JSON.parse(JSON.stringify(m));
    expect(round).toEqual(JSON.parse(JSON.stringify(m)));
    for (const [k, v] of Object.entries(round)) {
      expect(v, `${k} must not be null/undefined`).not.toBeNull();
      expect(v, `${k} must not be null/undefined`).not.toBeUndefined();
    }
  });
});
