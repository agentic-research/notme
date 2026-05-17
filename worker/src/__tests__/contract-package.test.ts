/**
 * contract-package.test.ts — shape tests for @notme/contract.
 *
 * The package is consumed by both halves of the notme ecosystem (this repo
 * and notme.bot). These tests pin the SHAPE of each exported constant so a
 * future refactor that renames or drops a member surfaces here in CI.
 *
 * The package itself has no test runner wired; we co-locate the tests in
 * worker/ where vitest already runs. Imports are by relative path because
 * worker/ does not yet declare a workspace dep on @notme/contract (that's
 * a separate adoption PR that swaps the inline hardcoded constants for
 * imports from this package).
 */

import { describe, expect, it } from "vitest";
import * as contract from "../../../packages/contract/src/index";

describe("@notme/contract — exported shape", () => {
  it("CONTRACT_VERSION is a positive integer", () => {
    expect(Number.isInteger(contract.CONTRACT_VERSION)).toBe(true);
    expect(contract.CONTRACT_VERSION).toBeGreaterThan(0);
  });

  it("SCOPES contains the four expected scope tokens", () => {
    expect(contract.SCOPES.BRIDGE_CERT).toBe("bridgeCert");
    expect(contract.SCOPES.AUTHORITY_MANAGE).toBe("authorityManage");
    expect(contract.SCOPES.CERT_MINT).toBe("certMint");
    expect(contract.SCOPES.SIGN_GIT).toBe("sign:git");
    expect(contract.SCOPES.SIGN_ATTESTATION).toBe("sign:attestation");
  });

  it("ALL_SCOPES enumerates every value in SCOPES exactly once", () => {
    const values = Object.values(contract.SCOPES);
    expect([...contract.ALL_SCOPES].sort()).toEqual([...values].sort());
  });

  it("OIDC_ALLOWED_ALGS rejects symmetric + 'none' families by omission", () => {
    expect([...contract.OIDC_ALLOWED_ALGS]).toEqual(["RS256", "ES256"]);
    expect(contract.OIDC_ALLOWED_ALGS as readonly string[]).not.toContain(
      "none",
    );
    expect(contract.OIDC_ALLOWED_ALGS as readonly string[]).not.toContain(
      "HS256",
    );
  });

  it("TRUSTED_ISSUERS baseline lists auth.notme.bot + GHA, in that order", () => {
    // Order is part of the contract — a future widening must be deliberate.
    expect([...contract.TRUSTED_ISSUERS]).toEqual([
      "https://auth.notme.bot",
      "https://token.actions.githubusercontent.com",
    ]);
  });

  it("TRUSTED_ISSUERS does NOT include Google (audience asymmetry)", () => {
    // Google IDs carry aud=<client-id>.apps.googleusercontent.com; including
    // Google here would produce confusing "wrong audience" rejections rather
    // than the clearer "untrusted issuer" path. See notme-ae65a0.
    for (const iss of contract.TRUSTED_ISSUERS) {
      expect(iss).not.toContain("accounts.google.com");
    }
  });

  it("GHA_REJECTED_EVENTS covers the fork-PR confused-deputy lane", () => {
    expect(contract.GHA_REJECTED_EVENTS).toContain("pull_request_target");
    expect(contract.GHA_REJECTED_EVENTS).toContain("pull_request");
  });

  it("ERROR_STATUS uses standard 4xx codes for documented failure classes", () => {
    expect(contract.ERROR_STATUS.OIDC_PROOF_REJECTED).toBe(403);
    expect(contract.ERROR_STATUS.SCOPE_INSUFFICIENT).toBe(403);
    expect(contract.ERROR_STATUS.RESET_NOT_PERMITTED).toBe(403);
    expect(contract.ERROR_STATUS.GHA_TOKEN_INVALID).toBe(401);
    expect(contract.ERROR_STATUS.AUTH_FAILED).toBe(401);
    expect(contract.ERROR_STATUS.SESSION_REQUIRED).toBe(401);
  });
});
