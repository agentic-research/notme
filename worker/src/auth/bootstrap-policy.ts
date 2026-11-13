/**
 * bootstrap-policy.ts — who may bootstrap an authority by attestation.
 *
 * PURE, and in its own module for a reason found by mutation testing. The
 * SigningAuthority DO reads `BOOTSTRAP_GHA_SUBJECT` from its own env, which
 * the workers test pool fixes for a whole run — so the UNCONFIGURED branch
 * was unreachable from any route- or DO-level test. A mutation making an
 * unset variable mean "accept any attested subject" passed all eight tests
 * of the feature. Whatever a test cannot vary, it cannot defend; so the
 * decision lives here, where its inputs are arguments (notme-addef9).
 */

/**
 * The one workflow identity permitted to bootstrap this authority.
 *
 * A VAR, not a secret — it is an identity, so there is nothing to leak and
 * nothing to scrape out of a log, which is the whole point (notme-addef9).
 * Security comes from GitHub's signature over the OIDC token, not from the
 * value being hidden.
 *
 * Exact-match on the full `sub`, deliberately narrower than
 * GHA_ALLOWED_OWNERS. The owner allowlist answers "may this workflow get a
 * credential"; anyone with push access to any repo under that owner clears
 * it. Becoming the ADMINISTRATOR is a different question, and the deployer
 * has to name one workflow to answer it.
 */
export function bootstrapAttestedSubject(env: {
  BOOTSTRAP_GHA_SUBJECT?: string;
}): string | null {
  const raw = env.BOOTSTRAP_GHA_SUBJECT?.trim();
  return raw ? raw : null;
}

/**
 * May this attested subject bootstrap this authority?
 *
 * A PURE predicate, extracted deliberately. The DO reads
 * `BOOTSTRAP_GHA_SUBJECT` from its own env, which a test cannot vary
 * per-instance — so the unconfigured branch was unreachable from any test,
 * and a mutation that made an unset variable mean "accept any attested
 * subject" passed the entire suite. That is the difference between a control
 * and a control nothing checks: unset must mean OFF, and the only way to say
 * so provably is a function whose inputs a test can choose.
 *
 * `subjectsMatch` is passed in rather than compared here because the DO does
 * it timing-safely; this function decides POLICY, not how bytes are compared.
 */
export function mayBootstrapFromAttestation(args: {
  configuredSubject: string | null;
  subjectsMatch: boolean;
  authorityIsGovernable: boolean;
}): boolean {
  // Unset means OFF. Never "allow anyone the owner allowlist already let in"
  // — that list answers "may this workflow get a credential", a far wider
  // question than "may it become the administrator".
  if (args.configuredSubject === null) return false;
  if (!args.subjectsMatch) return false;
  // One-time door: an authority with any principal or authenticator is
  // already governed, and bootstrap is over.
  return !args.authorityIsGovernable;
}
