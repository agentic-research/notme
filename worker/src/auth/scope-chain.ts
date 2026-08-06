/**
 * scope-chain.ts — monotonic scope attenuation across a delegation step
 * (ADR-008, notme-acc822).
 *
 * ADR-008's chain-verification pseudocode states this as a requirement, in
 * these words:
 *
 *     verify cert.scopes ⊆ parent.scopes   // MUST check — not optional
 *
 * Until now the ONLY implementation of that rule in the repository lived
 * inside `__tests__/adversarial.test.ts` as a local helper, exercised by six
 * passing tests. Six green tests asserted a real property of a function that
 * existed only in the test — coverage of nothing. This file is that rule as
 * production code, so those tests bind to something that runs.
 *
 * ── WHY THE RULE IS THE WHOLE SAFETY ARGUMENT FOR DEPTH ──
 * The risk in a delegated chain is not how DEEP it goes; it is whether each
 * step is allowed to gain authority. Every catastrophic PKI failure of this
 * class — DigiNotar, TÜRKTRUST, ANSSI — was an intermediate issuing beyond
 * what it should have, not a chain that was too long.
 *
 * If every step must strictly narrow, depth bounds ITSELF: a chain can only
 * run as long as the scope set can still be meaningfully subdivided, and a
 * monotonically decreasing chain in a finite lattice terminates on its own.
 * That is why this file exists and why there is no tier number anywhere in it
 * — the lattice does the bounding, so nothing has to count levels. It is the
 * same reason macaroons and Biscuit permit unbounded attenuation safely.
 *
 * The namespace half of the same argument is `nameConstraints` (ADR-008 §299,
 * RFC 5280 §4.2.1.10), which is still unimplemented; scopes alone bound what a
 * credential may DO, not which identities it may name.
 */

/**
 * Does a child's scope set stay within its parent's?
 *
 * Equality passes: a delegation that narrows nothing is still a valid
 * delegation. Growth fails, which is the escalation this exists to stop.
 * An empty child always passes — maximal restriction is always permitted —
 * and an empty parent admits only an empty child, since there is nothing to
 * pass on.
 *
 * Set semantics, so duplicates and ordering in either argument are
 * irrelevant; the question is about membership, not sequence.
 */
export function verifyScopeChain(
  parentScopes: readonly string[],
  childScopes: readonly string[],
): boolean {
  const parent = new Set(parentScopes);
  return childScopes.every((s) => parent.has(s));
}

/**
 * The scopes a child gained that its parent never held.
 *
 * Separate from `verifyScopeChain` because a rejection needs to SAY what was
 * wrong. A boolean tells an operator that a chain failed; this tells them
 * which grant was fabricated, which is the difference between an alert
 * somebody can act on and one they can only escalate.
 */
export function escalatedScopes(
  parentScopes: readonly string[],
  childScopes: readonly string[],
): string[] {
  const parent = new Set(parentScopes);
  return [...new Set(childScopes)].filter((s) => !parent.has(s));
}
