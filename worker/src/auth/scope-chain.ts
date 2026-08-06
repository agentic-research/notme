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
 * ── WHAT THIS BOUNDS, AND WHAT IT EMPHATICALLY DOES NOT ──
 * The subset rule makes AUTHORITY monotone non-increasing: no chain, at any
 * depth, can exceed the root grant. That is the macaroon/Biscuit property, and
 * it is why unbounded attenuation is safe for authority.
 *
 * IT DOES NOT BOUND DEPTH. An earlier version of this comment claimed it did —
 * "monotone narrowing means depth bounds itself" — and that is false three
 * times over. Recording why, because the mistake is seductive:
 *
 *   1. Equality passes (deliberately — see below), so the relation is
 *      REFLEXIVE, hence a preorder, hence never well-founded. The constant
 *      chain S, S, S, … is an admissible infinite descent.
 *   2. Even forbidding equality only bounds a chain at |S|+1 — a depth limit
 *      set accidentally by whoever last added a scope string. That is not a
 *      formalisation of anything.
 *   3. The lattice is not staying finite. Once scopes are hierarchical
 *      (`sign:git` → `sign:git:repo` → …), which is the direction
 *      nameConstraints-style namespacing points, infinite STRICTLY decreasing
 *      chains exist too.
 *
 * The macaroon/Biscuit comparison actually proves the opposite of what it was
 * cited for: both permit unbounded attenuation precisely BECAUSE authority
 * cannot grow, and both then bound depth SEPARATELY and explicitly — Biscuit
 * with block-count limits, macaroon deployments with caveat caps — because
 * chain length is a verification-cost problem even when authority is safe.
 *
 * ── DEPTH IS AN INDEPENDENT DIMENSION WITH ITS OWN MECHANISM ──
 * Terminating a chain whose scopes may stay equal requires some OTHER
 * component to strictly decrease. That is a rank function into a well-founded
 * set, and X.509 already carries it: `pathLenConstraint`. RFC 5280 §6.1.4(l)
 * and (m) are a loop variant — a budget decremented at each non-self-issued
 * intermediate and min'd with each cert's own constraint. Chains terminate
 * because ℕ has no infinite descent, not because the scope lattice is finite.
 *
 * SPKI/SDSI (RFC 2693) carries the degenerate case: a boolean delegation bit.
 * notme's two-hop design IS that boolean — the bridge may delegate, the task
 * may not — so nothing here needs inventing.
 *
 * THE ENFORCEMENT ASYMMETRY IS THE REASON TO KEEP BOTH. ADR-008 is explicit
 * that the scope-subset check is COOPERATIVE: relying parties MUST perform it
 * and nothing compels them to. `pathLenConstraint` is INTRINSIC — every
 * conformant X.509 validator enforces it without being asked. So the weaker
 * mechanism here does not make the stronger one redundant; they bound
 * different things. This file is the AUTHORITY bound.
 * `delegation-depth.do.test.ts` pins the DEPTH bound.
 *
 * The namespace bound is the third dimension: `nameConstraints` (ADR-008 §299,
 * RFC 5280 §4.2.1.10), still unimplemented. Scopes bound what a credential may
 * DO, pathlen bounds how far it may pass that on, and neither bounds which
 * identities it may NAME.
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
