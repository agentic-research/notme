/**
 * passkey-cert-scopes.ts — decide which of a passkey session's scopes a bridge
 * cert may carry.
 *
 * THE WHOLE POINT, and the one place this route differs from `/cert/gha`:
 *
 * `/cert/gha` hardcodes `scopes: ["bridgeCert"]` because a GitHub OIDC token
 * says nothing about privilege — there is nothing to inherit. A passkey
 * session is different: it carries `authorityManage` and `certMint` for the
 * deployer (worker.ts, first-user registration). Passing those through would
 * turn a browser session into a *minting credential* — a cert that can mint
 * further certs, valid for its whole lifetime, usable from anywhere, with none
 * of the properties that made the session acceptable (same-origin, HttpOnly,
 * SameSite=Strict, revocable by clearing a cookie).
 *
 * So: INTERSECT with an explicit allowlist. Two properties matter, and they
 * are different:
 *
 *   1. The result is a SUBSET of the session's scopes — a cert can never
 *      exceed the authority of the session that requested it.
 *   2. The result is a subset of CERT_ELIGIBLE_SCOPES — a scope is carryable
 *      only if someone decided it is safe in a long-lived, exportable,
 *      off-origin credential.
 *
 * An allowlist rather than a denylist deliberately. With a denylist, every new
 * scope is carryable by default and someone has to remember to exclude it;
 * the failure is silent and in the permissive direction. With an allowlist a
 * new scope is inert until named here, and the failure is a missing capability
 * someone notices immediately.
 */

/**
 * Scopes a bridge cert minted from a passkey session may carry.
 *
 * `bridgeCert` only, today. It is the scope that means "this credential may
 * act as a bridge identity" — exactly what a cert IS — so it is the one whose
 * meaning does not change when it moves from a cookie into a certificate.
 *
 * NOT `certMint`: a cert that can mint certs is a delegation the human never
 * agreed to at the touch prompt.
 * NOT `authorityManage`: administering the authority from a long-lived
 * exportable credential removes the "human present at a browser" property that
 * made granting it acceptable in the first place.
 */
export const CERT_ELIGIBLE_SCOPES: ReadonlySet<string> = new Set([
  "bridgeCert",
]);

/**
 * Intersect a session's scopes with what a cert may carry.
 *
 * @returns the granted subset, deduplicated, in the allowlist's order so the
 *   result is deterministic regardless of how the session happened to store
 *   them — cert contents feed a signature, and a signature over a set that
 *   reorders is a diffing headache at best.
 */
export function certScopesForSession(
  sessionScopes: readonly string[] | undefined,
): string[] {
  const held = new Set(sessionScopes ?? []);
  return [...CERT_ELIGIBLE_SCOPES].filter((s) => held.has(s));
}
