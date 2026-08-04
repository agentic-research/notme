/**
 * delegated-claims.ts — validate a JWS header + payload before the authority
 * will sign them on a delegated issuer's behalf (ADR-015).
 *
 * The separate signing key is what actually closes the authentication bypass:
 * a token signed here cannot verify against notme's own JWKS, because it is a
 * cryptographically unrelated key. These checks are defence in depth, and each
 * one closes a specific footgun rather than being generic hygiene.
 *
 * Note what is deliberately NOT attempted: constraining `sub`, `scope`, `aud`
 * or lifetime. A delegated issuer's whole job is minting tokens for its own
 * subjects, so those are its business. Trying to police them here would be
 * security theatre — it would look like a control while the issuer could
 * always pick values notme has no basis to judge. The real control is that
 * whatever it mints is only ever valid within its own trust domain.
 */

export class DelegatedJwtError extends Error {
  constructor(
    readonly code: DelegatedJwtErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "DelegatedJwtError";
  }
}

/**
 * Every rejection code. Exhaustive, exported as a union so a caller's `switch`
 * gets compiler exhaustiveness rather than string-matching — same contract
 * shape cloister asked for on ADR-014.
 *
 * None of these are retryable: each means the caller must change what it sent.
 */
export type DelegatedJwtErrorCode =
  | "NOT_BASE64URL"
  | "NOT_JSON"
  | "HEADER_NOT_OBJECT"
  | "PAYLOAD_NOT_OBJECT"
  | "ALG_NOT_EDDSA"
  | "KID_MISMATCH"
  | "TYP_RESERVED"
  | "CNF_FORBIDDEN"
  | "ISS_MISMATCH"
  | "ISSUER_NOT_DELEGATED";

function fail(code: DelegatedJwtErrorCode, message: string): never {
  throw new DelegatedJwtError(code, message);
}

/** Strict base64url (RFC 7515 §2) — no padding, no standard-base64 chars. */
const B64URL = /^[A-Za-z0-9_-]+$/;

function decodeSegment(segment: string, what: string): Record<string, unknown> {
  if (!B64URL.test(segment)) {
    // `+` and `/` are base64 but not base64url. Accepting them would mean the
    // bytes signed differ from the bytes a verifier re-encodes from the
    // compact serialization.
    fail("NOT_BASE64URL", `${what} is not unpadded base64url`);
  }
  let json: string;
  try {
    const pad = "=".repeat((4 - (segment.length % 4)) % 4);
    const bin = atob(segment.replace(/-/g, "+").replace(/_/g, "/") + pad);
    json = new TextDecoder().decode(
      Uint8Array.from(bin, (c) => c.charCodeAt(0)),
    );
  } catch {
    fail("NOT_BASE64URL", `${what} is not decodable base64url`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    fail("NOT_JSON", `${what} is not valid JSON`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    fail(
      what === "header" ? "HEADER_NOT_OBJECT" : "PAYLOAD_NOT_OBJECT",
      `${what} must be a JSON object`,
    );
  }
  return parsed as Record<string, unknown>;
}

/**
 * The `typ` notme's OWN access tokens carry (RFC 9068).
 *
 * Reserved so the two token families stay distinguishable to a human reading
 * a decoded token, not only to a verifier checking a signature. A delegated
 * token that merely *looked* like a notme access token would be a support
 * burden and an incident-response trap even though it could never verify.
 */
const RESERVED_TYP = "at+jwt";

export interface DelegatedSigningContext {
  /** The issuer this key is bound to — from operator config, never the payload. */
  issuer: string;
  /** `kid` of the delegated key. */
  kid: string;
}

/**
 * Validate the two segments and return the exact JWS signing input
 * (RFC 7515 §3.1) to sign.
 *
 * Returns the bytes rather than letting the caller re-derive them, so there
 * is no gap between what was validated and what gets signed — the same
 * discipline as ADR-014's re-encode-and-compare.
 */
export function validateDelegatedJws(
  headerB64: string,
  payloadB64: string,
  ctx: DelegatedSigningContext,
): Uint8Array {
  const header = decodeSegment(headerB64, "header");
  const payload = decodeSegment(payloadB64, "payload");

  if (header.alg !== "EdDSA") {
    fail("ALG_NOT_EDDSA", `alg must be "EdDSA", got ${JSON.stringify(header.alg)}`);
  }

  // A caller advertising a different kid would point verifiers at a key that
  // did not sign this token — at best a verification failure, at worst an
  // attempt to have notme's own kid resolve for a delegated token.
  if (header.kid !== undefined && header.kid !== ctx.kid) {
    fail(
      "KID_MISMATCH",
      `kid must be ${JSON.stringify(ctx.kid)} or absent, got ${JSON.stringify(header.kid)}`,
    );
  }

  if (header.typ === RESERVED_TYP) {
    fail(
      "TYP_RESERVED",
      `typ "${RESERVED_TYP}" is reserved for this authority's own access tokens`,
    );
  }

  // A delegated issuer must not claim key-binding this authority never
  // established. RFC 9449 `cnf.jkt` and RFC 7800 `cnf` generally.
  if (payload.cnf !== undefined) {
    fail(
      "CNF_FORBIDDEN",
      "cnf (proof-of-possession confirmation) cannot be delegated",
    );
  }

  // Derived, never received (notme-6ad276): the caller does not get to say
  // who issued the token. Absent is fine — the caller may omit it and let the
  // binding speak — but a present-and-different iss is a lie, not a default.
  if (payload.iss !== undefined && payload.iss !== ctx.issuer) {
    fail(
      "ISS_MISMATCH",
      `iss must be ${JSON.stringify(ctx.issuer)} or absent, got ${JSON.stringify(payload.iss)}`,
    );
  }

  return new TextEncoder().encode(`${headerB64}.${payloadB64}`);
}
