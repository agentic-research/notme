/**
 * correlation-key.ts — a delegation-shaped key that answers "what happened
 * under X" by prefix match, for X at any level of the chain (notme-9f84e6).
 *
 *     <principal>                    everything that principal ever did
 *     <principal>/<bridge>           one machine session
 *     <principal>/<bridge>/<task>    one task
 *
 * ── WHY THESE THREE COMPONENTS ──
 * PRINCIPAL, not a root key id: it is the level a human asks questions about,
 * and it survives CA rotation.
 *
 * BINDING, not a certificate serial. `mintBridgeCertPair` issues TWO
 * certificates with two independently random serials, so no single serial
 * names "the bridge" — it names half of one. The pair already has an
 * identifier: `binding = SHA-256(P-256 SPKI || Ed25519 SPKI)`, returned by
 * that function and carried in the cert at OID_PEER_BINDING. Because the
 * keypairs are ephemeral, this identifies a machine SESSION, which is the
 * right granularity for the middle level.
 *
 * TASK, opaque. notme does not get to decide what upstream calls a unit of
 * work.
 *
 * ── WHY THIS IS NOT JUST `[a, b, c].join("/")` ──
 * The principal is a WIMSE URI and ALREADY CONTAINS SLASHES
 * (`wimse://notme.bot/passkey/<uuid>`). Joining raw produces two silent
 * defects, both of which OVER-MATCH — and for a correlation key, over-matching
 * means attributing one principal's activity to another:
 *
 *   1. PHANTOM LEVELS. The principal's own slashes read as level boundaries,
 *      so a prefix aimed at the bridge level lands inside the principal.
 *   2. STRING-PREFIX IS NOT SEGMENT-PREFIX. "a/b" is a string prefix of
 *      "a/bb", so a query for `wimse://x/a` also matches `wimse://x/ab`.
 *
 * Both are fixed by the same two decisions: percent-encode each segment so
 * "/" cannot occur INSIDE one, and terminate every key and every prefix with
 * the delimiter so a match can only land on a boundary. The result is that a
 * plain `startsWith` — or a KV `list({prefix})` at the edge — is exact,
 * with no parsing on the hot path.
 *
 * This is the same hazard already documented for identity URIs in
 * gen/go/verify/identity.go ("never split this string"). The answer there was
 * a comment telling consumers not to parse; here the structure is the point,
 * so the encoding has to make parsing safe instead of forbidding it.
 *
 * ── WHAT THIS IS NOT ──
 * NOT the revocation index. Revocation needs a mutable, pruned, current-state
 * store keyed by certificate instance; this is append-only history keyed by
 * principal. Serving both from one store produces either pruned history or an
 * unbounded hot auth path. Subtree revocation also needs no key at all —
 * revoking a bridge cert fails every task cert beneath it by issuer, which is
 * intrinsic X.509 behaviour.
 */

/** Segment delimiter and key terminator. See the header for why both. */
const SEP = "/";

/** SHA-256 hex, as produced by `mintBridgeCertPair`'s `binding`. */
const BINDING_RE = /^[0-9a-f]{64}$/;

export interface CorrelationParts {
  /** Stable WIMSE identity URI of the principal. */
  principal: string;
  /** `SHA-256(P-256 SPKI || Ed25519 SPKI)` hex — the bridge pair. */
  binding: string;
  /** Opaque upstream task identifier. */
  task: string;
}

/**
 * Percent-encode everything that could be confused with structure.
 *
 * `encodeURIComponent` already escapes "/" and "%", which is the whole
 * requirement; it is used rather than a bespoke escape so the inverse is
 * `decodeURIComponent` and no custom parser can drift from it.
 */
const enc = (s: string): string => encodeURIComponent(s);

function requirePrincipal(principal: string): void {
  // An absolute URI, so the top level cannot be invented by convention. The
  // scheme is not pinned to wimse: a BYO deployment may name principals
  // differently, and this file has no business deciding that.
  if (!/^[a-z][a-z0-9+.-]*:\/\/.+/i.test(principal)) {
    throw new TypeError(
      `correlation principal must be an absolute URI, got ${JSON.stringify(principal)}`,
    );
  }
}

function requireBinding(binding: string): void {
  if (!BINDING_RE.test(binding)) {
    throw new TypeError(
      "correlation binding must be a SHA-256 hex digest (64 lowercase hex chars)",
    );
  }
}

/**
 * A prefix matching everything at or below the given level.
 *
 * Always ends with the delimiter, which is what makes `startsWith` land on a
 * segment boundary rather than mid-segment.
 */
export function correlationPrefix(parts: {
  principal: string;
  binding?: string;
}): string {
  requirePrincipal(parts.principal);
  let prefix = enc(parts.principal) + SEP;
  if (parts.binding !== undefined) {
    requireBinding(parts.binding);
    prefix += enc(parts.binding) + SEP;
  }
  return prefix;
}

/** The full key for one task. */
export function correlationKey(parts: CorrelationParts): string {
  return (
    correlationPrefix({ principal: parts.principal, binding: parts.binding }) +
    enc(parts.task) +
    SEP
  );
}

/**
 * Recover the components of a key.
 *
 * Returns null rather than throwing on a malformed key: these arrive from
 * storage and from other processes, so a bad one is data to skip, not a
 * failure to propagate into whatever is reading history.
 */
export function parseCorrelationKey(key: string): CorrelationParts | null {
  // Trailing SEP means a trailing empty element; every segment is encoded, so
  // no interior SEP can appear and the split is exact.
  const segments = key.split(SEP);
  if (segments.length !== 4 || segments[3] !== "") return null;
  try {
    const [principal, binding, task] = segments.slice(0, 3).map(decodeURIComponent);
    if (!BINDING_RE.test(binding!)) return null;
    return { principal: principal!, binding: binding!, task: task! };
  } catch {
    // decodeURIComponent throws on a malformed escape sequence.
    return null;
  }
}
