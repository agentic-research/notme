/**
 * revocation.ts — Edge certificate revocation for the APAS stack.
 *
 * Implements the **verifier** side of signet's SPIRE-model revocation at the
 * Cloudflare edge. The **issuer** side lives in signet (Go):
 *   https://github.com/agentic-research/signet
 *
 * Architecture:
 *   - CABundle      — mirrors signet's pkg/revocation/types.CABundle
 *   - RevocationAuthority — Durable Object: atomic monotonic seqno (rollback protection)
 *   - verifyBundleSignature — WebCrypto Ed25519 bundle signature check
 *   - checkRevocation — full token revocation check (bundle → seqno → epoch → kid)
 *
 * KV stores the current CA bundle (written by signet on rotation).
 * DO enforces SetLastSeenSeqnoIfGreater atomically (one instance per issuer).
 *
 * Spec: https://notme.bot/apas
 */

// ── Types ─────────────────────────────────────────────────────────────────────

/**
 * CABundle mirrors signet's pkg/revocation/types.CABundle.
 *
 * `keys` values are base64-standard encoded (Go json.Marshal encodes []byte
 * as standard base64, not base64url). `signature` is likewise base64-standard.
 */
export interface CABundle {
  epoch: number;
  seqno: number;
  /** kid → base64-standard raw Ed25519 public key (32 bytes) */
  keys: Record<string, string>;
  keyId: string;
  prevKeyId?: string;
  /**
   * Unix-seconds at which the bundle was issued. REQUIRED — staleness check
   * is fail-closed. A bundle without `issuedAt` is treated as stale at
   * runtime even if its signature is otherwise valid (rosary-9bb26b).
   */
  issuedAt: number;
  /** Ed25519 signature over bundleCanonical(bundle), base64-standard */
  signature: string;
}

export interface TokenClaims {
  /** Key ID from token field 10 — hex or base64url encoded */
  keyId: string;
  /** Epoch from token field 19 */
  epoch: number;
}

export type RevocationReason =
  | "epoch_mismatch"   // token.epoch < bundle.epoch — old epoch, cert class revoked
  | "unknown_key"      // keyId not in bundle.keyId or prevKeyId
  | "rollback_attack"  // bundle seqno decreased — reject
  | "bundle_invalid"   // bundle signature verification failed
  | "bundle_stale";    // bundle issuedAt too old (clock-skew limit exceeded)

export type RevocationResult =
  | { revoked: false }
  | { revoked: true; reason: RevocationReason };

export interface RevocationEnv {
  CA_BUNDLE_CACHE?: KVNamespace;
  REVOCATION: DurableObjectNamespace;
}

// ── Durable Object ────────────────────────────────────────────────────────────

/**
 * RevocationAuthority — Durable Object enforcing monotonic seqno advancement.
 *
 * Implements signet's Storage.SetLastSeenSeqnoIfGreater atomically per issuer.
 * Key: `seqno:<issuerId>` — one DO instance handles all issuers for a Worker.
 *
 * Rollback semantics:
 *   seqno >  lastSeen → advance, ok
 *   seqno == lastSeen → same bundle fetched again, ok (no-op)
 *   seqno <  lastSeen → rollback attack, reject
 */
export class RevocationAuthority {
  constructor(private state: DurableObjectState) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/seqno") {
      return this.handleSeqno(request);
    }
    return new Response("not found", { status: 404 });
  }

  private async handleSeqno(request: Request): Promise<Response> {
    const { issuerId, seqno } = await request.json<{
      issuerId: string;
      seqno: number;
    }>();

    // Validate seqno is a positive integer — null/undefined/NaN bypasses rollback check
    if (typeof seqno !== "number" || !Number.isFinite(seqno) || seqno < 1) {
      return Response.json({ ok: false, reason: "invalid_seqno" }, { status: 400 });
    }

    const result = await this.state.storage.transaction(async (txn) => {
      const key = `seqno:${issuerId}`;
      const last = (await txn.get<number>(key)) ?? 0;
      if (seqno < last) return { ok: false, reason: "rollback" as const };
      if (seqno > last) await txn.put(key, seqno);
      return { ok: true };
    });

    return Response.json(result);
  }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/** Decode base64 (standard or url-safe) to Uint8Array<ArrayBuffer>. */
function b64Decode(s: string): Uint8Array<ArrayBuffer> {
  const norm = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (norm.length % 4)) % 4;
  const binary = atob(norm + "=".repeat(pad));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * Canonical JSON for bundle signature verification.
 *
 * Excludes the `signature` field; sorts remaining keys alphabetically.
 * Must stay in sync with signet's signing implementation.
 */
/**
 * Staleness gate — fail closed.
 *
 * A bundle without a valid `issuedAt` (missing, NaN, non-positive) is
 * treated as stale even if its signature is otherwise valid. This is
 * defense-in-depth — the type signature also requires `issuedAt`, but
 * malformed JSON could slip through KV deserialization with the wrong
 * shape, and a producer that omitted the field would otherwise yield
 * a bundle accepted forever (rosary-9bb26b).
 *
 * Bundles older than BUNDLE_MAX_AGE_MS are also stale — that's the
 * normal clock-skew window enforced against legitimate-but-old bundles.
 *
 * `nowMs` is injectable for tests; defaults to `Date.now()`.
 */
export function isBundleStale(bundle: CABundle, nowMs: number = Date.now()): boolean {
  if (
    typeof bundle.issuedAt !== "number" ||
    !Number.isFinite(bundle.issuedAt) ||
    bundle.issuedAt <= 0
  ) {
    return true;
  }
  return nowMs - bundle.issuedAt * 1000 > BUNDLE_MAX_AGE_MS;
}

export function bundleCanonical(bundle: CABundle): Uint8Array {
  const { signature: _sig, ...rest } = bundle;
  const sorted: Record<string, unknown> = {};
  for (const k of Object.keys(rest).sort()) {
    sorted[k] = rest[k as keyof typeof rest];
  }
  return new TextEncoder().encode(JSON.stringify(sorted));
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Verify a CA bundle's Ed25519 signature against a trusted root public key.
 *
 * @param bundle - the bundle to verify
 * @param rootPublicKeyB64 - base64-encoded (standard or url) raw Ed25519 root key (32 bytes)
 * @returns true if the signature is valid
 */
export async function verifyBundleSignature(
  bundle: CABundle,
  rootPublicKeyB64: string,
): Promise<boolean> {
  try {
    const keyBytes = b64Decode(rootPublicKeyB64);
    const key = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      "Ed25519",
      key,
      b64Decode(bundle.signature),
      bundleCanonical(bundle),
    );
  } catch {
    // Malformed key or signature bytes — treat as verification failure.
    return false;
  }
}

/** Maximum age of a CA bundle before it is considered stale (5 minutes). */
export const BUNDLE_MAX_AGE_MS = 5 * 60 * 1000;

/**
 * Check whether a token is revoked against the current CA bundle.
 *
 * Steps:
 *  1. Fetch CA bundle from KV (written by signet on rotation)
 *  2. Reject if bundle is stale (issuedAt + BUNDLE_MAX_AGE_MS < now)
 *  3. Verify bundle Ed25519 signature with the trusted root key
 *  4. Atomic seqno check via RevocationAuthority DO (rollback protection)
 *  5. Check token epoch against bundle epoch
 *  6. Check token keyId against bundle keyId / prevKeyId
 *
 * Fails **open** if no bundle exists (bootstrap / first deploy).
 * Fails **closed** on signature failure or rollback attack.
 *
 * @param token - claims extracted from the incoming signet token
 * @param env - Worker bindings (CA_BUNDLE_CACHE + REVOCATION)
 * @param rootPublicKeyB64 - base64 root public key for bundle verification
 */
export async function checkRevocation(
  token: TokenClaims,
  env: RevocationEnv,
  rootPublicKeyB64: string,
): Promise<RevocationResult> {
  // 1. Fetch bundle from KV
  if (!env.CA_BUNDLE_CACHE) {
    // No KV binding (local workerd) — fail open (same as no bundle)
    return { revoked: false };
  }
  const bundle = await env.CA_BUNDLE_CACHE.get<CABundle>(
    "bundle:current",
    "json",
  );
  if (!bundle) {
    // No bundle published yet — fail open (bootstrap case)
    return { revoked: false };
  }

  // 2. Staleness check — fail closed.
  if (isBundleStale(bundle)) {
    return { revoked: true, reason: "bundle_stale" };
  }

  // 3. Verify bundle signature
  if (!(await verifyBundleSignature(bundle, rootPublicKeyB64))) {
    return { revoked: true, reason: "bundle_invalid" };
  }

  // 4. Rollback protection via DO (one instance per issuer)
  const doId = env.REVOCATION.idFromName("notme.bot");
  const stub = env.REVOCATION.get(doId);
  const resp = await stub.fetch("http://do/seqno", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ issuerId: "notme.bot", seqno: bundle.seqno }),
  });
  const { ok } = await resp.json<{ ok: boolean }>();
  if (!ok) {
    return { revoked: true, reason: "rollback_attack" };
  }

  // 5. Epoch check — token issued before CA rotation
  if (token.epoch < bundle.epoch) {
    return { revoked: true, reason: "epoch_mismatch" };
  }

  // 6. Key ID check — token signed with an unknown CA key
  if (token.keyId !== bundle.keyId && token.keyId !== bundle.prevKeyId) {
    return { revoked: true, reason: "unknown_key" };
  }

  return { revoked: false };
}
