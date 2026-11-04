/**
 * epoch-history.ts — the signed epoch history served at
 * /.well-known/epochs.json (notme-6a4f23, ADR-019 D7).
 *
 * WHY IT IS SIGNED. A verifier checking an EXPIRED certificate as of the
 * moment it signed (signet's `--at` mode) needs two facts the live CABundle
 * cannot give: which keys served each epoch, and WHEN each ended epoch was
 * revoked. Unsigned, whoever serves the document (an edge cache, a mirror, a
 * MITM on a misissued TLS cert) could drop a revocation or move its time, and
 * a revoked epoch's signatures would verify again. Signed by the root, in the
 * CABundle's discipline — canonical CBOR, a monotonic `seqno` against
 * rollback, an `issuedAt` against freezing — it cannot be rewritten by the
 * server path, only by the key.
 *
 * WHAT ENDED AN EPOCH, AND WHY TWO FIELDS. `retiredAt` (on a key entry) says
 * a key was ROTATED out: its old signatures stay good. `revokedAt` (on a
 * revocation entry) says an EPOCH was ended by `revokeEpoch()`, a declared
 * compromise or mass revocation: signatures in that epoch made at or after
 * `revokedAt` are bad. Revocation is per epoch and rotation is per key — the
 * two axes ADR-019 D7 separated — so they are recorded in different lists
 * rather than as two timestamps on one row.
 *
 * WIRE vs SIGNING FORM. Transported as JSON (the existing `epochs` entries
 * unchanged, for backwards compatibility, with the new fields beside them).
 * Signed as RFC 8949 §4.2 canonical CBOR, integer-keyed (ADR-010):
 *
 *   0: "notme-epoch-history-v1"   domain tag; no CABundle encoding has key 0
 *   1: seqno         uint
 *   2: issuedAt      uint, unix seconds
 *   3: currentEpoch  uint
 *   4: [ {1: epoch, 2: untilEpoch|null, 3: keyId, 4: publicRaw (bytes), 5: retiredAt|null} ... ]
 *   5: [ {1: epoch, 2: revokedAt, 3: reason} ... ]
 *
 * Arrays keep the document's order; the signer emits keys by
 * (epoch, keyId) and revocations by epoch, and a verifier re-encodes what it
 * received rather than sorting. Golden vectors: schema/fixtures/epochhistory-*.
 */

import { Encoder } from "cbor-x";

export const EPOCH_HISTORY_DOMAIN = "notme-epoch-history-v1";

/** One signing key and the inclusive span of epochs it served (unchanged shape). */
export interface EpochKeyEntry {
  epoch: number;
  /** null: still serving. */
  untilEpoch: number | null;
  keyId: string;
  /** standard base64 raw Ed25519 public key */
  publicRawB64: string;
  /** unix seconds the key was ROTATED out; null while live. Not a revocation. */
  retiredAt: number | null;
}

/** An epoch ended by `revokeEpoch()` (POST /admin/revoke-epoch). */
export interface EpochRevocation {
  epoch: number;
  /** unix seconds the revocation committed */
  revokedAt: number;
  /** operator-supplied, public; "unspecified" when none was given */
  reason: string;
}

export interface EpochHistory {
  epochs: EpochKeyEntry[];
  revocations: EpochRevocation[];
  currentEpoch: number;
  seqno: number;
  issuedAt: number;
  /** Ed25519 over epochHistoryCanonical(doc), standard base64 */
  signature: string;
}

/** Longest reason accepted, in UTF-16 code units. It is published verbatim. */
export const REVOCATION_REASON_MAX = 200;

/**
 * Normalize an operator's revocation reason: absent → "unspecified";
 * otherwise a string of 1..REVOCATION_REASON_MAX characters with no control
 * characters. Returns null when it is not acceptable.
 */
export function normalizeRevocationReason(reason: unknown): string | null {
  if (reason === undefined || reason === null) return "unspecified";
  if (typeof reason !== "string") return null;
  const r = reason.trim();
  if (r.length === 0 || r.length > REVOCATION_REASON_MAX) return null;
  if (/\p{Cc}/u.test(r)) return null;
  return r;
}

const encoder = new Encoder({
  mapsAsObjects: false,
  useRecords: false,
  tagUint8Array: false, // plain CBOR bytes (major type 2), as revocation.ts
});

function uint(n: unknown, field: string): number {
  if (typeof n !== "number" || !Number.isSafeInteger(n) || n < 0) {
    throw new Error(`epoch history: ${field} must be a non-negative integer`);
  }
  return n;
}

function b64Bytes(s: string): Uint8Array {
  const norm = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(norm + "=".repeat((4 - (norm.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Canonical CBOR signing input. The `signature` field, if present, is ignored. */
export function epochHistoryCanonical(doc: Omit<EpochHistory, "signature"> & { signature?: string }): Uint8Array {
  const message = new Map<number, unknown>([
    [0, EPOCH_HISTORY_DOMAIN],
    [1, uint(doc.seqno, "seqno")],
    [2, uint(doc.issuedAt, "issuedAt")],
    [3, uint(doc.currentEpoch, "currentEpoch")],
    [
      4,
      doc.epochs.map(
        (e) =>
          new Map<number, unknown>([
            [1, uint(e.epoch, "epoch")],
            [2, e.untilEpoch === null ? null : uint(e.untilEpoch, "untilEpoch")],
            [3, String(e.keyId)],
            [4, b64Bytes(e.publicRawB64)],
            [5, e.retiredAt === null ? null : uint(e.retiredAt, "retiredAt")],
          ]),
      ),
    ],
    [
      5,
      doc.revocations.map(
        (r) =>
          new Map<number, unknown>([
            [1, uint(r.epoch, "revocation epoch")],
            [2, uint(r.revokedAt, "revokedAt")],
            [3, String(r.reason)],
          ]),
      ),
    ],
  ]);
  const out = encoder.encode(message);
  return out instanceof Uint8Array && out.constructor === Uint8Array ? out : new Uint8Array(out);
}

/** True iff `doc.signature` is a valid Ed25519 signature by the root over its canonical form. */
export async function verifyEpochHistorySignature(doc: EpochHistory, rootPublicKeyB64: string): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey("raw", b64Bytes(rootPublicKeyB64), { name: "Ed25519" }, false, [
      "verify",
    ]);
    return await crypto.subtle.verify("Ed25519", key, b64Bytes(doc.signature), epochHistoryCanonical(doc));
  } catch {
    return false;
  }
}

export type EpochStatus =
  | { ok: true }
  | { ok: false; reason: "epoch_revoked" | "epoch_unknown" | "epoch_end_unrecorded" | "history_too_old" };

/**
 * The verifier rule (ADR-019 D7), for a signature made at trusted time `t`
 * (unix seconds, e.g. a Rekor integrated time) by a certificate of `epoch`.
 * Call it only on a document whose signature verified under the root and
 * whose seqno is not below the last one seen.
 *
 *   - `t` must be strictly before `doc.issuedAt`: a history issued at or
 *     before `t` cannot know of a revocation between its issuance and `t`.
 *   - an epoch above `currentEpoch` was never issued under.
 *   - a revoked epoch is good only for `t < revokedAt` ("not revoked at or
 *     before T"); `strict` refuses it whatever `t`.
 *   - the current epoch, unrevoked, is good.
 *   - an ended epoch with no revocation entry is refused: the document
 *     cannot say when it ended (epochs ended before revocations were
 *     recorded, or by the pre-notme-77a024 rotation coupling).
 *
 * The chain itself (validity at `t`, issuer, signature) is the caller's.
 */
export function epochStatusAt(
  doc: Pick<EpochHistory, "currentEpoch" | "revocations" | "issuedAt">,
  epoch: number,
  t: number,
  opts: { strict?: boolean } = {},
): EpochStatus {
  if (!(t < doc.issuedAt)) return { ok: false, reason: "history_too_old" };
  if (epoch > doc.currentEpoch) return { ok: false, reason: "epoch_unknown" };
  const revocation = doc.revocations.find((r) => r.epoch === epoch);
  if (revocation) {
    if (opts.strict || t >= revocation.revokedAt) return { ok: false, reason: "epoch_revoked" };
    return { ok: true };
  }
  if (epoch === doc.currentEpoch) return { ok: true };
  return { ok: false, reason: "epoch_end_unrecorded" };
}
