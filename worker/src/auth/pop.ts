/**
 * pop.ts — the one proof-of-possession check (notme-a011d2).
 *
 * A caller proves it holds both private keys by signing the BINDING PRE-IMAGE
 * with each. Three routes need this — `/cert/gha`, `/cert`, `/cert/passkey` —
 * and each previously carried its own inline copy: two `crypto.subtle.verify`
 * calls wrapped in try/catch, six blocks across two files. That duplication is
 * why the convention could drift on all of them at once without any single
 * change looking wrong.
 *
 * ── WHAT THE SIGNED MESSAGE IS, and why this file exists ──
 * The proofs cover `bindingInput` ITSELF, never `SHA-256(bindingInput)`.
 *
 * `crypto.subtle.verify({name:"ECDSA", hash:"SHA-256"}, …)` applies SHA-256 to
 * whatever it is handed. Passing a digest therefore verifies against
 * SHA-256(SHA-256(bindingInput)) — two hashes. Go's `ecdsa.Sign(rand, priv,
 * digest)` takes the digest as its argument and applies none, so a conformant
 * Go signer produces one hash and could never interoperate. Signet's
 * v0.3.0-rc.2 release run found this against production; notme's own action
 * double-hashed identically, so a round trip between them passed and hid it.
 *
 * Ed25519 is PureEdDSA over the message, so it does not double-hash — but it
 * is held to the SAME rule deliberately. If the two proofs in one request
 * covered different bytes, every implementer would assume otherwise and the
 * mismatch would only surface as an opaque 401.
 *
 * ONE RULE, BOTH ALGORITHMS: sign the pre-image, let each primitive apply its
 * own hashing. That is what a Go, Rust or Python signer does by default, which
 * is the entire point of a cross-language proof.
 */

/**
 * Base64url (or base64) proof bytes, as they arrive on the wire.
 *
 * Both fields are optional because that is what a parsed request body actually
 * offers — a caller can simply omit one. An absent proof is a FAILED proof,
 * not a skipped check; see `decodeProof`.
 */
export interface PopProofs {
  /** P-256 / ES256 signature, raw r||s — NOT DER. */
  mtls?: string;
  /** Ed25519 signature. */
  signing?: string;
}

export type PopResult =
  /**
   * `binding` reports WHICH encoding matched. "digest" means the caller is a
   * pre-fix signer still covering SHA-256(bindingInput); it is accepted during
   * the migration window below and is worth logging, because the window closes
   * when that count reaches zero.
   */
  | { ok: true; binding: "pre-image" | "digest" }
  /** Which key failed, so the caller can say so without re-deriving it. */
  | { ok: false; algorithm: "P-256" | "Ed25519" };

/**
 * TRANSITIONAL: also accept proofs over SHA-256(bindingInput) — the pre-fix
 * encoding (notme-a011d2).
 *
 * WHY THIS EXISTS RATHER THAN A CLEAN CUT. The signer and the verifier ship
 * in different places: the Worker deploys from this repo, while
 * `.github/workflows/gha-identity.yml` pins `agentic-research/notme/action`
 * at a COMMIT SHA. Deploying the corrected verifier alone breaks that pinned
 * action; bumping the pin alone breaks it against the old verifier. The two
 * can only cross together, and the pin bump cannot land before the
 * goalzero→main merge — so a flag day would mean either a broken window or
 * holding signet's release behind an unrelated merge gate.
 *
 * WHY IT IS SAFE. Both encodings are deterministic functions of the same two
 * public keys, proved by the same private keys. Accepting either does not let
 * a caller assert anything it could not already assert with the other; there
 * is no cross-protocol confusion, because neither message is meaningful input
 * to any other verifier in this system. What it costs is one extra verify on
 * the failure path, and an ambiguity that must not become permanent.
 *
 * REMOVAL — notme-a011d2 tracks it. Delete this constant and the second
 * attempt in `verifyPopProofs` once the action pin is bumped past
 * 0d2312f and no request has reported `binding: "digest"`.
 */
const ACCEPT_LEGACY_DIGEST_BINDING = true;

const ED25519 = { name: "Ed25519" } as const;

/**
 * Decode base64url or standard base64 to bytes.
 *
 * Returns null rather than throwing: undecodable proof bytes are a failed
 * proof, not an exception. Every call site used to wrap `verify` in try/catch
 * purely to convert a throw into a 401; folding that in here is what lets them
 * drop it.
 */
function decodeProof(s: string | undefined): Uint8Array<ArrayBuffer> | null {
  // Absent or empty is a failed proof. Without this an omitted field would
  // decode to zero bytes and reach `verify`, which rejects it — the right
  // answer by accident, via a path that reads like a skipped check.
  if (!s) return null;
  const norm = s.replace(/-/g, "+").replace(/_/g, "/");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(norm)) return null;
  try {
    const bin = atob(norm + "=".repeat((4 - (norm.length % 4)) % 4));
    const out = new Uint8Array(new ArrayBuffer(bin.length));
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/**
 * Verify both proof-of-possession signatures over the binding pre-image.
 *
 * @param bindingInput - the pre-image, NOT its digest. Callers build this by
 *   concatenating the SPKI DER of both public keys (plus, on `/cert/gha`, the
 *   SHA-256 of the OIDC JWT). Passing a digest here is the bug this file
 *   exists to prevent, and `pop-preimage.test.ts` pins it with a fixture no
 *   WebCrypto signer in this repo can reproduce.
 * @param mtlsPubKey - imported P-256 public key
 * @param signingPubKey - imported Ed25519 public key
 * @param proofs - the wire-encoded signatures
 */
export async function verifyPopProofs(
  bindingInput: BufferSource,
  mtlsPubKey: CryptoKey,
  signingPubKey: CryptoKey,
  proofs: PopProofs,
): Promise<PopResult> {
  const checks = [
    {
      algorithm: "P-256" as const,
      params: { name: "ECDSA", hash: "SHA-256" },
      key: mtlsPubKey,
      proof: proofs.mtls,
    },
    {
      algorithm: "Ed25519" as const,
      params: ED25519,
      key: signingPubKey,
      proof: proofs.signing,
    },
  ];

  // Computed lazily and only if the pre-image attempt fails, so a conformant
  // caller never pays for the legacy path.
  let digest: ArrayBuffer | undefined;
  let sawLegacy = false;

  for (const check of checks) {
    const bytes = decodeProof(check.proof);
    if (!bytes) return { ok: false, algorithm: check.algorithm };

    // `verify` throws on a key/signature shape WebCrypto rejects outright —
    // the same disposition as a signature that simply does not match.
    const attempt = async (message: BufferSource) => {
      try {
        return await crypto.subtle.verify(
          check.params,
          check.key,
          bytes,
          message,
        );
      } catch {
        return false;
      }
    };

    if (await attempt(bindingInput)) continue;

    if (!ACCEPT_LEGACY_DIGEST_BINDING) {
      return { ok: false, algorithm: check.algorithm };
    }
    digest ??= await crypto.subtle.digest("SHA-256", bindingInput);
    if (!(await attempt(digest))) {
      return { ok: false, algorithm: check.algorithm };
    }
    sawLegacy = true;
  }

  return { ok: true, binding: sawLegacy ? "digest" : "pre-image" };
}
