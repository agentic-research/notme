/**
 * dpop-nonce.ts — server-issued DPoP nonces (RFC 9449 §8, §9).
 *
 * Without a nonce, the only freshness control on a DPoP proof is its `iat`
 * claim, which the CLIENT writes and the server accepts within a tolerance
 * window (±60s, see dpop.ts). That makes proof freshness a property of the
 * client's clock. A nonce inverts it: the server names a value the client
 * cannot have known in advance, so a proof carrying it is provably no older
 * than the challenge that produced it.
 *
 * The nonce is STATELESS — an HMAC over its own timestamp, not a row in a
 * table. Two reasons:
 *
 *   1. A stored nonce needs a write on issue and a read on redeem. The /token
 *      path already pays one DO round-trip (`mintDPoPTokenOnce`); adding a
 *      second one to hand out a value the client immediately returns is cost
 *      for no security — an attacker who cannot forge the MAC cannot forge the
 *      nonce either.
 *   2. Nonces are issued on the REJECTION path. A stored nonce would let an
 *      unauthenticated caller drive unbounded writes by spamming proofs
 *      without one.
 *
 * The tradeoff is honest and worth stating: a stateless nonce is verifiable
 * but not single-use. Within its validity window the same nonce may be
 * replayed. That is not a hole here, because the PROOF carrying it is
 * single-use — `mintDPoPTokenOnce` consumes the `jti` atomically
 * (signing-authority.ts). The nonce bounds freshness; the jti bounds reuse.
 * Neither alone is sufficient and the split is deliberate.
 */

import { encodeBase64url, decodeBase64url } from "@oslojs/encoding";

/**
 * How long an issued nonce stays redeemable.
 *
 * Long enough for a client to receive the challenge and re-sign a proof
 * (one round-trip), short enough that a captured challenge is not a
 * long-lived asset. RFC 9449 §8.2 leaves the lifetime to the server.
 */
export const NONCE_TTL_SECONDS = 300;

/**
 * Tolerance for a nonce timestamp in the future.
 *
 * The timestamp is written by THIS server, so a future-dated nonce means
 * clock movement between edge locations, not client behaviour. Kept tight —
 * a wide window here would silently extend the effective TTL.
 */
const NONCE_FUTURE_SKEW_SECONDS = 5;

/**
 * Domain separator. Baked into both the HKDF info and the signed message.
 *
 * The key is derived from the same authority secret that signs session
 * cookies. Without separation, a value signed for one purpose could be
 * presented as the other; with it, a session HMAC is not a valid nonce MAC
 * and vice versa, even though one secret underlies both. The `v1` is the
 * rotation handle: changing it invalidates every outstanding nonce, which is
 * the intended behaviour if the format ever changes.
 */
const NONCE_DOMAIN = "notme-dpop-nonce-v1";

/**
 * Whether this deployment requires a server-issued nonce on DPoP proofs.
 *
 * Defaults to OFF. Requiring a nonce means every client's first request is
 * answered with a 400 challenge it must understand and retry — correct per
 * RFC 9449 §8, and a breaking change for any deployed client that does not
 * implement the retry. Operators opt in once their clients handle it.
 *
 * Accepts `true`/`1` (case-insensitive, surrounding whitespace ignored).
 * Anything else, including absent, is off — an unparseable value must not
 * silently enable a rejection path.
 */
export function dpopNonceRequired(env: {
  DPOP_REQUIRE_NONCE?: string;
}): boolean {
  const raw = env.DPOP_REQUIRE_NONCE?.trim().toLowerCase();
  return raw === "true" || raw === "1";
}

/**
 * Derive the nonce MAC key from the authority's session secret.
 *
 * HKDF rather than using the secret directly — see NONCE_DOMAIN. The derived
 * key is non-extractable and scoped to HMAC-SHA-256.
 */
async function deriveNonceKey(
  secret: string,
  usage: "sign" | "verify",
): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    "HKDF",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: new TextEncoder().encode(NONCE_DOMAIN),
    },
    material,
    { name: "HMAC", hash: "SHA-256" },
    false,
    [usage],
  );
}

/** The bytes the MAC covers: the domain separator and the timestamp. */
function nonceMessage(issuedAt: number): Uint8Array {
  return new TextEncoder().encode(`${NONCE_DOMAIN}:${issuedAt}`);
}

/**
 * Issue a nonce for a `use_dpop_nonce` challenge.
 *
 * Wire format is `<issuedAt>.<base64url(mac)>`. Both characters used as
 * structure (the digits and the `.`) are outside the base64url alphabet, so
 * the split is unambiguous regardless of MAC content.
 *
 * @param secret  The authority session secret (`getSessionSecret()`).
 * @param now     Unix seconds. Injected so tests can drive the clock.
 */
export async function issueDpopNonce(
  secret: string,
  now: number = Math.floor(Date.now() / 1000),
): Promise<string> {
  const issuedAt = Math.floor(now);
  const key = await deriveNonceKey(secret, "sign");
  const mac = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, nonceMessage(issuedAt)),
  );
  return `${issuedAt}.${encodeBase64url(mac)}`;
}

/**
 * Verify a nonce presented in a DPoP proof.
 *
 * Returns false rather than throwing for every rejection reason: the caller's
 * response is the same in all cases (a fresh challenge), and a caller that
 * distinguished "malformed" from "expired" from "bad MAC" would be an oracle
 * for probing the nonce format.
 *
 * @param nonce   The `nonce` claim from the proof. Untrusted input — may be
 *                any type, since it arrives from parsed client JSON.
 * @param secret  The authority session secret.
 * @param now     Unix seconds. Injected so tests can drive the clock.
 */
export async function verifyDpopNonce(
  nonce: unknown,
  secret: string,
  now: number = Math.floor(Date.now() / 1000),
): Promise<boolean> {
  if (typeof nonce !== "string") return false;

  const separator = nonce.indexOf(".");
  if (separator <= 0) return false;

  const issuedAtRaw = nonce.slice(0, separator);
  const macRaw = nonce.slice(separator + 1);
  if (macRaw.length === 0) return false;

  // Strict digits only. `Number()` would accept "0x10", " 10", "1e3" and
  // Infinity, each of which is a different integer than the one that was
  // signed — and the MAC check below would then fail for a confusing reason,
  // or (for a canonicalization that round-trips) pass on a value the issuer
  // never wrote.
  if (!/^\d+$/.test(issuedAtRaw)) return false;
  const issuedAt = Number(issuedAtRaw);
  if (!Number.isSafeInteger(issuedAt)) return false;

  const age = now - issuedAt;
  if (age > NONCE_TTL_SECONDS) return false;
  if (age < -NONCE_FUTURE_SKEW_SECONDS) return false;

  let mac: Uint8Array;
  try {
    mac = decodeBase64url(macRaw);
  } catch {
    return false;
  }

  const key = await deriveNonceKey(secret, "verify");
  // crypto.subtle.verify, not a byte comparison — the platform's HMAC
  // verification does not short-circuit on the first differing byte.
  return crypto.subtle.verify("HMAC", key, mac, nonceMessage(issuedAt));
}
