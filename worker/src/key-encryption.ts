// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 notme contributors
//
// Envelope encryption for the authority's own PRIVATE SIGNING KEYS at rest.
//
// PROVENANCE. The KEK/DEK construction below is notme's own Apache-2.0
// `vault/src/crypto.ts`, recovered from git history (deleted in 0d3ec86,
// "retire notme/vault", ADR-012). It is deliberately NOT copied from
// cloister/vault/src/crypto.ts, which is the same code re-licensed
// AGPL-3.0-or-later — copying that back would pull AGPL into an Apache-2.0
// repo. cloister's own NOTICE anticipates this: "the original copy in notme
// remains under Apache 2.0 and is unaffected." Verified 2026-08-04: the two
// files are byte-identical apart from their three-line license headers, so
// nothing is lost by taking the Apache-2.0 side.
//
// WHY THIS EXISTS. ADR-012 lifted the credential vault to cloister, where
// tenant credentials get envelope encryption with per-tenant KEKs. notme kept
// the CA master Ed25519 key — and stored it as a plaintext JWK in DO SQLite.
// The substrate encrypted the leaves and left the root in the clear, while the
// root has by far the larger blast radius: it mints certs for any identity
// with any scopes, and signs the `at+jwt` access tokens every notme resource
// server accepts.
//
// ADR-007 already stated the bar this failed: "A system that claims to be
// secretless cannot have `cat *.sqlite | strings | grep '\"d\"'` extract the
// CA key."
//
// WHAT THIS BUYS, STATED HONESTLY. It does not stop an attacker who can
// execute in the Worker — they can just ask the authority to sign. What it
// separates is "can read DO storage" from "can read Worker secrets", which are
// two different compromise surfaces. That separation is the whole reason
// cloister built it for credentials; the CA key deserves it more.

/**
 * A sealed private key as stored in the `private_jwk` column.
 *
 * The `sealed` member is a DISCRIMINATOR, not decoration. Rows written before
 * this module existed hold a bare JWK, and both shapes must coexist in one
 * column during migration. Detecting by the presence of an explicit marker is
 * robust; detecting by the *absence* of `d` or `kty` would misread a malformed
 * row as sealed and produce an unwrap error instead of a clear diagnosis.
 */
export interface SealedKey {
  /** Format marker + version. Bumping it forces a deliberate re-seal. */
  sealed: "notme-authority-kek-v1";
  /** AES-256-GCM DEK wrapped by the KEK, with its 96-bit wrap IV prefixed (base64url). */
  wrappedDek: string;
  /** 96-bit IV for the payload encryption (base64url). */
  iv: string;
  /** AES-GCM ciphertext of the JSON-serialised JWK (base64url). */
  ciphertext: string;
}

const SEALED_MARKER = "notme-authority-kek-v1" as const;

// ── KEK derivation ──────────────────────────────────────────────────────────

// DOMAIN SEPARATION. Deliberately different from the vault's
// ("notme-vault-kek-v1" / "credential-encryption"). One operator secret may
// plausibly be reused across both; if the salt and info matched, the same
// secret would derive the SAME KEK for two unrelated purposes, and a blob
// sealed by one subsystem would unseal under the other. Same discipline as
// the HKDF separator in auth/dpop-nonce.ts.
const HKDF_SALT = new TextEncoder().encode("notme-authority-kek-v1");
const HKDF_INFO = new TextEncoder().encode("signing-key-encryption");

/**
 * Derive the key-encryption key from an operator secret (`NOTME_KEK_SECRET`).
 *
 * Deterministic — the same secret always yields the same KEK, which is what
 * makes a restarted Worker able to read what a previous instance sealed.
 * Non-extractable, so the derived key itself can never be exported back out
 * of Web Crypto.
 */
export async function deriveKek(secret: string): Promise<CryptoKey> {
  if (!secret) {
    // Fail loud. A blank secret would still derive a perfectly usable KEK, and
    // every key would then be sealed under a value an attacker can guess in one
    // try — strictly worse than plaintext, because it looks encrypted.
    throw new Error("deriveKek: secret is empty");
  }
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    "HKDF",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "HKDF", salt: HKDF_SALT, info: HKDF_INFO, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false, // never extractable
    ["wrapKey", "unwrapKey"],
  );
}

// ── Seal / unseal ───────────────────────────────────────────────────────────

/** Envelope-encrypt a private JWK for storage. */
export async function sealPrivateJwk(
  jwk: JsonWebKey,
  kek: CryptoKey,
): Promise<SealedKey> {
  // Per-seal DEK. Extractable only so it can be wrapped; it is discarded when
  // this function returns and never touches storage unwrapped.
  const dek = (await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt"],
  )) as CryptoKey;

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    dek,
    new TextEncoder().encode(JSON.stringify(jwk)),
  );

  const wrapIv = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await crypto.subtle.wrapKey("raw", dek, kek, {
    name: "AES-GCM",
    iv: wrapIv,
  });

  // Prefix the wrap IV so unsealing needs only the KEK and this one field.
  const wrappedWithIv = new Uint8Array(12 + wrapped.byteLength);
  wrappedWithIv.set(wrapIv, 0);
  wrappedWithIv.set(new Uint8Array(wrapped), 12);

  return {
    sealed: SEALED_MARKER,
    wrappedDek: b64url(wrappedWithIv),
    iv: b64url(iv),
    ciphertext: b64url(new Uint8Array(ciphertext)),
  };
}

/** Decrypt a sealed private JWK. Throws if the KEK is wrong or the blob is tampered. */
export async function unsealPrivateJwk(
  sealed: SealedKey,
  kek: CryptoKey,
): Promise<JsonWebKey> {
  const wrappedWithIv = b64decode(sealed.wrappedDek);
  const dek = await crypto.subtle.unwrapKey(
    "raw",
    wrappedWithIv.slice(12),
    kek,
    { name: "AES-GCM", iv: wrappedWithIv.slice(0, 12) },
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64decode(sealed.iv) },
    dek,
    b64decode(sealed.ciphertext),
  );
  return JSON.parse(new TextDecoder().decode(plain)) as JsonWebKey;
}

// ── Migration helper ────────────────────────────────────────────────────────

/**
 * Read a `private_jwk` column that may hold either shape.
 *
 * Returns the JWK plus whether it arrived sealed, so the caller can re-seal a
 * legacy row in place. Callers MUST treat `wasSealed: false` as "this key has
 * been sitting in cleartext" rather than as a benign default.
 */
export async function readStoredJwk(
  stored: string,
  kek: CryptoKey | null,
): Promise<{ jwk: JsonWebKey; wasSealed: boolean }> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stored);
  } catch {
    throw new Error("readStoredJwk: stored private_jwk is not JSON");
  }
  if (isSealed(parsed)) {
    if (!kek) {
      // Refuse rather than guess. Returning null here would let a caller with a
      // missing/misconfigured secret silently regenerate the authority key,
      // which invalidates every certificate and token ever issued.
      throw new Error(
        "readStoredJwk: stored key is sealed but no KEK is configured — " +
          "set NOTME_KEK_SECRET to the value used when it was sealed",
      );
    }
    return { jwk: await unsealPrivateJwk(parsed, kek), wasSealed: true };
  }
  return { jwk: parsed as JsonWebKey, wasSealed: false };
}

/** Type guard for the sealed shape. Checks the marker, not the absence of JWK fields. */
export function isSealed(value: unknown): value is SealedKey {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as { sealed?: unknown }).sealed === SEALED_MARKER
  );
}

/** Serialise for the `private_jwk` column: sealed when a KEK exists, bare JWK otherwise. */
export async function serialiseJwkForStorage(
  jwk: JsonWebKey,
  kek: CryptoKey | null,
): Promise<string> {
  if (!kek) return JSON.stringify(jwk);
  return JSON.stringify(await sealPrivateJwk(jwk, kek));
}

// ── base64url (RFC 4648 §5, unpadded) ───────────────────────────────────────

function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64decode(s: string): Uint8Array {
  const padded =
    s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
