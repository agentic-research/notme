// AES-GCM envelope encryption for credential header values.
//
// Architecture:
//   KEK (key encryption key) — derived from Worker secret via HKDF.
//   DEK (data encryption key) — random AES-256-GCM key, generated per-encrypt.
//   Sealed blob = { wrappedDek, iv, ciphertext } — all base64url.
//
// The DEK encrypts the plaintext. The KEK wraps the DEK.
// Rotating the KEK means re-wrapping all DEKs (not re-encrypting data).
//
// Pure Web Crypto — no npm dependencies.

/** Sealed envelope: stored in DO SQLite instead of plaintext headers. */
export interface SealedCredential {
  /** AES-256-GCM DEK wrapped by the KEK (base64url). */
  wrappedDek: string;
  /** 96-bit IV for the AES-GCM encryption (base64url). */
  iv: string;
  /** AES-GCM ciphertext of JSON-serialized headers (base64url). */
  ciphertext: string;
}

// ── KEK derivation ──────────────────────────────────────────────────────────

const HKDF_SALT = new TextEncoder().encode("notme-vault-kek-v1");
const HKDF_INFO = new TextEncoder().encode("credential-encryption");

/**
 * Derive a KEK from a secret string using HKDF-SHA256.
 * Deterministic: same secret → same key.
 */
export async function deriveKEK(secret: string): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    "HKDF",
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    { name: "HKDF", salt: HKDF_SALT, info: HKDF_INFO, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false, // NOT extractable — key material never leaves Web Crypto
    ["wrapKey", "unwrapKey"],
  );
}

// ── Encrypt ─────────────────────────────────────────────────────────────────

/**
 * Encrypt credential headers using envelope encryption.
 *
 * 1. Generate a random AES-256-GCM DEK
 * 2. Encrypt the JSON-serialized headers with the DEK
 * 3. Wrap the DEK with the KEK (AES-GCM key wrapping)
 * 4. Return { wrappedDek, iv, ciphertext } — all base64url
 */
export async function encrypt(
  headers: Record<string, string>,
  kek: CryptoKey,
): Promise<SealedCredential> {
  // Generate random DEK
  const dek = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true, // extractable — we need to wrap it
    ["encrypt"],
  );

  // Encrypt plaintext with DEK
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV
  const plaintext = new TextEncoder().encode(JSON.stringify(headers));
  const ciphertextBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    dek,
    plaintext,
  );

  // Wrap DEK with KEK
  const wrapIv = crypto.getRandomValues(new Uint8Array(12));
  const wrappedDekBuf = await crypto.subtle.wrapKey(
    "raw",
    dek,
    kek,
    { name: "AES-GCM", iv: wrapIv },
  );

  // Encode: prefix wrap IV to wrapped DEK so we can unwrap later
  const wrappedWithIv = new Uint8Array(12 + wrappedDekBuf.byteLength);
  wrappedWithIv.set(wrapIv, 0);
  wrappedWithIv.set(new Uint8Array(wrappedDekBuf), 12);

  return {
    wrappedDek: b64url(wrappedWithIv),
    iv: b64url(iv),
    ciphertext: b64url(new Uint8Array(ciphertextBuf)),
  };
}

// ── Decrypt ─────────────────────────────────────────────────────────────────

/**
 * Decrypt a sealed credential envelope.
 *
 * 1. Unwrap the DEK using the KEK
 * 2. Decrypt the ciphertext using the DEK + IV
 * 3. Parse the JSON headers
 */
export async function decrypt(
  sealed: SealedCredential,
  kek: CryptoKey,
): Promise<Record<string, string>> {
  // Decode
  const wrappedWithIv = b64decode(sealed.wrappedDek);
  const wrapIv = wrappedWithIv.slice(0, 12);
  const wrappedDekBytes = wrappedWithIv.slice(12);
  const iv = b64decode(sealed.iv);
  const ciphertext = b64decode(sealed.ciphertext);

  // Unwrap DEK
  const dek = await crypto.subtle.unwrapKey(
    "raw",
    wrappedDekBytes,
    kek,
    { name: "AES-GCM", iv: wrapIv },
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );

  // Decrypt
  const plainBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    dek,
    ciphertext,
  );

  return JSON.parse(new TextDecoder().decode(plainBuf));
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function b64url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function b64decode(s: string): Uint8Array {
  const base64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
