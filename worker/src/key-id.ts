/**
 * Derive the canonical key ID from an Ed25519 SPKI (base64), per signet
 * ADR-012 (bead `signet-248d17`):
 *
 *   kid = lowercasehex( SHA-256( canonical SPKI DER )[:16] )   // 128-bit, 32 hex
 *
 * **Canonicalize-then-hash (ADR-012 R2).** The input SPKI is re-encoded to its
 * canonical DER form before hashing, via Web Crypto import→export. The same key
 * has multiple *valid* SPKI encodings (Ed25519 `parameters` ABSENT per RFC 8410
 * vs a lenient encoder's `NULL`), and hashing the bytes as-received yields a
 * DIFFERENT kid per encoding — which was the bug this fixes: notme previously
 * hashed the received bytes and so could disagree with signet's
 * `MachineFingerprint` (which re-marshals) on any non-canonical input. Web
 * Crypto also *rejects* non-canonical / non-Ed25519 SPKI outright, which is
 * itself ADR-012-conformant ("reject explicit-parameters").
 *
 * **Width: 128-bit (16 bytes).** Widened from the prior 64-bit (rosary-808b0e)
 * per ADR-012's rotation-timing adversary model. Truncation takes the *leading*
 * bytes, so the old 64-bit id is a prefix of the new one (`9408457aefd071ce` ⊂
 * `9408457aefd071cec127c1f985399308`) — migration is a widening, not a re-key.
 * Retiring the remaining 64-bit comparators is tracked in `signet-3723b6` (R3).
 *
 * **Conformance vector (ADR-012):** the fixed Ed25519 pubkey `00..1f` yields
 * `9408457aefd071cec127c1f985399308`. Pinned in signing.test.ts as the
 * cross-language contract every implementation reproduces.
 *
 * In its own file (no DO dependencies) so unit tests can import directly.
 */
export async function keyIdFromSpki(spkiB64: string): Promise<string> {
  const raw = atob(spkiB64);
  const inBytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) inBytes[i] = raw.charCodeAt(i);

  // Import rejects non-canonical / non-Ed25519 SPKI; export re-emits the
  // canonical DER. Hashing that (never `inBytes`) is what makes the kid
  // encoding-independent and byte-identical across implementations.
  const key = await crypto.subtle.importKey(
    "spki",
    inBytes,
    { name: "Ed25519" },
    true,
    ["verify"],
  );
  // exportKey is typed as ArrayBuffer | JsonWebKey; "spki" always yields the
  // ArrayBuffer arm.
  const canonical = (await crypto.subtle.exportKey("spki", key)) as ArrayBuffer;

  const hashBuf = await crypto.subtle.digest("SHA-256", canonical);
  return Array.from(new Uint8Array(hashBuf).slice(0, 16))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
