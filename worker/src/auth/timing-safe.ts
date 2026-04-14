// Constant-time string comparison using HMAC.
//
// JS string === is not constant-time. For security-sensitive comparisons
// (bootstrap codes, session tokens), compare HMAC digests instead.

let cachedKey: CryptoKey | null = null;

async function getHmacKey(): Promise<CryptoKey> {
  if (cachedKey) return cachedKey;
  cachedKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode("notme-timing-safe-cmp"),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return cachedKey;
}

async function hmacDigest(value: string): Promise<ArrayBuffer> {
  const key = await getHmacKey();
  return crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
}

export async function timingSafeEqual(a: string, b: string): Promise<boolean> {
  const [digestA, digestB] = await Promise.all([hmacDigest(a), hmacDigest(b)]);
  const bufA = new Uint8Array(digestA);
  const bufB = new Uint8Array(digestB);
  if (bufA.length !== bufB.length) return false;
  let result = 0;
  for (let i = 0; i < bufA.length; i++) {
    result |= bufA[i]! ^ bufB[i]!;
  }
  return result === 0;
}
