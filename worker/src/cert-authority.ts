// Edge bridge cert minting using WebCrypto + @peculiar/x509.
//
// GHA variant: authority signs an ephemeral P-256 public key with the master
// Ed25519 key. No KV caching — these certs are 5-minute ephemeral credentials
// returned once to the requesting CI job.
//
// OIDs match the Go authority (cmd/signet/authority.go) for cert format parity.

import { X509CertificateGenerator, Extension } from "@peculiar/x509";

const OID_SUBJECT = "1.3.6.1.4.1.99999.1.1"; // Subject identity
const OID_ISSUANCE_TIME = "1.3.6.1.4.1.99999.1.2"; // Issuance time (RFC3339)

// Encode a string as ASN.1 UTF8String DER (tag 0x0C + length + value)
function derUtf8String(s: string): Uint8Array {
  const encoded = new TextEncoder().encode(s);
  const len = encoded.length;
  if (len < 128) {
    const buf = new Uint8Array(2 + len);
    buf[0] = 0x0c;
    buf[1] = len;
    buf.set(encoded, 2);
    return buf;
  }
  const lenBytes = len < 256 ? 1 : 2;
  const buf = new Uint8Array(2 + lenBytes + len);
  buf[0] = 0x0c;
  buf[1] = 0x80 | lenBytes;
  if (lenBytes === 1) {
    buf[2] = len;
  } else {
    buf[2] = (len >> 8) & 0xff;
    buf[3] = len & 0xff;
  }
  buf.set(encoded, 2 + lenBytes);
  return buf;
}

async function importMasterKey(pem: string): Promise<CryptoKey> {
  const b64 = pem
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replace(/\s/g, "");
  const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey(
    "pkcs8",
    der,
    { name: "Ed25519" } as any,
    false,
    ["sign"],
  );
}

async function importPublicKey(pem: string): Promise<CryptoKey> {
  const b64 = pem
    .replace("-----BEGIN PUBLIC KEY-----", "")
    .replace("-----END PUBLIC KEY-----", "")
    .replace(/\s/g, "");
  const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  // Try Ed25519 first, fall back to ECDSA P-256 (GHA ephemeral keys are P-256)
  try {
    return await crypto.subtle.importKey(
      "spki",
      der,
      { name: "Ed25519" } as any,
      true,
      ["verify"],
    );
  } catch {
    return await crypto.subtle.importKey(
      "spki",
      der,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"],
    );
  }
}

export interface BridgeCertResult {
  certificate: string; // PEM — signed by master Ed25519 key
  expires_at: number; // Unix timestamp
  subject: string; // CN embedded in cert
}

// Mint a bridge cert binding the provided public key to the given subject.
// The subject for GHA certs is the OIDC sub claim:
//   "repo:{owner}/{repo}:ref:refs/heads/{branch}"
//
// masterKey: either a PEM string (legacy) or a CryptoKey from SigningAuthority DO.
export async function mintGHABridgeCert(
  subject: string,
  publicKeyPem: string,
  masterKey: string | CryptoKey,
  ttlMs = 5 * 60 * 1000, // 5 minutes — enough for one CI job
): Promise<BridgeCertResult> {
  const signingKey =
    typeof masterKey === "string"
      ? await importMasterKey(masterKey)
      : masterKey;
  const userPublicKey = await importPublicKey(publicKeyPem);

  const now = new Date();
  const expires = new Date(now.getTime() + ttlMs);

  const serial = crypto
    .getRandomValues(new Uint8Array(16))
    .reduce((s, b) => s + b.toString(16).padStart(2, "0"), "");

  const cert = await X509CertificateGenerator.create({
    subject: `CN=${subject},O=notme`,
    issuer: `CN=signet-authority,O=notme`,
    notBefore: now,
    notAfter: expires,
    signingAlgorithm: { name: "Ed25519" } as any,
    publicKey: userPublicKey,
    signingKey: signingKey,
    serialNumber: serial,
    extensions: [
      new Extension(OID_SUBJECT, false, derUtf8String(subject)),
      new Extension(OID_ISSUANCE_TIME, false, derUtf8String(now.toISOString())),
    ],
  });

  return {
    certificate: cert.toString("pem"),
    expires_at: Math.floor(expires.getTime() / 1000),
    subject,
  };
}
