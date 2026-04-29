// Edge bridge cert minting using WebCrypto + @peculiar/x509.
//
// GHA variant: authority signs an ephemeral P-256 public key with the master
// Ed25519 key. No KV caching — these certs are 5-minute ephemeral credentials
// returned once to the requesting CI job.
//
// OIDs match the Go authority (cmd/signet/authority.go) for cert format parity.

import {
  X509CertificateGenerator,
  Extension,
  BasicConstraintsExtension,
  KeyUsagesExtension,
  KeyUsageFlags,
  ExtendedKeyUsageExtension,
} from "@peculiar/x509";
import { ED25519 } from "./platform";

// Leaf-cert extensions — declare what each cert is for so strict X.509
// validators (rustls, boringssl, openssl 3) can enforce. Without these, the
// signing cert can't be used by validators that require explicit
// digitalSignature KeyUsage (e.g. ley-line manifest receivers).
//
// BasicConstraints CA=false marks both certs as end-entity (not CAs).
// Marked critical per RFC 5280 §4.2.1.9.
const BASIC_CONSTRAINTS_LEAF = new BasicConstraintsExtension(false, undefined, true);

// mTLS cert: digitalSignature (TLS handshake signing) + keyAgreement
// (ECDHE in TLS 1.2+); ExtendedKeyUsage clientAuth so validators that
// enforce EKU on TLS clients accept it.
const MTLS_KEY_USAGE = new KeyUsagesExtension(
  KeyUsageFlags.digitalSignature | KeyUsageFlags.keyAgreement,
  true,
);
const CLIENT_AUTH_EKU = new ExtendedKeyUsageExtension(
  ["1.3.6.1.5.5.7.3.2"], // id-kp-clientAuth
  false,
);

// Signing cert: digitalSignature is sufficient for arbitrary payload
// signatures (ley-line manifests, git commits, attestations, DSSE).
const SIGNING_KEY_USAGE = new KeyUsagesExtension(
  KeyUsageFlags.digitalSignature,
  true,
);

const OID_SUBJECT = "1.3.6.1.4.1.99999.1.1"; // Subject identity
const OID_ISSUANCE_TIME = "1.3.6.1.4.1.99999.1.2"; // Issuance time (RFC3339)
const OID_SCOPES = "1.3.6.1.4.1.99999.1.3"; // Granted scopes
const OID_EPOCH = "1.3.6.1.4.1.99999.1.4"; // CA epoch at issuance
const OID_AUTH_METHOD = "1.3.6.1.4.1.99999.1.5"; // Authentication method
const OID_PEER_BINDING = "1.3.6.1.4.1.99999.1.6"; // SHA-256(P-256 SPKI || Ed25519 SPKI)

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
    ED25519,
    false,
    ["sign"],
  );
}

export async function importPublicKey(pem: string): Promise<CryptoKey> {
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
      ED25519,
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

export interface BridgeCertPairResult {
  certificates: {
    mtls: string; // P-256 cert PEM
    signing: string; // Ed25519 cert PEM
  };
  identity: string; // wimse:// URI
  scopes: string[];
  expires_at: number;
  subject: string;
  binding: string; // SHA-256(P-256 SPKI || Ed25519 SPKI) hex
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

  // GHA legacy single cert is used as a TLS client cert AND for arbitrary
  // signing — set both digitalSignature and keyAgreement, plus clientAuth EKU.
  const ghaKeyUsage = new KeyUsagesExtension(
    KeyUsageFlags.digitalSignature | KeyUsageFlags.keyAgreement,
    true,
  );

  const cert = await X509CertificateGenerator.create({
    subject: `CN=${subject},O=notme`,
    issuer: `CN=signet-authority,O=notme`,
    notBefore: now,
    notAfter: expires,
    signingAlgorithm: ED25519,
    publicKey: userPublicKey,
    signingKey: signingKey,
    serialNumber: serial,
    extensions: [
      BASIC_CONSTRAINTS_LEAF,
      ghaKeyUsage,
      CLIENT_AUTH_EKU,
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

// ── Cert pair minting (008) ─────────────────────────────────────────────────

// Encode ASN.1 SEQUENCE OF UTF8String for scope list
function derScopeSequence(scopes: string[]): Uint8Array {
  const encoded = scopes.map(s => derUtf8String(s));
  const totalLen = encoded.reduce((sum, e) => sum + e.length, 0);
  // SEQUENCE tag = 0x30
  const header = totalLen < 128
    ? new Uint8Array([0x30, totalLen])
    : new Uint8Array([0x30, 0x81, totalLen]);
  const buf = new Uint8Array(header.length + totalLen);
  buf.set(header, 0);
  let offset = header.length;
  for (const e of encoded) {
    buf.set(e, offset);
    offset += e.length;
  }
  return buf;
}

// Encode a 4-byte big-endian integer as ASN.1 INTEGER
function derInteger(n: number): Uint8Array {
  const buf = new Uint8Array([0x02, 0x04, (n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
  return buf;
}

export async function mintBridgeCertPair(
  subject: string,
  identity: string,
  mtlsPublicKeyPem: string,
  signingPublicKeyPem: string,
  signingKey: CryptoKey,
  opts: {
    scopes: string[];
    epoch: number;
    authMethod: string;
    ttlMs?: number;
  },
): Promise<BridgeCertPairResult> {
  const ttlMs = opts.ttlMs ?? 5 * 60 * 1000;
  const now = new Date();
  const expires = new Date(now.getTime() + ttlMs);

  // Import both public keys
  const mtlsPubKey = await importPublicKey(mtlsPublicKeyPem);
  const signingPubKey = await importPublicKey(signingPublicKeyPem);

  // Compute binding: SHA-256(P-256 SPKI DER || Ed25519 SPKI DER)
  const mtlsSpki = (await crypto.subtle.exportKey("spki", mtlsPubKey)) as ArrayBuffer;
  const signingSpki = (await crypto.subtle.exportKey("spki", signingPubKey)) as ArrayBuffer;
  const bindingInput = new Uint8Array(mtlsSpki.byteLength + signingSpki.byteLength);
  bindingInput.set(new Uint8Array(mtlsSpki), 0);
  bindingInput.set(new Uint8Array(signingSpki), mtlsSpki.byteLength);
  const bindingHash = await crypto.subtle.digest("SHA-256", bindingInput);
  const bindingHex = Array.from(new Uint8Array(bindingHash))
    .map(b => b.toString(16).padStart(2, "0")).join("");

  // Shared extensions for both certs
  const sharedExtensions = [
    new Extension(OID_SUBJECT, false, derUtf8String(subject)),
    new Extension(OID_ISSUANCE_TIME, false, derUtf8String(now.toISOString())),
    new Extension(OID_SCOPES, false, derScopeSequence(opts.scopes)),
    new Extension(OID_EPOCH, false, derInteger(opts.epoch)),
    new Extension(OID_AUTH_METHOD, false, derUtf8String(opts.authMethod)),
    new Extension(OID_PEER_BINDING, false, new Uint8Array(bindingHash)),
  ];

  // SAN URI extension (WIMSE identity)
  // SubjectAltName with URI is handled by @peculiar/x509 via the extensions param
  // We encode it as a custom extension with the URI as a DER-encoded IA5String
  const sanUri = new TextEncoder().encode(identity);
  const sanDer = new Uint8Array(2 + 2 + sanUri.length); // SEQUENCE { [6] URI }
  sanDer[0] = 0x30; // SEQUENCE
  sanDer[1] = 2 + sanUri.length;
  sanDer[2] = 0x86; // context [6] = URI (implicit IA5String)
  sanDer[3] = sanUri.length;
  sanDer.set(sanUri, 4);
  const sanExtension = new Extension("2.5.29.17", true, sanDer); // SubjectAltName OID, critical

  const serial1 = crypto.getRandomValues(new Uint8Array(16));
  // Ensure positive (RFC 5280: serial must be positive integer)
  serial1[0] &= 0x7f;
  const serialHex1 = Array.from(serial1).map(b => b.toString(16).padStart(2, "0")).join("");

  const serial2 = crypto.getRandomValues(new Uint8Array(16));
  serial2[0] &= 0x7f;
  const serialHex2 = Array.from(serial2).map(b => b.toString(16).padStart(2, "0")).join("");

  // Mint P-256 mTLS cert
  const mtlsCert = await X509CertificateGenerator.create({
    subject: `CN=${subject},O=notme`,
    issuer: `CN=signet-authority,O=notme`,
    notBefore: now,
    notAfter: expires,
    signingAlgorithm: ED25519,
    publicKey: mtlsPubKey,
    signingKey,
    serialNumber: serialHex1,
    extensions: [
      BASIC_CONSTRAINTS_LEAF,
      MTLS_KEY_USAGE,
      CLIENT_AUTH_EKU,
      ...sharedExtensions,
      sanExtension,
    ],
  });

  // Mint Ed25519 signing cert
  const signingCert = await X509CertificateGenerator.create({
    subject: `CN=${subject},O=notme`,
    issuer: `CN=signet-authority,O=notme`,
    notBefore: now,
    notAfter: expires,
    signingAlgorithm: ED25519,
    publicKey: signingPubKey,
    signingKey,
    serialNumber: serialHex2,
    extensions: [
      BASIC_CONSTRAINTS_LEAF,
      SIGNING_KEY_USAGE,
      ...sharedExtensions,
      sanExtension,
    ],
  });

  return {
    certificates: {
      mtls: mtlsCert.toString("pem"),
      signing: signingCert.toString("pem"),
    },
    identity,
    scopes: opts.scopes,
    expires_at: Math.floor(expires.getTime() / 1000),
    subject,
    binding: bindingHex,
  };
}
