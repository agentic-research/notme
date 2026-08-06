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
const BASIC_CONSTRAINTS_LEAF = new BasicConstraintsExtension(
  false,
  undefined,
  true,
);

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

// Custom-extension OID arc.
//
// 1.3.6.1.4.1.99999 is the IANA "example/private-experiment" arc used while a
// real Private Enterprise Number (PEN) is pending — see notme-229dc3. When the
// PEN arrives, change OID_PEN below; all extension OIDs derive from it, so the
// rest of the file (and the Go authority's cert format) update automatically.
//
// IANA PEN application: https://pen.iana.org/pen/PenApplication.page (free,
// few business days). Until then, ANY third-party verifier that pins our OID
// arc will be pinning the placeholder.
const OID_PEN = "1.3.6.1.4.1.99999"; // TODO(notme-229dc3): replace with assigned PEN
// Exported because verification has to read back exactly what minting wrote.
// A second copy of these strings in the verifier would let the two drift, and
// the failure mode of that drift is silent: `getExtension` returns undefined
// for an unknown OID, so a mismatched verifier reads "no identity in this
// cert" rather than erroring — which is how a derived-identity check
// degrades back into a trust-the-caller one (notme-6ad276).
export const OID_SUBJECT = `${OID_PEN}.1.1`; // Subject identity
const OID_ISSUANCE_TIME = `${OID_PEN}.1.2`; // Issuance time (RFC3339)
export const OID_SCOPES = `${OID_PEN}.1.3`; // Granted scopes
export const OID_EPOCH = `${OID_PEN}.1.4`; // CA epoch at issuance
const OID_AUTH_METHOD = `${OID_PEN}.1.5`; // Authentication method
const OID_PEER_BINDING = `${OID_PEN}.1.6`; // SHA-256(P-256 SPKI || Ed25519 SPKI)

// ASN.1 definite-length encoding: short form (a single byte) up to 0x7f, long
// form (0x81 nn, 0x82 nn nn, …) above it.
//
// The high bit is the discriminator, so a length of 0x80 or more CANNOT be
// written as one byte — a parser reads that byte as "a long-form length
// follows in the next N octets" and then walks off into the value. Getting
// this wrong does not produce a rejected cert; it produces a SIGNED one whose
// bytes are malformed, which is the worse failure: it looks issued, it leaves
// here, and it breaks later in a parser the operator does not control
// (notme-193368).
function derLength(n: number): Uint8Array {
  if (n < 0x80) return new Uint8Array([n]);
  const bytes: number[] = [];
  for (let v = n; v > 0; v >>>= 8) bytes.unshift(v & 0xff);
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

// Wrap a value in its tag and length. Every hand-rolled structure below goes
// through here so none of them can reintroduce a single-byte length ceiling.
function derTlv(tag: number, value: Uint8Array): Uint8Array {
  const len = derLength(value.length);
  const buf = new Uint8Array(1 + len.length + value.length);
  buf[0] = tag;
  buf.set(len, 1);
  buf.set(value, 1 + len.length);
  return buf;
}

// Encode a string as ASN.1 UTF8String DER (tag 0x0C + length + value)
function derUtf8String(s: string): Uint8Array {
  return derTlv(0x0c, new TextEncoder().encode(s));
}

async function importMasterKey(pem: string): Promise<CryptoKey> {
  const b64 = pem
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replace(/\s/g, "");
  const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey("pkcs8", der, ED25519, false, ["sign"]);
}

/**
 * Ed25519 AlgorithmIdentifier as it appears in an SPKI: SEQUENCE { OID
 * 1.3.101.112 } — `30 05 06 03 2B 65 70` (RFC 8410 §3).
 */
const ED25519_SPKI_ALG_ID = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

function isEd25519Spki(der: Uint8Array): boolean {
  // The AlgorithmIdentifier sits near the front, after the outer SEQUENCE
  // header. Scanning a short prefix is enough and avoids a full DER parser.
  const limit = Math.min(der.length - ED25519_SPKI_ALG_ID.length, 16);
  outer: for (let i = 0; i <= limit; i++) {
    for (let j = 0; j < ED25519_SPKI_ALG_ID.length; j++) {
      if (der[i + j] !== ED25519_SPKI_ALG_ID[j]) continue outer;
    }
    return true;
  }
  return false;
}

/**
 * Import an SPKI PEM public key, dispatching on the key's OWN algorithm OID.
 *
 * WAS "try Ed25519, fall back to ECDSA P-256 on throw". That is broken on
 * workerd: an Ed25519 import of a **P-256** SPKI SUCCEEDS rather than
 * throwing, so the fallback never ran and every key came back as
 * `{name:"Ed25519"}`. The SPKI bytes round-trip intact, so the certificate
 * minted from it is fine — but the returned CryptoKey is unusable for the
 * thing callers actually do with it:
 *
 *     crypto.subtle.verify({name:"ECDSA", hash:"SHA-256"}, key, sig, data)
 *     → throws: Requested algorithm "ECDSA" does not match this CryptoKey's
 *       algorithm "Ed25519".
 *
 * That is the P-256 proof-of-possession check on every cert-issuing path —
 * /cert/gha, /cert, /cert/passkey. Verified against real workerd in the
 * vitest-pool-workers suite; whether Cloudflare's production build is equally
 * permissive on the Ed25519 import is NOT established here, so treat the
 * blast radius as "at minimum local and CI" until checked against prod.
 *
 * Nothing caught it because no test imported a P-256 key through this
 * function — `grep -rn importPublicKey src/__tests__` was empty. The three
 * call sites all used it and all had coverage of their own; the shared
 * primitive underneath had none.
 *
 * Now dispatches on the algorithm OID, so the result is determined by what
 * the key IS rather than by which import happens to reject first.
 */
export async function importPublicKey(pem: string): Promise<CryptoKey> {
  const b64 = pem
    .replace("-----BEGIN PUBLIC KEY-----", "")
    .replace("-----END PUBLIC KEY-----", "")
    .replace(/\s/g, "");
  const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

  return crypto.subtle.importKey(
    "spki",
    der,
    isEd25519Spki(der) ? ED25519 : { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );
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
  const encoded = scopes.map((s) => derUtf8String(s));
  const body = new Uint8Array(encoded.reduce((sum, e) => sum + e.length, 0));
  let offset = 0;
  for (const e of encoded) {
    body.set(e, offset);
    offset += e.length;
  }
  return derTlv(0x30, body); // SEQUENCE
}

// Encode a 4-byte big-endian integer as ASN.1 INTEGER
function derInteger(n: number): Uint8Array {
  const buf = new Uint8Array([
    0x02,
    0x04,
    (n >> 24) & 0xff,
    (n >> 16) & 0xff,
    (n >> 8) & 0xff,
    n & 0xff,
  ]);
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
  const mtlsSpki = (await crypto.subtle.exportKey(
    "spki",
    mtlsPubKey,
  )) as ArrayBuffer;
  const signingSpki = (await crypto.subtle.exportKey(
    "spki",
    signingPubKey,
  )) as ArrayBuffer;
  const bindingInput = new Uint8Array(
    mtlsSpki.byteLength + signingSpki.byteLength,
  );
  bindingInput.set(new Uint8Array(mtlsSpki), 0);
  bindingInput.set(new Uint8Array(signingSpki), mtlsSpki.byteLength);
  const bindingHash = await crypto.subtle.digest("SHA-256", bindingInput);
  const bindingHex = Array.from(new Uint8Array(bindingHash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

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
  //
  // The identity is caller-influenced and unbounded: notme-ebc9af made its
  // method segment the session's auth method, and both mint paths
  // percent-encode it, so an issuer-qualified method spends ~3 bytes per
  // delimiter. "oidc:https://token.actions.githubusercontent.com" alone lands
  // near the old single-byte ceiling and a tenant-qualified enterprise issuer
  // clears it — so this length must be encoded, not assumed. Inner first: the
  // SEQUENCE's own length depends on how many bytes the [6] header took.
  const sanUri = derTlv(0x86, new TextEncoder().encode(identity)); // context [6] = URI (implicit IA5String)
  const sanDer = derTlv(0x30, sanUri); // SEQUENCE { [6] URI }
  const sanExtension = new Extension("2.5.29.17", true, sanDer); // SubjectAltName OID, critical

  const serial1 = crypto.getRandomValues(new Uint8Array(16));
  // Ensure positive (RFC 5280: serial must be positive integer)
  serial1[0] &= 0x7f;
  const serialHex1 = Array.from(serial1)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const serial2 = crypto.getRandomValues(new Uint8Array(16));
  serial2[0] &= 0x7f;
  const serialHex2 = Array.from(serial2)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

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
