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

// Issuing-CA tier (ADR-008 §BasicConstraints "orchestrator bridge", named the
// Issuing CA per signet-9dfb44): CA=true so the holder can sign task certs,
// pathLenConstraint=0 so nothing it issues can issue in turn. The pathlen is
// the rank function ADR-019 D4 requires — depth terminates because RFC 5280
// §6.1.4(l)–(m) decrements it, not because scopes narrow (they may stay
// equal). Critical per RFC 5280 §4.2.1.9.
const BASIC_CONSTRAINTS_ISSUING = new BasicConstraintsExtension(true, 0, true);

// keyCertSign ONLY, per ADR-008's tier table. Not digitalSignature: this key
// signs CERTIFICATES, and a tier that can also sign arbitrary payloads
// collapses the task/machine distinction the chain exists to draw.
const ISSUING_KEY_USAGE = new KeyUsagesExtension(KeyUsageFlags.keyCertSign, true);

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
export const OID_PEER_BINDING = `${OID_PEN}.1.6`; // SHA-256(P-256 SPKI || Ed25519 SPKI)
export const OID_TASK_SCOPE = `${OID_PEN}.1.7`; // SEQUENCE { UTF8String task, OCTET STRING goalHash }
export const OID_PRINCIPAL_KIND = `${OID_PEN}.1.8`; // UTF8String: human|agent|workload|organization

/**
 * What the certificate's subject IS — a different axis from HOW it was
 * authenticated or attested (ADR-019 D2). An earlier identity shape put the
 * ceremony in the URI, which conflated the two and made the identity vary
 * with the door the principal came through.
 */
export type PrincipalKind = "human" | "agent" | "workload" | "organization";

/**
 * The WIMSE identity: `wimse://<trust-domain>/principal/<stable-id>`.
 *
 * THE ONE BUILDER, because this string was previously assembled inline at
 * four call sites with two different shapes — `/<authMethod>/<id>` for
 * sessions and `/gha/<owner>/<repo>` for CI — which is how one principal
 * ended up with several identities (notme-77438b).
 *
 * The URI carries the SUBJECT and nothing else. Kind, authentication and
 * attestation are signed extensions, so a verifier reads a claim rather than
 * splitting a string whose segment meanings differ by route. `gen/go/verify`
 * already documents the URI as display-and-routing only — this makes that
 * documented contract true rather than merely asserted.
 *
 * The id is percent-encoded per segment: a GHA subject is
 * `repo:owner/name:ref:refs/heads/main`, whose slashes would otherwise
 * invent path segments and break the D5 prefix-confinement rule that
 * compares segments raw.
 */
export function principalIdentity(
  trustDomain: string,
  principalId: string,
): string {
  if (!principalId) {
    throw new Error("principal id required — refusing to mint a headless identity");
  }
  return `wimse://${trustDomain}/principal/${encodeURIComponent(principalId)}`;
}

/** Read `principal_kind` back, or null when the cert predates the claim. */
export function certPrincipalKind(cert: {
  getExtension(oid: string): { value: ArrayBuffer } | null;
}): PrincipalKind | null {
  const ext = cert.getExtension(OID_PRINCIPAL_KIND);
  if (!ext) return null;
  const der = new Uint8Array(ext.value);
  if (der.length < 2 || der[0] !== 0x0c) return null;
  const value = new TextDecoder().decode(der.subarray(2, 2 + der[1]!));
  return value === "human" || value === "agent" || value === "workload" ||
    value === "organization"
    ? value
    : null;
}

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
      new Extension(OID_PRINCIPAL_KIND, false, derUtf8String("workload")),
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
    /**
     * The signer's SUBJECT name, when the signer is not the root. RFC 5280
     * §6.1.3 chains by NAME as well as by key: a cert claiming
     * CN=signet-authority while signed by a tier is rejected by every stock
     * validator, and by verifyCertChain. mintTaskCertPair passes the tier's.
     */
    issuerName?: string;
    /** Extra extensions (e.g. the task scope) — appended to both certs. */
    extraExtensions?: Extension[];
    /** What the subject IS (ADR-019 D2). Defaults to the human case. */
    principalKind?: PrincipalKind;
  },
): Promise<BridgeCertPairResult> {
  const ttlMs = opts.ttlMs ?? 5 * 60 * 1000;
  const now = new Date();
  const expires = new Date(now.getTime() + ttlMs);
  const issuerName = opts.issuerName ?? "CN=signet-authority,O=notme";

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
    new Extension(
      OID_PRINCIPAL_KIND,
      false,
      derUtf8String(opts.principalKind ?? "human"),
    ),
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
    issuer: issuerName,
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
      ...(opts.extraExtensions ?? []),
    ],
  });

  // Mint Ed25519 signing cert
  const signingCert = await X509CertificateGenerator.create({
    subject: `CN=${subject},O=notme`,
    issuer: issuerName,
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
      ...(opts.extraExtensions ?? []),
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

/** What `mintIssuingCaCert` returns — one certificate, one tier. */
export interface IssuingCaCertResult {
  certificate: string;
  identity: string;
  scopes: string[];
  expires_at: number;
  subject: string;
}

/**
 * Mint the MIDDLE tier: an Issuing CA certificate (`CA=true, pathlen=0`).
 *
 * This is hop 1 of ADR-019's chain — the bridge delegates the human to the
 * MACHINE, and the machine may then sign task certs itself, offline, without
 * asking this authority per task. pathlen=0 is what makes every task cert
 * terminal: an X.509 validator enforces the depth cap for us instead of
 * trusting notme to refuse (delegation-depth.do.test.ts pins both halves).
 *
 * Ed25519 only. The chain is Ed25519 end-to-end — root signs this tier, this
 * tier signs task certs — and accepting a P-256 subject key here would fork
 * the chain's algorithm story for no caller that exists.
 *
 * Scopes carried here BOUND what task certs below may claim: a verifier
 * applying the chain rule (`scopes ⊆ parent.scopes`, auth/scope-chain.ts)
 * reads this cert as the parent. The route narrows them from the requesting
 * session before they reach this function.
 */
export async function mintIssuingCaCert(
  subject: string,
  identity: string,
  publicKeyPem: string,
  signingKey: CryptoKey,
  opts: {
    scopes: string[];
    epoch: number;
    authMethod: string;
    ttlMs?: number;
    /** Signer's subject name when not the root — see mintBridgeCertPair. */
    issuerName?: string;
    /** Defaults to "agent": a tier is a machine, however a human armed it. */
    principalKind?: PrincipalKind;
  },
): Promise<IssuingCaCertResult> {
  // Longer-lived than the 5-minute leaves by design (ADR-019 D4: "a
  // longer-lived machine tier"): the tier must outlive the tasks it signs
  // for, or every task cert chains to an expired parent at first use.
  const ttlMs = opts.ttlMs ?? 60 * 60 * 1000;
  const now = new Date();
  const expires = new Date(now.getTime() + ttlMs);

  const publicKey = await importPublicKey(publicKeyPem);
  if (publicKey.algorithm.name !== "Ed25519") {
    throw new Error(
      `issuing tier requires an Ed25519 key, got ${publicKey.algorithm.name}`,
    );
  }

  const sanUri = derTlv(0x86, new TextEncoder().encode(identity));
  const sanDer = derTlv(0x30, sanUri);
  const serial = crypto.getRandomValues(new Uint8Array(16));
  serial[0] &= 0x7f;

  const cert = await X509CertificateGenerator.create({
    subject: `CN=${subject},O=notme`,
    issuer: opts.issuerName ?? "CN=signet-authority,O=notme",
    notBefore: now,
    notAfter: expires,
    signingAlgorithm: ED25519,
    publicKey,
    signingKey,
    serialNumber: Array.from(serial)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(""),
    extensions: [
      BASIC_CONSTRAINTS_ISSUING,
      ISSUING_KEY_USAGE,
      new Extension(OID_SUBJECT, false, derUtf8String(subject)),
      new Extension(OID_ISSUANCE_TIME, false, derUtf8String(now.toISOString())),
      new Extension(OID_SCOPES, false, derScopeSequence(opts.scopes)),
      new Extension(OID_EPOCH, false, derInteger(opts.epoch)),
      new Extension(OID_AUTH_METHOD, false, derUtf8String(opts.authMethod)),
      new Extension(
        OID_PRINCIPAL_KIND,
        false,
        derUtf8String(opts.principalKind ?? "agent"),
      ),
      new Extension("2.5.29.17", true, sanDer),
    ],
  });

  return {
    certificate: cert.toString("pem"),
    identity,
    scopes: opts.scopes,
    expires_at: Math.floor(expires.getTime() / 1000),
    subject,
  };
}

// ── Hop 2: the machine mints task credentials (ADR-019 D3/D4/D5) ────────────

const GOAL_HASH_RE = /^[0-9a-f]{64}$/;

function derOctetString(bytes: Uint8Array): Uint8Array {
  return derTlv(0x04, bytes);
}

/**
 * Encode the task scope: SEQUENCE { UTF8String task, OCTET STRING goalHash }.
 * This is what makes the credential TASK-scoped rather than merely
 * time-bound (ADR-019 D3): `expires_at` stops it outliving the work;
 * `goal_hash` says which work.
 */
function derTaskScope(task: string, goalHash: string): Uint8Array {
  const hash = new Uint8Array(goalHash.match(/../g)!.map((h) => parseInt(h, 16)));
  const body = new Uint8Array([...derUtf8String(task), ...derOctetString(hash)]);
  return derTlv(0x30, body);
}

/** Read the task scope back — null when absent, never a partial. */
export function certTaskScope(cert: {
  getExtension(oid: string): { value: ArrayBuffer } | null;
}): { task: string; goalHash: string } | null {
  const ext = cert.getExtension(OID_TASK_SCOPE);
  if (!ext) return null;
  const der = new Uint8Array(ext.value);
  // SEQUENCE
  if (der[0] !== 0x30) return null;
  let at = 2;
  if (der[1]! & 0x80) at = 2 + (der[1]! & 0x7f);
  // UTF8String
  if (der[at] !== 0x0c) return null;
  let len = der[at + 1]!;
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + der[at + 2 + i]!;
    hdr = 2 + n;
  }
  const task = new TextDecoder().decode(der.subarray(at + hdr, at + hdr + len));
  at = at + hdr + len;
  // OCTET STRING, exactly 32 bytes
  if (der[at] !== 0x04 || der[at + 1] !== 32 || der.length < at + 34) return null;
  const goalHash = Array.from(der.subarray(at + 2, at + 34))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return { task, goalHash };
}

/**
 * Mint a TASK credential pair, signed by an Issuing CA tier — offline, no
 * round trip to the authority. This is hop 2 of the chain, and the reason
 * the tier exists at all (ADR-019 D4: "a machine that mints locally").
 *
 * What the producer enforces, so a verifier is not the only line:
 *
 *   NAMESPACE  identity = tier.identity + "/" + task — D5 confinement by
 *              construction; a task id that is empty, contains a separator,
 *              or is a dot-segment is refused before it can escape
 *   AUTHORITY  scopes ⊆ tier scopes, via narrowScopes' checked postcondition
 *   DEPTH      the pair is CA=false (BASIC_CONSTRAINTS_LEAF): tasks are
 *              terminal, and the tier's pathlen=0 makes stock validators
 *              agree
 *   LIFETIME   never past the tier's own notAfter — a task cert chaining to
 *              an expired parent fails at first use
 *   POSSESSION the private key must match the tier certificate's public key;
 *              the producer refuses to sign with a key that is not the tier's
 *
 * Epoch is the caller's to supply because the machine is offline: it stamps
 * the epoch it enrolled under, and a rotation since then is caught by the
 * verifier (every tier checks the epoch), which is the intended blast
 * radius.
 */
export async function mintTaskCertPair(
  tierCertPem: string,
  tierPrivateKey: CryptoKey,
  mtlsPublicKeyPem: string,
  signingPublicKeyPem: string,
  opts: {
    task: string;
    goalHash: string;
    scopes: string[];
    epoch: number;
    ttlMs?: number;
  },
): Promise<BridgeCertPairResult> {
  const { X509Certificate, SubjectAlternativeNameExtension } = await import("@peculiar/x509");
  const { narrowScopes, escalatedScopes } = await import("./auth/scope-chain");
  const tier = new X509Certificate(tierCertPem);

  // Possession: the private key must be the tier's. Sign a probe and verify
  // against the cert's public key — WebCrypto has no "same key" oracle.
  const probe = new TextEncoder().encode("notme task-credential possession probe");
  const sig = await crypto.subtle.sign(ED25519, tierPrivateKey, probe);
  const tierPublic = await tier.publicKey.export();
  if (!(await crypto.subtle.verify(ED25519, tierPublic, sig, probe))) {
    throw new Error("private key does not match the tier certificate");
  }

  // Task id: one segment, non-empty, no separator, no dot-segments. Encoded
  // per segment so an odd character cannot become structure.
  if (opts.task.length === 0 || opts.task.includes("/") || opts.task === "." || opts.task === "..") {
    throw new Error(`task id must be one non-empty path segment, got ${JSON.stringify(opts.task)}`);
  }
  if (!GOAL_HASH_RE.test(opts.goalHash)) {
    throw new Error("goal hash must be a SHA-256 hex digest (64 lowercase hex chars)");
  }

  const san = tier.getExtension(SubjectAlternativeNameExtension);
  const tierIdentity = san?.names.items.find((n) => n.type === "url")?.value;
  if (!tierIdentity) throw new Error("tier certificate carries no identity URI");
  const identity = `${tierIdentity}/${encodeURIComponent(opts.task)}`;

  const tierScopes = readScopes(tier);
  if (tierScopes === null) throw new Error("tier certificate carries no scopes");
  const requested = [...new Set(opts.scopes)];
  const scopes = narrowScopes(tierScopes, requested);
  if (scopes.length !== requested.length) {
    throw new Error(
      `scope escalation: ${escalatedScopes(tierScopes, requested).join(", ")} not held by the tier`,
    );
  }

  // Lifetime: never past the tier's own expiry.
  const requestedTtl = opts.ttlMs ?? 5 * 60 * 1000;
  const untilTierExpiry = tier.notAfter.getTime() - Date.now();
  const ttlMs = Math.max(0, Math.min(requestedTtl, untilTierExpiry));

  const authMethodExt = tier.getExtension(OID_AUTH_METHOD);
  const authMethod = authMethodExt
    ? new TextDecoder().decode(new Uint8Array(authMethodExt.value).subarray(2))
    : "task";

  return mintBridgeCertPair(
    opts.task,
    identity,
    mtlsPublicKeyPem,
    signingPublicKeyPem,
    tierPrivateKey,
    {
      scopes,
      epoch: opts.epoch,
      authMethod,
      ttlMs,
      issuerName: tier.subject,
      // A task is exercised by the same agent the tier names; the task scope
      // bounds WHAT it may do, it does not make the task a separate kind.
      principalKind: "agent",
      extraExtensions: [new Extension(OID_TASK_SCOPE, false, derTaskScope(opts.task, opts.goalHash))],
    },
  );
}

/** Scopes at OID_SCOPES — a local reader so this module has no import cycle with verify-chain. */
function readScopes(cert: { getExtension(oid: string): { value: ArrayBuffer } | null }): string[] | null {
  const ext = cert.getExtension(OID_SCOPES);
  if (!ext) return null;
  const der = new Uint8Array(ext.value);
  if (der[0] !== 0x30) return null;
  let at = 2;
  if (der[1]! & 0x80) at = 2 + (der[1]! & 0x7f);
  const out: string[] = [];
  while (at < der.length) {
    if (der[at] !== 0x0c) return null;
    let len = der[at + 1]!;
    let hdr = 2;
    if (len & 0x80) {
      const n = len & 0x7f;
      len = 0;
      for (let i = 0; i < n; i++) len = len * 256 + der[at + 2 + i]!;
      hdr = 2 + n;
    }
    out.push(new TextDecoder().decode(der.subarray(at + hdr, at + hdr + len)));
    at += hdr + len;
  }
  return out;
}
