/**
 * derive-credentials.ts — read a caller's principal out of its certificates
 * instead of believing what the caller says about itself (notme-6ad276).
 *
 * `AuthService.authenticate()` is reachable by any Worker holding an `AUTH`
 * service binding. It used to accept `identity`, `scopes` and `expiresAt` as
 * plain fields on a caller-supplied struct and assign them straight to the
 * session. `proxy()` then gated on `scopes.includes("bridgeCert")` and
 * audit-logged `identity` — so a bound Worker could name itself any WIMSE
 * principal and grant itself any scope, and the audit trail would agree.
 *
 * The certs in that same struct are the one part a caller cannot forge: they
 * are CA-signed, and cert-authority.ts already writes the subject and the
 * granted scopes into them as custom extensions. So the principal is recovered
 * from the cert, and the caller's opinion of who it is never enters.
 *
 * THE INVARIANT: identity and scopes are DERIVED, never RECEIVED.
 */

import { SubjectAlternativeNameExtension, X509Certificate } from "@peculiar/x509";
import { importPublicKey, OID_SCOPES, OID_SUBJECT } from "../cert-authority";

export interface DerivedCredentials {
  /**
   * WIMSE identity, read from the cert's SAN URI (2.5.29.17).
   *
   * NOT from OID_SUBJECT — that extension carries the internal PRINCIPAL name
   * (e.g. `principal-test`), while the WIMSE URI callers audit and authorize
   * against (`wimse://notme.bot/gha/org/repo`) is minted into the SAN. Reading
   * the wrong one yields a plausible non-empty string, which is the failure
   * mode that would survive review.
   */
  identity: string;
  /** Internal principal name, from the signing cert's OID_SUBJECT extension. */
  principal: string;
  /** Granted scopes, read from the signing cert's OID_SCOPES extension. */
  scopes: string[];
  /** Unix seconds, from the signing cert's notAfter. */
  expiresAt: number;
}

/**
 * Decode one ASN.1 UTF8String (tag 0x0C), returning the value and the offset
 * just past it.
 *
 * Mirrors `derUtf8String` in cert-authority.ts, including its long-form length
 * (0x81 = one length byte, 0x82 = two). Anything else is rejected rather than
 * guessed at — a length this function misparses would silently truncate an
 * identity, and a truncated identity is a different principal.
 */
function readUtf8String(buf: Uint8Array, offset: number): { value: string; next: number } {
  if (offset >= buf.length) throw new Error("malformed extension: truncated before tag");
  if (buf[offset] !== 0x0c) {
    throw new Error(
      `malformed extension: expected UTF8String (0x0c), got 0x${buf[offset].toString(16)}`,
    );
  }
  const first = buf[offset + 1];
  let len: number;
  let headerLen: number;
  if (first < 0x80) {
    len = first;
    headerLen = 2;
  } else if (first === 0x81) {
    len = buf[offset + 2];
    headerLen = 3;
  } else if (first === 0x82) {
    len = (buf[offset + 2] << 8) | buf[offset + 3];
    headerLen = 4;
  } else {
    throw new Error(`malformed extension: unsupported length form 0x${first.toString(16)}`);
  }
  const start = offset + headerLen;
  const end = start + len;
  if (end > buf.length) throw new Error("malformed extension: length exceeds buffer");
  return { value: new TextDecoder().decode(buf.subarray(start, end)), next: end };
}

/** Read the single UTF8String an extension carries. */
function extensionString(cert: X509Certificate, oid: string, what: string): string {
  const ext = cert.getExtension(oid);
  if (!ext) throw new Error(`cert carries no ${what} extension (${oid})`);
  return readUtf8String(new Uint8Array(ext.value), 0).value;
}

/**
 * Read the SEQUENCE OF UTF8String a scopes extension carries.
 *
 * An ABSENT extension yields `[]` — a cert that was never granted scopes has
 * none, which is the safe reading. An extension that is present but
 * unparseable throws instead: that is corruption, and treating corruption as
 * "no scopes" would turn a decode bug into a silent authorization decision.
 */
function extensionScopes(cert: X509Certificate): string[] {
  const ext = cert.getExtension(OID_SCOPES);
  if (!ext) return [];
  const buf = new Uint8Array(ext.value);
  if (buf.length === 0) return [];
  if (buf[0] !== 0x30) {
    throw new Error(`malformed scopes extension: expected SEQUENCE, got 0x${buf[0].toString(16)}`);
  }
  const first = buf[1];
  let offset: number;
  if (first < 0x80) offset = 2;
  else if (first === 0x81) offset = 3;
  else if (first === 0x82) offset = 4;
  else throw new Error(`malformed scopes extension: unsupported length form 0x${first.toString(16)}`);

  const scopes: string[] = [];
  while (offset < buf.length) {
    const { value, next } = readUtf8String(buf, offset);
    scopes.push(value);
    offset = next;
  }
  return scopes;
}

/**
 * Read the WIMSE identity from the cert's SAN URI.
 *
 * cert-authority.ts mints this as a CRITICAL SubjectAltName containing exactly
 * one URI. Exactly one is required here: a cert bearing several would make
 * "which identity is this?" a choice, and picking the first would let a minting
 * bug hand a caller an identity nobody reviewed.
 */
function sanIdentity(cert: X509Certificate, what: string): string {
  const san = cert.getExtension(SubjectAlternativeNameExtension);
  const uris = san?.names?.items?.filter((n) => n.type === "url").map((n) => n.value) ?? [];
  if (uris.length === 0) throw new Error(`${what} cert carries no SAN URI identity`);
  if (uris.length > 1) {
    throw new Error(`${what} cert carries ${uris.length} SAN URIs — ambiguous identity`);
  }
  return uris[0];
}

/**
 * Verify a cert against the CA and check its validity window.
 *
 * The signature check is the load-bearing one: without it any self-signed cert
 * with sane dates would pass, which is the same trust-the-caller hole one
 * level down.
 */
async function verifyAgainstCA(
  certPem: string,
  caPublicKey: CryptoKey,
  what: string,
): Promise<X509Certificate> {
  const cert = new X509Certificate(certPem);

  // `signatureOnly` matters. peculiar's verify() checks the validity window
  // as well by default, so an EXPIRED cert comes back as `false` — reported as
  // "not signed by the trusted CA", which is false and points an operator at
  // the wrong problem (a suspected CA compromise instead of a stale cert).
  // Split the two so each rejection names its own cause.
  const signatureValid = await cert.verify({ publicKey: caPublicKey, signatureOnly: true });
  if (!signatureValid) {
    throw new Error(`${what} cert signature invalid — not signed by the trusted CA`);
  }

  const now = new Date();
  if (cert.notAfter < now) throw new Error(`${what} cert expired`);
  if (cert.notBefore > now) throw new Error(`${what} cert not yet valid`);

  return cert;
}

/**
 * Recover the caller's principal from its CA-signed certs.
 *
 * @param signingCertPem  Ed25519 signing cert — the authority on identity and scopes.
 * @param mtlsCertPem     P-256 mTLS cert — must name the same principal.
 * @param caPublicKeyPem  SPKI PEM of the CA public key both certs must chain to.
 *
 * @throws if either cert fails CA verification, is outside its validity
 *         window, carries no subject, or names a different principal than
 *         its partner.
 */
export async function deriveCredentialsFromCerts(
  signingCertPem: string,
  mtlsCertPem: string,
  caPublicKeyPem: string,
): Promise<DerivedCredentials> {
  const caPublicKey = await importPublicKey(caPublicKeyPem);

  const signingCert = await verifyAgainstCA(signingCertPem, caPublicKey, "signing");
  const mtlsCert = await verifyAgainstCA(mtlsCertPem, caPublicKey, "mTLS");

  const identity = sanIdentity(signingCert, "signing");
  const mtlsIdentity = sanIdentity(mtlsCert, "mTLS");

  // Both certs are individually valid here. Pairing two principals' certs
  // would otherwise let a caller egress under one identity while signing as
  // another — the certs are used by different methods (`proxy` uses the mTLS
  // key, `sign` the signing key) and only this check ties them to one subject.
  if (identity !== mtlsIdentity) {
    throw new Error(
      `cert identity mismatch — signing cert names ${JSON.stringify(identity)} ` +
        `but mTLS cert names ${JSON.stringify(mtlsIdentity)}`,
    );
  }

  return {
    identity,
    principal: extensionString(signingCert, OID_SUBJECT, "subject identity"),
    scopes: extensionScopes(signingCert),
    // Floor, not round: rounding up would extend the session past the cert.
    expiresAt: Math.floor(signingCert.notAfter.getTime() / 1000),
  };
}
