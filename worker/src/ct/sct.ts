/**
 * sct.ts — RFC 6962 precertificate poison and embedded-SCT encoding.
 *
 * Two byte formats stand between a certificate notme mints and one a
 * transparency log has recorded (notme-1b46a8, answering notme-907299):
 *
 *   1. A PRECERTIFICATE carries the poison extension and is otherwise
 *      identical to the certificate that will be issued. The log signs an SCT
 *      over it; the poison is what stops the precertificate itself being
 *      usable, because a verifier MUST reject a certificate carrying a
 *      critical extension it does not recognise.
 *   2. The final certificate replaces the poison with the SCT list, so a
 *      verifier can check inclusion without talking to the log.
 *
 * Kept as pure functions in their own file, with no DO or Worker imports, so
 * the encodings can be asserted directly against bytes a real log emitted.
 */
import { Extension } from "@peculiar/x509";

/** RFC 6962 §3.3 — the embedded SCT list. MUST NOT be critical. */
export const CT_SCT_LIST_OID = "1.3.6.1.4.1.11129.2.4.2";
/** RFC 6962 §3.1 — the precertificate poison. MUST be critical. */
export const CT_POISON_OID = "1.3.6.1.4.1.11129.2.4.3";

/** The JSON an `add-chain` / `add-pre-chain` response returns. */
export interface SctResponse {
  sct_version: number;
  /** base64, 32 bytes: SHA-256 of the log's public key. */
  id: string;
  /** milliseconds since the epoch. */
  timestamp: number;
  /** base64 CtExtensions — for static-ct-api, the leaf_index. */
  extensions: string;
  /** base64 of the WHOLE digitally-signed struct, alg bytes included. */
  signature: string;
}

const fromB64 = (s: string): Uint8Array =>
  Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

/**
 * The poison extension: OID, critical, ASN.1 NULL.
 *
 * `05 00` is written literally rather than built, because it is a constant of
 * the format and a builder would be more code than the thing it builds.
 */
export function ctPoisonExtension(): Extension {
  return new Extension(CT_POISON_OID, true, new Uint8Array([0x05, 0x00]));
}

/**
 * Serialise one SCT into the TLS wire form RFC 6962 §3.2 defines:
 *
 *   Version(1) ‖ LogID(32) ‖ timestamp(8, uint64 BE)
 *     ‖ CtExtensions(uint16 length ‖ bytes)
 *     ‖ digitally-signed struct
 *
 * The response's `signature` field is ALREADY the digitally-signed struct —
 * hash algorithm, signature algorithm, uint16 length, signature — so it is
 * appended whole. Re-encoding a length in front of it produces bytes that
 * embed cleanly and verify nowhere.
 */
export function serialiseSct(sct: SctResponse): Uint8Array {
  if (sct.sct_version !== 0) {
    throw new Error(
      `unsupported SCT version ${sct.sct_version}: only v1 (0) has this layout`,
    );
  }
  const id = fromB64(sct.id);
  if (id.length !== 32) {
    throw new Error(`log id must be 32 bytes, got ${id.length}`);
  }
  const extensions = fromB64(sct.extensions);
  if (extensions.length > 0xffff) {
    throw new Error(`CtExtensions too long for a uint16 length: ${extensions.length}`);
  }
  const signature = fromB64(sct.signature);

  const out = new Uint8Array(1 + 32 + 8 + 2 + extensions.length + signature.length);
  let at = 0;
  out[at++] = 0; // v1
  out.set(id, at);
  at += 32;
  // uint64 big-endian. BigInt because a millisecond timestamp is 41 bits now
  // and shifting past 32 in JS numbers is a silent wrap.
  let ts = BigInt(sct.timestamp);
  for (let i = 7; i >= 0; i--) {
    out[at + i] = Number(ts & 0xffn);
    ts >>= 8n;
  }
  at += 8;
  out[at++] = (extensions.length >> 8) & 0xff;
  out[at++] = extensions.length & 0xff;
  out.set(extensions, at);
  at += extensions.length;
  out.set(signature, at);
  return out;
}

/** DER length octets for `n` — short form under 128, else long form. */
function derLength(n: number): number[] {
  if (n < 0x80) return [n];
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>= 8;
  }
  return [0x80 | bytes.length, ...bytes];
}

/**
 * The embedded SCT list extension.
 *
 * DOUBLE-WRAPPED, deliberately. RFC 6962 §3.3 declares
 * `SignedCertificateTimestampList ::= OCTET STRING`, so the extension's VALUE
 * is an OCTET STRING whose contents are the TLS list — and X.509 then wraps
 * that value in extnValue, which is also an OCTET STRING. Emitting a single
 * wrap is the bug to watch for: it decodes as a truncated list rather than
 * failing, so the certificate looks logged and satisfies nothing.
 */
export function sctListExtension(scts: Uint8Array[]): Extension {
  if (scts.length === 0) {
    throw new Error(
      "refusing to build an SCT list with no SCTs — an empty list encodes " +
        "cleanly and asserts that nothing was logged",
    );
  }
  const body: number[] = [];
  for (const sct of scts) {
    if (sct.length > 0xffff) {
      throw new Error(`SCT too long for a uint16 length: ${sct.length}`);
    }
    body.push((sct.length >> 8) & 0xff, sct.length & 0xff, ...sct);
  }
  if (body.length > 0xffff) {
    throw new Error(`SCT list too long for a uint16 length: ${body.length}`);
  }
  const list = [(body.length >> 8) & 0xff, body.length & 0xff, ...body];
  const value = new Uint8Array([0x04, ...derLength(list.length), ...list]);
  return new Extension(CT_SCT_LIST_OID, false, value);
}
