/**
 * verify-sct.ts — check that an SCT came from THE log notme pins, and that it
 * signs the entry notme submitted (notme-1b46a8, final review I1).
 *
 * An SCT-shaped 200 proves nothing on its own: a misconfigured CT_LOG_PATH, a
 * wrong shard, or a catch-all Worker behind the binding all answer with
 * well-formed JSON. So a returned SCT is accepted only when
 *
 *   - its `id` equals the pinned log id (CT_LOG_ID), and the pinned id is
 *     SHA-256 of the pinned key (CT_LOG_KEY, base64 SPKI DER of a P-256 key);
 *   - its ECDSA-P256-SHA256 signature verifies, under that key, over the
 *     RFC 6962 §3.2 digitally-signed struct for the entry submitted:
 *       precert_entry — the precert's TBSCertificate with the poison removed,
 *                       plus issuer_key_hash = SHA-256(issuer SPKI);
 *       x509_entry    — the whole final certificate.
 *
 * Pure: no DO or Worker imports, local WebCrypto only, never throws from
 * `verifySct`. Verification is a few hundred microseconds of local crypto, so
 * it does not widen the mint's time bound.
 */
import { CT_POISON_OID, type SctResponse } from "./sct";

// ── Minimal DER, enough for the §3.2 reconstruction ────────────────────────

interface Tlv {
  tag: number;
  /** first byte of the TLV */
  start: number;
  /** first byte of the content */
  body: number;
  /** one past the last content byte */
  end: number;
}

function tlv(d: Uint8Array, at: number): Tlv {
  if (at + 2 > d.length) throw new Error("DER: truncated header");
  const tag = d[at]!;
  let len = d[at + 1]!;
  let body = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 3 || at + 2 + n > d.length) throw new Error("DER: bad length");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + d[at + 2 + i]!;
    body = at + 2 + n;
  }
  if (body + len > d.length) throw new Error("DER: truncated content");
  return { tag, start: at, body, end: body + len };
}

function children(d: Uint8Array, t: Tlv): Tlv[] {
  const out: Tlv[] = [];
  for (let at = t.body; at < t.end; ) {
    const c = tlv(d, at);
    out.push(c);
    at = c.end;
  }
  return out;
}

function encode(tag: number, content: Uint8Array): Uint8Array {
  const n = content.length;
  const len =
    n < 0x80
      ? [n]
      : n < 0x100
        ? [0x81, n]
        : n < 0x10000
          ? [0x82, n >> 8, n & 0xff]
          : [0x83, n >> 16, (n >> 8) & 0xff, n & 0xff];
  const out = new Uint8Array(1 + len.length + n);
  out[0] = tag;
  out.set(len, 1);
  out.set(content, 1 + len.length);
  return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function oidString(content: Uint8Array): string {
  const arcs = [Math.floor(content[0]! / 40), content[0]! % 40];
  let v = 0;
  for (const b of content.subarray(1)) {
    v = v * 128 + (b & 0x7f);
    if (!(b & 0x80)) {
      arcs.push(v);
      v = 0;
    }
  }
  return arcs.join(".");
}

const tbsFields = (certDer: Uint8Array): Tlv[] =>
  children(certDer, children(certDer, tlv(certDer, 0))[0]!);

/**
 * The TBSCertificate of `certDer` with the one extension `drop` removed.
 * Throws unless exactly one such extension is present.
 */
export function tbsWithout(certDer: Uint8Array, drop: string): Uint8Array {
  const fields = tbsFields(certDer);
  const extsField = fields.find((f) => f.tag === 0xa3);
  if (!extsField) throw new Error("certificate has no extensions");
  const seq = children(certDer, extsField)[0]!;
  const exts = children(certDer, seq);
  const kept = exts.filter((e) => {
    const oid = children(certDer, e)[0]!;
    return oidString(certDer.subarray(oid.body, oid.end)) !== drop;
  });
  if (kept.length !== exts.length - 1) {
    throw new Error(`expected exactly one ${drop} extension`);
  }
  return encode(
    0x30,
    concat([
      ...fields.filter((f) => f.tag !== 0xa3).map((f) => certDer.subarray(f.start, f.end)),
      encode(0xa3, encode(0x30, concat(kept.map((e) => certDer.subarray(e.start, e.end))))),
    ]),
  );
}

/** The SubjectPublicKeyInfo DER of a certificate. */
export function spkiOf(certDer: Uint8Array): Uint8Array {
  const f = tbsFields(certDer);
  // [0] version is optional; SPKI follows serial, sigAlg, issuer, validity, subject.
  const s = f[f[0]!.tag === 0xa0 ? 6 : 5]!;
  return certDer.subarray(s.start, s.end);
}

/** DER ECDSA-Sig-Value → the raw r‖s (P-256) WebCrypto verifies. */
function ecdsaDerToRaw(der: Uint8Array): Uint8Array {
  const seq = tlv(der, 0);
  if (seq.tag !== 0x30 || seq.end !== der.length) throw new Error("not an ECDSA-Sig-Value");
  const parts = children(der, seq);
  if (parts.length !== 2 || parts.some((p) => p.tag !== 0x02)) {
    throw new Error("not an ECDSA-Sig-Value");
  }
  const fixed = (t: Tlv) => {
    let v = der.subarray(t.body, t.end);
    while (v.length > 32 && v[0] === 0) v = v.subarray(1);
    if (v.length > 32) throw new Error("ECDSA integer too long for P-256");
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length);
    return out;
  };
  return concat([fixed(parts[0]!), fixed(parts[1]!)]);
}

const fromB64 = (s: string): Uint8Array => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const toB64 = (b: Uint8Array): string => btoa(String.fromCharCode(...b));
const sha256 = async (b: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", b));

// ── The pinned log ──────────────────────────────────────────────────────────

/** The log notme trusts: its P-256 key and id (= SHA-256 of the key's SPKI). */
export interface LogPin {
  key: CryptoKey;
  /** base64, 32 bytes */
  id: string;
}

const B64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/**
 * Validate CT_LOG_ID / CT_LOG_KEY. Returns the pin, or a short reason the
 * configuration cannot be trusted (missing, not base64, not a P-256 SPKI, or
 * an id that is not SHA-256 of the key). Never throws.
 */
export async function parseLogPin(
  idB64: string | undefined,
  keyB64: string | undefined,
): Promise<LogPin | { error: string }> {
  if (!idB64) return { error: "CT_LOG_ID missing" };
  if (!keyB64) return { error: "CT_LOG_KEY missing" };
  if (!B64_RE.test(idB64) || fromB64(idB64).length !== 32) {
    return { error: "CT_LOG_ID is not base64 of 32 bytes" };
  }
  if (!B64_RE.test(keyB64)) return { error: "CT_LOG_KEY is not base64" };
  const spki = fromB64(keyB64);
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey(
      "spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"],
    );
  } catch {
    return { error: "CT_LOG_KEY is not a P-256 SPKI" };
  }
  if (toB64(await sha256(spki)) !== idB64) {
    return { error: "CT_LOG_ID is not SHA-256(CT_LOG_KEY)" };
  }
  return { key, id: idB64 };
}

// ── The SCT ─────────────────────────────────────────────────────────────────

/** What the log was asked to record. */
export type SctEntry =
  /** `tbs`: the precert's TBSCertificate with the poison removed (precertTbs). */
  | { kind: "precert"; tbs: Uint8Array; issuerSpki: Uint8Array }
  | { kind: "x509"; certDer: Uint8Array };

/** RFC 6962 §3.2: the TBSCertificate a precert_entry signs. Throws on a cert without the poison. */
export function precertTbs(precertDer: Uint8Array): Uint8Array {
  return tbsWithout(precertDer, CT_POISON_OID);
}

/**
 * RFC 6962 §3.2: the bytes the log signs for `entry` at `timestamp` with
 * `extensions` —
 *   version(0) ‖ signature_type(certificate_timestamp = 0) ‖ uint64 timestamp
 *   ‖ uint16 entry_type ‖ signed_entry ‖ uint16-length extensions
 * where signed_entry is uint24 ASN.1Cert for x509_entry (0), and
 * issuer_key_hash(32) ‖ uint24 TBSCertificate for precert_entry (1).
 */
export async function signedSctInput(
  entry: SctEntry,
  timestamp: number,
  extensions: Uint8Array,
): Promise<Uint8Array> {
  const ts = new Uint8Array(8);
  let t = BigInt(timestamp);
  for (let i = 7; i >= 0; i--) {
    ts[i] = Number(t & 0xffn);
    t >>= 8n;
  }
  const u24 = (n: number) => new Uint8Array([n >> 16, (n >> 8) & 0xff, n & 0xff]);
  let signedEntry: Uint8Array[];
  if (entry.kind === "precert") {
    signedEntry = [
      new Uint8Array([0, 1]),
      await sha256(entry.issuerSpki),
      u24(entry.tbs.length),
      entry.tbs,
    ];
  } else {
    signedEntry = [new Uint8Array([0, 0]), u24(entry.certDer.length), entry.certDer];
  }
  return concat([
    new Uint8Array([0, 0]),
    ts,
    ...signedEntry,
    new Uint8Array([extensions.length >> 8, extensions.length & 0xff]),
    extensions,
  ]);
}

export type SctVerdict = "ok" | "wrong log" | "bad signature";

/**
 * Accept `sct` only if it is from `pin`'s log and its signature verifies over
 * `entry`. Never throws: anything unparseable is "bad signature".
 */
export async function verifySct(
  sct: SctResponse,
  entry: SctEntry,
  pin: LogPin,
): Promise<SctVerdict> {
  if (sct.id !== pin.id) return "wrong log";
  try {
    // DigitallySigned: hash alg(1) ‖ sig alg(1) ‖ uint16 length ‖ signature.
    const ds = fromB64(sct.signature);
    if (ds.length < 4 || ds[0] !== 4 || ds[1] !== 3) return "bad signature"; // sha256 / ecdsa
    const len = (ds[2]! << 8) | ds[3]!;
    if (len !== ds.length - 4) return "bad signature";
    const raw = ecdsaDerToRaw(ds.subarray(4));
    const signed = await signedSctInput(entry, sct.timestamp, fromB64(sct.extensions));
    const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pin.key, raw, signed);
    return ok ? "ok" : "bad signature";
  } catch {
    return "bad signature";
  }
}
