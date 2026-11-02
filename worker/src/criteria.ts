/**
 * criteria.ts — the `.1.10` extension: which unit of identity a certificate is.
 *
 * A certificate carries `SEQUENCE OF SEQUENCE { UTF8String name, INTEGER
 * version }`. A tier may carry several; a task carries exactly one, and it must
 * be one its tier carries (task ⊆ tier, the same rule as scopes). The registry
 * below says what each criteria allows: who mints it, how long it may live,
 * which scopes it may carry, and what else it requires. `checkCriteria` is the
 * single verdict every producer and verifier calls.
 *
 * Non-critical, like every notme extension: enforcement lives in verifiers.
 *
 * notme-1a5465: `.1.9`'s goal hash is notme's "which work"; `.1.7`
 * `confinementDigest` is LLO's "what the run may touch"; neither derives from
 * the other. This module only checks `.1.7` is present, never its contents.
 */
import { OID_CRITERIA, OID_PEN, derTlv, derUtf8String, readScopes } from "./cert-authority";
import { CERT_ELIGIBLE_SCOPES } from "./auth/passkey-cert-scopes";

export interface Criteria {
  name: string;
  version: number;
}

export interface CriteriaDefinition {
  id: string; // "agent-session/1"
  mintedBy: "tier" | "authority";
  maxLifetimeS: number;
  scopeCeiling: ReadonlySet<string>;
  requiresConfinementDigest: boolean;
  grantable: boolean; // offered at /enroll this phase
}

const BRIDGE_ONLY: ReadonlySet<string> = new Set(["bridgeCert"]);

const DEFINITIONS: CriteriaDefinition[] = [
  {
    id: "agent-session/1",
    mintedBy: "tier",
    maxLifetimeS: 300,
    scopeCeiling: CERT_ELIGIBLE_SCOPES,
    requiresConfinementDigest: false,
    grantable: true,
  },
  {
    id: "llo-run/1",
    mintedBy: "tier",
    maxLifetimeS: 300,
    scopeCeiling: BRIDGE_ONLY,
    requiresConfinementDigest: true,
    grantable: false,
  },
  {
    id: "deploy/1",
    mintedBy: "authority",
    maxLifetimeS: 900,
    scopeCeiling: BRIDGE_ONLY,
    requiresConfinementDigest: false,
    grantable: false,
  },
];

/** Keyed "name/version". */
export const CRITERIA: ReadonlyMap<string, CriteriaDefinition> = new Map(DEFINITIONS.map((d) => [d.id, d]));

// Presence only. The encoding is ley-line's (cert-authority.ts table: DO NOT REUSE).
const OID_CONFINEMENT_DIGEST = `${OID_PEN}.1.7`;

const MAX_VERSION = 0x7fffffff; // a positive INTEGER of at most 4 DER bytes

export function criteriaId(c: Criteria): string {
  return `${c.name}/${c.version}`;
}

export function parseCriteriaId(id: string): Criteria | null {
  const m = /^([^/]+)\/([1-9][0-9]*)$/.exec(id);
  if (!m) return null;
  const version = Number(m[2]);
  if (!Number.isSafeInteger(version) || version > MAX_VERSION) return null;
  return { name: m[1]!, version };
}

function derPositiveInt(n: number): Uint8Array {
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v % 256);
  if (bytes[0]! & 0x80) bytes.unshift(0);
  return derTlv(0x02, new Uint8Array(bytes));
}

function validShape(c: Criteria): boolean {
  return (
    c.name.length > 0 &&
    !c.name.includes("/") &&
    Number.isInteger(c.version) &&
    c.version >= 1 &&
    c.version <= MAX_VERSION
  );
}

/** DER `SEQUENCE OF SEQUENCE { UTF8String name, INTEGER version }`. Throws on an empty list or duplicates. */
export function encodeCriteria(list: Criteria[]): Uint8Array {
  if (list.length === 0) throw new Error("criteria list must not be empty");
  const seen = new Set<string>();
  const parts: Uint8Array[] = [];
  for (const c of list) {
    if (!validShape(c)) throw new Error(`invalid criteria ${JSON.stringify(c)}`);
    const id = criteriaId(c);
    if (seen.has(id)) throw new Error(`duplicate criteria ${id}`);
    seen.add(id);
    parts.push(derTlv(0x30, new Uint8Array([...derUtf8String(c.name), ...derPositiveInt(c.version)])));
  }
  return derTlv(0x30, new Uint8Array(parts.flatMap((p) => [...p])));
}

interface Tlv {
  tag: number;
  start: number; // content start
  end: number; // content end (== next TLV start)
}

/** One definite-length TLV at `at`, bounded by `limit`. Long-form lengths accepted; indefinite refused. */
function readTlv(der: Uint8Array, at: number, limit: number): Tlv | null {
  if (at + 2 > limit) return null;
  const tag = der[at]!;
  let len = der[at + 1]!;
  let start = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || start + n > limit) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + der[start + i]!;
    start += n;
  }
  const end = start + len;
  if (end > limit) return null;
  return { tag, start, end };
}

function decodeList(der: Uint8Array): Criteria[] | null {
  const outer = readTlv(der, 0, der.length);
  if (!outer || outer.tag !== 0x30 || outer.end !== der.length) return null;
  const list: Criteria[] = [];
  const seen = new Set<string>();
  let at = outer.start;
  while (at < outer.end) {
    const el = readTlv(der, at, outer.end);
    if (!el || el.tag !== 0x30) return null;
    const nameTlv = readTlv(der, el.start, el.end);
    if (!nameTlv || nameTlv.tag !== 0x0c) return null;
    const verTlv = readTlv(der, nameTlv.end, el.end);
    if (!verTlv || verTlv.tag !== 0x02 || verTlv.end !== el.end) return null;
    let name: string;
    try {
      name = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(der.subarray(nameTlv.start, nameTlv.end));
    } catch {
      return null;
    }
    const v = der.subarray(verTlv.start, verTlv.end);
    if (v.length < 1 || v.length > 4 || v[0]! & 0x80) return null; // positive, at most 4 bytes
    if (v.length > 1 && v[0] === 0 && !(v[1]! & 0x80)) return null; // minimal encoding
    let version = 0;
    for (const b of v) version = version * 256 + b;
    const c = { name, version };
    if (!validShape(c)) return null;
    const id = criteriaId(c);
    if (seen.has(id)) return null;
    seen.add(id);
    list.push(c);
    at = el.end;
  }
  return list.length === 0 ? null : list;
}

type ExtensionSource = { getExtension(oid: string): { value: ArrayBuffer } | null };

/** Read `.1.10`. Malformed input is reported, never thrown. */
export function readCriteria(
  cert: ExtensionSource,
): { present: false } | { present: true; ok: true; list: Criteria[] } | { present: true; ok: false; reason: string } {
  const ext = cert.getExtension(OID_CRITERIA);
  if (!ext) return { present: false };
  try {
    const list = decodeList(new Uint8Array(ext.value));
    if (!list) return { present: true, ok: false, reason: "malformed criteria" };
    return { present: true, ok: true, list };
  } catch {
    return { present: true, ok: false, reason: "malformed criteria" };
  }
}

/** The subset of `@peculiar/x509`'s `X509Certificate` this module uses. */
export interface X509Like extends ExtensionSource {
  notBefore: Date;
  notAfter: Date;
}

export type CriteriaVerdict =
  | { ok: true; criteria: Criteria | null; legacy: boolean }
  | { ok: false; reason: string };

const refuse = (reason: string): CriteriaVerdict => ({ ok: false, reason });

/**
 * One verdict on a leaf and the tier above it (null when the authority itself
 * issued the leaf). Lifetime is read from the certificate's own fields, never
 * the wall clock; `at` is consulted only for the legacy cutoff.
 */
export function checkCriteria(
  tier: X509Like | null,
  leaf: X509Like,
  opts: { at?: Date; legacyCutoff?: Date } = {},
): CriteriaVerdict {
  const t = tier ? readCriteria(tier) : ({ present: false } as const);
  const l = readCriteria(leaf);
  if (t.present && !t.ok) return refuse("malformed criteria on tier");
  if (l.present && !l.ok) return refuse("malformed criteria on leaf");
  if (l.present && l.list.length > 1) return refuse("a task carries exactly one criteria");

  if (!t.present && !l.present) {
    const at = opts.at ?? new Date();
    if (opts.legacyCutoff && at > opts.legacyCutoff) return refuse("legacy certificate past the operator's cutoff");
    return { ok: true, criteria: null, legacy: true };
  }
  if (!t.present && l.present && tier !== null) return refuse("task claims criteria its tier does not carry");
  if (t.present && !l.present) return refuse("tier carries criteria; the task names none");
  if (!l.present) return refuse("tier carries criteria; the task names none"); // unreachable; narrows the type

  const criteria = l.list[0]!;
  const id = criteriaId(criteria);
  const def = CRITERIA.get(id);
  if (!def) return refuse(`unknown criteria ${id}`);
  if ((def.mintedBy === "tier" && tier === null) || (def.mintedBy === "authority" && tier !== null)) {
    return refuse(`${id} is minted by the ${def.mintedBy} only`);
  }
  if (t.present && !t.list.some((c) => criteriaId(c) === id)) {
    return refuse(`task criteria ${id} is not granted by its tier`);
  }
  const spanS = Math.round((leaf.notAfter.getTime() - leaf.notBefore.getTime()) / 1000);
  if (spanS > def.maxLifetimeS) {
    return refuse(`${id} allows at most ${def.maxLifetimeS}s, this certificate spans ${spanS}s`);
  }
  for (const s of readScopes(leaf) ?? []) {
    if (!def.scopeCeiling.has(s)) return refuse(`${id} does not allow scope ${s}`);
  }
  if (def.requiresConfinementDigest && !leaf.getExtension(OID_CONFINEMENT_DIGEST)) {
    return refuse(`${id} requires the run's confinementDigest (.1.7)`);
  }
  return { ok: true, criteria, legacy: false };
}
