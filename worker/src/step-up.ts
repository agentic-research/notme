/**
 * step-up.ts — step-up presence certificates (ADR-024, notme-d92ba1).
 *
 * "Touch your key before this action" as a credential a third party can
 * check with nothing but the notme root. notme verifies a WebAuthn assertion
 * whose challenge is the ACTION's digest (D2), then mints a short-lived
 * `step-up/1` certificate for the requesting task's signing key (D3) that
 * names the action in `.1.9` and the approver in `.1.11` (D4). A verifier
 * presented with the task certificate, the step-up certificate and the
 * action runs `checkStepUp` (D7) after verifying both chains and epochs.
 *
 * The raw assertion is not the proof: only notme holds the credential key,
 * so notme is the assertion's verifier of record and the certificate is the
 * portable result.
 */
import { Extension, X509Certificate, X509CertificateGenerator } from "@peculiar/x509";
import { Encoder } from "cbor-x";
import {
  BASIC_CONSTRAINTS_LEAF,
  OID_APPROVAL,
  OID_AUTH_METHOD,
  OID_CRITERIA,
  OID_EPOCH,
  OID_ISSUANCE_TIME,
  OID_PEER_BINDING,
  OID_PRINCIPAL_KIND,
  OID_SCOPES,
  OID_SUBJECT,
  OID_TASK_SCOPE,
  SIGNING_KEY_USAGE,
  certTaskScope,
  derInteger,
  derScopeSequence,
  derTlv,
  derUtf8String,
} from "./cert-authority";
import { checkCriteria, criteriaId, encodeCriteria, readCriteria } from "./criteria";
import { ED25519 } from "./platform";

// ── The action (D2) ──────────────────────────────────────────────────────

export interface StepUpAction {
  /** What is being approved, e.g. "deploy" or "accept". */
  type: string;
  /** Its parameters, e.g. { commit, env }. Strings only, so the bytes are unambiguous. */
  params: Record<string, string>;
  /** The requesting task's `.1.9` task id (path). */
  taskId: string;
  /** SHA-256 of the requesting task signing certificate's SubjectPublicKeyInfo. */
  requesterSpkiSha256: Uint8Array;
  /** The requester's nonce: two identical actions get two approvals. */
  nonce: Uint8Array;
}

const CHALLENGE_DOMAIN = "notme-step-up-v1:";

// Same options as revocation.ts's canonical encoder (ADR-010): Map keeps
// integer keys, plain CBOR, byte strings as major type 2.
const cbor = new Encoder({ mapsAsObjects: false, useRecords: false, tagUint8Array: false });

/** RFC 8949 §4.2 order for text keys: shorter first, then bytewise. */
function canonicalTextOrder(a: string, b: string): number {
  const ab = new TextEncoder().encode(a);
  const bb = new TextEncoder().encode(b);
  if (ab.length !== bb.length) return ab.length - bb.length;
  for (let i = 0; i < ab.length; i++) if (ab[i] !== bb[i]) return ab[i]! - bb[i]!;
  return 0;
}

/**
 * The action's canonical bytes: deterministic CBOR (RFC 8949 §4.2) of
 * `{1: type, 2: {params, sorted}, 3: taskId, 4: requesterSpkiSha256, 5: nonce}`.
 * The cross-language contract: signet recomputes these bytes.
 */
export function actionCanonical(a: StepUpAction): Uint8Array {
  if (a.requesterSpkiSha256.length !== 32) throw new Error("requesterSpkiSha256 must be 32 bytes");
  if (a.nonce.length < 16) throw new Error("nonce must be at least 16 bytes");
  const params = new Map(Object.keys(a.params).sort(canonicalTextOrder).map((k) => [k, a.params[k]!]));
  for (const v of params.values()) if (typeof v !== "string") throw new Error("action params must be strings");
  const m = new Map<number, unknown>([
    [1, a.type],
    [2, params],
    [3, a.taskId],
    [4, new Uint8Array(a.requesterSpkiSha256)],
    [5, new Uint8Array(a.nonce)],
  ]);
  return new Uint8Array(cbor.encode(m));
}

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const sha256 = async (b: Uint8Array) => new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(b)));

/** SHA-256(canonical) as hex: the step-up certificate's `.1.9` goal hash. */
export async function actionDigest(a: StepUpAction): Promise<string> {
  return hex(await sha256(actionCanonical(a)));
}

/** The WebAuthn challenge: SHA-256("notme-step-up-v1:" ‖ canonical). One tap, one action. */
export async function stepUpChallenge(a: StepUpAction): Promise<Uint8Array> {
  const c = actionCanonical(a);
  const prefix = new TextEncoder().encode(CHALLENGE_DOMAIN);
  const msg = new Uint8Array(prefix.length + c.length);
  msg.set(prefix, 0);
  msg.set(c, prefix.length);
  return sha256(msg);
}

// ── .1.11 approval (D4) ──────────────────────────────────────────────────

export type PresenceMethod = "passkey-uv" | "passkey-up";
const METHODS: ReadonlySet<string> = new Set(["passkey-uv", "passkey-up"]);

export interface Approval {
  /** Principal id of the human who approved. */
  approver: string;
  method: PresenceMethod;
  /** When the assertion verified (whole seconds). */
  assertedAt: Date;
}

function generalizedTime(d: Date): string {
  return d.toISOString().replace(/[-:T]/g, "").replace(/\.\d{3}Z$/, "Z");
}

/** DER `SEQUENCE { UTF8String approver, UTF8String method, GeneralizedTime assertedAt }`. */
export function encodeApproval(a: Approval): Uint8Array {
  if (!a.approver) throw new Error("approver required");
  if (!METHODS.has(a.method)) throw new Error(`unknown presence method ${a.method}`);
  const time = derTlv(0x18, new TextEncoder().encode(generalizedTime(a.assertedAt)));
  return derTlv(0x30, new Uint8Array([...derUtf8String(a.approver), ...derUtf8String(a.method), ...time]));
}

type ExtensionSource = { getExtension(oid: string): { value: ArrayBuffer } | null };

/** One short- or long-form TLV inside [at, limit), or null. */
function tlv(der: Uint8Array, at: number, limit: number): { tag: number; start: number; end: number } | null {
  if (at + 2 > limit) return null;
  const tag = der[at]!;
  let len = der[at + 1]!;
  let start = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 2 || start + n > limit) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + der[start + i]!;
    start += n;
  }
  const end = start + len;
  return end > limit ? null : { tag, start, end };
}

/** Read `.1.11`. Malformed input is reported, never thrown. */
export function readApproval(
  cert: ExtensionSource,
): { present: false } | { present: true; ok: true; approval: Approval } | { present: true; ok: false; reason: string } {
  const ext = cert.getExtension(OID_APPROVAL);
  if (!ext) return { present: false };
  const bad = { present: true as const, ok: false as const, reason: "malformed approval" };
  try {
    const der = new Uint8Array(ext.value);
    const seq = tlv(der, 0, der.length);
    if (!seq || seq.tag !== 0x30 || seq.end !== der.length) return bad;
    const a = tlv(der, seq.start, seq.end);
    const m = a && tlv(der, a.end, seq.end);
    const t = m && tlv(der, m.end, seq.end);
    if (!a || !m || !t || a.tag !== 0x0c || m.tag !== 0x0c || t.tag !== 0x18 || t.end !== seq.end) return bad;
    const text = (x: { start: number; end: number }) =>
      new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(der.subarray(x.start, x.end));
    const approver = text(a);
    const method = text(m);
    const gt = text(t);
    const g = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(gt);
    if (!approver || !METHODS.has(method) || !g) return bad;
    const assertedAt = new Date(`${g[1]}-${g[2]}-${g[3]}T${g[4]}:${g[5]}:${g[6]}Z`);
    if (Number.isNaN(assertedAt.getTime()) || generalizedTime(assertedAt) !== gt) return bad;
    return { present: true, ok: true, approval: { approver, method: method as PresenceMethod, assertedAt } };
  } catch {
    return bad;
  }
}

// ── Minting (D1, D3) ─────────────────────────────────────────────────────

const STEP_UP = { name: "step-up", version: 1 } as const;
const STEP_UP_TTL_MS = 300_000;

/**
 * Mint a `step-up/1` certificate for the task signing certificate
 * `taskSigningCertPem`, signed by the authority root. The caller has
 * VERIFIED the WebAuthn assertion over `stepUpChallenge(action)`; this
 * function refuses an action that does not name this task and this key.
 */
export async function mintStepUpCert(
  rootPrivateKey: CryptoKey,
  taskSigningCertPem: string,
  opts: { action: StepUpAction; approval: Approval; epoch: number; issuerName?: string; ttlMs?: number },
): Promise<string> {
  const task = new X509Certificate(taskSigningCertPem);
  const scope = certTaskScope(task);
  if (!scope) throw new Error("not a task certificate: no .1.9 task scope");
  if (opts.action.taskId !== scope.task) {
    throw new Error(`action names task ${JSON.stringify(opts.action.taskId)}, the certificate is task ${JSON.stringify(scope.task)}`);
  }
  const spki = new Uint8Array(task.publicKey.rawData);
  if (hex(await sha256(spki)) !== hex(opts.action.requesterSpkiSha256)) {
    throw new Error("action names a different requester key than the task certificate's");
  }
  const ttlMs = Math.min(opts.ttlMs ?? STEP_UP_TTL_MS, STEP_UP_TTL_MS);
  const now = new Date(Math.floor(Date.now() / 1000) * 1000);
  const subjectExt = task.getExtension(OID_SUBJECT);
  const subject = subjectExt ? new TextDecoder().decode(new Uint8Array(subjectExt.value).subarray(2)) : scope.task;
  const san = task.getExtension("2.5.29.17");
  const binding = task.getExtension(OID_PEER_BINDING);
  const serial = crypto.getRandomValues(new Uint8Array(16));
  serial[0]! &= 0x7f;

  const cert = await X509CertificateGenerator.create({
    subject: task.subject,
    issuer: opts.issuerName ?? "CN=signet-authority,O=notme",
    notBefore: now,
    notAfter: new Date(now.getTime() + ttlMs),
    signingAlgorithm: ED25519,
    publicKey: await task.publicKey.export(),
    signingKey: rootPrivateKey,
    serialNumber: hex(serial),
    extensions: [
      BASIC_CONSTRAINTS_LEAF,
      SIGNING_KEY_USAGE,
      new Extension(OID_SUBJECT, false, derUtf8String(subject)),
      new Extension(OID_ISSUANCE_TIME, false, derUtf8String(now.toISOString())),
      new Extension(OID_SCOPES, false, derScopeSequence(["bridgeCert"])),
      new Extension(OID_EPOCH, false, derInteger(opts.epoch)),
      new Extension(OID_AUTH_METHOD, false, derUtf8String(opts.approval.method)),
      ...(binding ? [new Extension(OID_PEER_BINDING, false, new Uint8Array(binding.value))] : []),
      new Extension(OID_PRINCIPAL_KIND, false, derUtf8String("agent")),
      ...(san ? [new Extension("2.5.29.17", true, new Uint8Array(san.value))] : []),
      new Extension(OID_TASK_SCOPE, false, derTaskScopeBytes(scope.task, await actionDigest(opts.action))),
      new Extension(OID_CRITERIA, false, encodeCriteria([STEP_UP])),
      new Extension(OID_APPROVAL, false, encodeApproval(opts.approval)),
    ],
  });

  // The producer never hands out a certificate its own verifier refuses.
  const verdict = checkCriteria(null, cert);
  if (!verdict.ok) throw new Error(verdict.reason);
  return cert.toString("pem");
}

/** `.1.9`: SEQUENCE { UTF8String task, OCTET STRING goalHash } (cert-authority.ts's layout). */
function derTaskScopeBytes(task: string, goalHashHex: string): Uint8Array {
  const hash = new Uint8Array(goalHashHex.match(/../g)!.map((h) => parseInt(h, 16)));
  return derTlv(0x30, new Uint8Array([...derUtf8String(task), ...derTlv(0x04, hash)]));
}

// ── Verifying (D7) ───────────────────────────────────────────────────────

export interface StepUpPolicy {
  /** The weakest method accepted; passkey-uv also satisfies passkey-up. */
  method: PresenceMethod;
  /** Seconds after assertedAt the approval still covers. */
  maxAgeS: number;
}

export type StepUpVerdict = { ok: true } | { ok: false; reason: string };

/**
 * D7 steps 2-4. The caller has already chained BOTH certificates to the
 * notme root and checked their epochs, as for any notme certificate. `at`
 * is the action's time.
 */
export async function checkStepUp(
  taskCert: X509Certificate,
  stepUp: X509Certificate,
  action: StepUpAction,
  policy: StepUpPolicy,
  at: Date,
): Promise<StepUpVerdict> {
  const refuse = (reason: string): StepUpVerdict => ({ ok: false, reason });

  const c = checkCriteria(null, stepUp);
  if (!c.ok) return refuse(c.reason);
  const crit = readCriteria(stepUp);
  if (!crit.present || !crit.ok || criteriaId(crit.list[0]!) !== "step-up/1") return refuse("not a step-up/1 certificate");

  const taskSpki = new Uint8Array(taskCert.publicKey.rawData);
  if (hex(taskSpki) !== hex(new Uint8Array(stepUp.publicKey.rawData))) return refuse("step-up certifies a different key");
  if (hex(await sha256(taskSpki)) !== hex(action.requesterSpkiSha256)) return refuse("action names a different requester key");

  const taskScope = certTaskScope(taskCert);
  const stepScope = certTaskScope(stepUp);
  if (!taskScope || !stepScope) return refuse("missing .1.9 task scope");
  if (taskScope.task !== stepScope.task || action.taskId !== taskScope.task) return refuse("step-up is for a different task");
  if (stepScope.goalHash !== (await actionDigest(action))) return refuse("step-up approves a different action");

  const r = readApproval(stepUp);
  if (!r.present) return refuse("step-up carries no approval (.1.11)");
  if (!r.ok) return refuse(r.reason);
  if (policy.method === "passkey-uv" && r.approval.method !== "passkey-uv") {
    return refuse(`policy requires passkey-uv, approval was ${r.approval.method}`);
  }
  if (r.approval.assertedAt.getTime() + policy.maxAgeS * 1000 < at.getTime()) return refuse("approval is older than policy allows");
  if (at.getTime() < stepUp.notBefore.getTime() || at.getTime() > stepUp.notAfter.getTime()) {
    return refuse("action time is outside the step-up certificate's validity");
  }
  return { ok: true };
}
