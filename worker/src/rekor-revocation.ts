/**
 * rekor-revocation.ts — each revoke-epoch event, signed by the root as a DSSE
 * statement and recorded in a public, append-only log (notme-8befcc, step 2 of
 * notme-6a4f23, ADR-019 D7).
 *
 * WHY. /.well-known/epochs.json is root-signed (epoch-history.ts), so nobody
 * else can forge it. The authority can: it holds the key and can sign a new
 * history with a revocation dropped, or its time moved. A seqno stops replay
 * of an OLD copy, not a fresh signature over a different past. So each
 * revocation is also written, once, as a root-signed statement to the public
 * sigstore Rekor log, which the authority cannot edit. A verifier compares
 * epochs.json against those entries (checkRevocationsAgainstLog, below).
 *
 * WHY AN IN-TOTO STATEMENT, NOT A CUSTOM PAYLOAD TYPE. ADR-020 ("compose, do
 * not invent") and Rekor itself: for a `dsse` entry whose payload type is
 * in-toto, Rekor indexes the statement's subject digests, so a verifier can
 * find every revocation a root ever logged by searching for that root's
 * digest, without trusting the authority to point at them. The subject is the
 * root public key that signed (sha256 over its 32 raw bytes, the bytes
 * epochs.json publishes as `publicRawB64`); the predicate is notme's, under
 * the `https://notme.bot/provenance/` namespace ADR-019 assigns it.
 *
 *   payloadType: application/vnd.in-toto+json
 *   payload: {"_type":"https://in-toto.io/Statement/v1",
 *             "subject":[{"name":"notme-authority-root:<keyId>","digest":{"sha256":"<hex>"}}],
 *             "predicateType":"https://notme.bot/provenance/epoch-revocation/v1",
 *             "predicate":{"epoch":N,"revokedAt":T,"reason":"...","historySeqno":S,"rootKeyId":"<keyId>"}}
 *
 * `historySeqno` ties the statement to the history: it is a seqno of the
 * epochs.json counter reserved in the same transaction as the revocation, so
 * EVERY epochs.json signed afterwards has a larger seqno and carries this
 * revocation. A document with seqno > historySeqno that lacks it, or carries
 * it with another time or reason, is the rewrite this exists to expose.
 *
 * The payload bytes are what is signed, so no JSON canonicalization is
 * needed to verify; the field order above is fixed only so the golden fixture
 * (schema/fixtures/revocationstatement-*) is reproducible. DSSE's PAE leads
 * with "DSSEv1 " and the payload type, so a statement signature cannot stand
 * in for any other root signature (canonical CBOR maps, DER, JWT inputs).
 *
 * WHAT IS NOT CHECKED HERE. Rekor's own proof that it logged an entry — the
 * signed entry timestamp and the inclusion proof against a signed checkpoint
 * — is the job of a sigstore client (rekor-cli, sigstore-go, cosign) holding
 * Rekor's key from the sigstore trusted root. checkRevocationsAgainstLog
 * takes entries a caller has already fetched and verified that way, and
 * checks what notme is responsible for: that each is a valid root-signed
 * revocation statement and that epochs.json agrees with it.
 */

import type { EpochHistory, EpochRevocation } from "./epoch-history";

export const IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
export const IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json";
export const EPOCH_REVOCATION_PREDICATE_TYPE = "https://notme.bot/provenance/epoch-revocation/v1";
/** in-toto subject name prefix; the key id follows. */
export const ROOT_SUBJECT_PREFIX = "notme-authority-root:";

/** The public sigstore Rekor; REKOR_URL overrides it. */
export const DEFAULT_REKOR_URL = "https://rekor.sigstore.dev";

export interface EpochRevocationPredicate {
  epoch: number;
  /** unix seconds the revocation committed (epochs.json `revokedAt`) */
  revokedAt: number;
  reason: string;
  /** the epochs.json seqno reserved with the revocation; every later document carries it */
  historySeqno: number;
  /** the key id (ADR-012) of the root key that signed this statement */
  rootKeyId: string;
}

export interface DsseSignature {
  keyid: string;
  /** standard base64 */
  sig: string;
}

export interface DsseEnvelope {
  payloadType: string;
  /** standard base64 of the payload bytes */
  payload: string;
  signatures: DsseSignature[];
}

/**
 * What epochs.json publishes beside each signed revocation. None of it is in
 * the epochs.json signing input (epochHistoryCanonical ignores these fields,
 * so the epochhistory fixtures and every vendored verifier are unchanged):
 * the statement carries its own root signature, and the log fields are
 * pointers a verifier confirms against the log, never takes on trust.
 */
export interface RevocationTransparency {
  /** the root-signed statement; null only until it has been signed */
  statement: DsseEnvelope | null;
  /** Rekor's log index once the entry is logged; null while pending (or REKOR_SUBMIT=off) */
  rekorLogIndex: number | null;
  rekorUuid: string | null;
  /** Rekor's integrated time, unix seconds */
  rekorIntegratedTime: number | null;
}

export type PublishedEpochRevocation = EpochRevocation & RevocationTransparency;

// ── bytes ─────────────────────────────────────────────────────────────────

const utf8 = new TextEncoder();

function b64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s);
}

function unb64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

const isUint = (n: unknown): n is number => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;

// ── DSSE ──────────────────────────────────────────────────────────────────

/**
 * DSSE v1 pre-authentication encoding, the bytes actually signed:
 * "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body, lengths in BYTES as
 * ASCII decimal (github.com/secure-systems-lab/dsse protocol.md).
 */
export function dssePae(payloadType: string, payload: Uint8Array): Uint8Array {
  const type = utf8.encode(payloadType);
  return concat([
    utf8.encode(`DSSEv1 ${type.length} `),
    type,
    utf8.encode(` ${payload.length} `),
    payload,
  ]);
}

/** The statement payload bytes for a revocation, signed by the root whose raw public key is given. */
export async function revocationStatementPayload(
  p: EpochRevocationPredicate,
  rootPublicRawB64: string,
): Promise<Uint8Array> {
  for (const [k, v] of [
    ["epoch", p.epoch],
    ["revokedAt", p.revokedAt],
    ["historySeqno", p.historySeqno],
  ] as const) {
    if (!isUint(v)) throw new Error(`revocation statement: ${k} must be a non-negative integer`);
  }
  if (typeof p.reason !== "string" || typeof p.rootKeyId !== "string" || p.rootKeyId === "") {
    throw new Error("revocation statement: reason and rootKeyId must be strings");
  }
  const statement = {
    _type: IN_TOTO_STATEMENT_TYPE,
    subject: [
      {
        name: `${ROOT_SUBJECT_PREFIX}${p.rootKeyId}`,
        digest: { sha256: await sha256Hex(unb64(rootPublicRawB64)) },
      },
    ],
    predicateType: EPOCH_REVOCATION_PREDICATE_TYPE,
    predicate: {
      epoch: p.epoch,
      revokedAt: p.revokedAt,
      reason: p.reason,
      historySeqno: p.historySeqno,
      rootKeyId: p.rootKeyId,
    },
  };
  return utf8.encode(JSON.stringify(statement));
}

/**
 * Build and sign the statement. `sign` is the caller's signer over the PAE
 * bytes — in the authority, the root CryptoKey that never leaves the Durable
 * Object; this module never sees a key.
 */
export async function signRevocationStatement(
  p: EpochRevocationPredicate,
  rootPublicRawB64: string,
  sign: (message: Uint8Array) => Promise<ArrayBuffer | Uint8Array>,
): Promise<DsseEnvelope> {
  const payload = await revocationStatementPayload(p, rootPublicRawB64);
  const sig = new Uint8Array(await sign(dssePae(IN_TOTO_PAYLOAD_TYPE, payload)));
  return {
    payloadType: IN_TOTO_PAYLOAD_TYPE,
    payload: b64(payload),
    signatures: [{ keyid: p.rootKeyId, sig: b64(sig) }],
  };
}

export type StatementCheck =
  | { ok: true; predicate: EpochRevocationPredicate }
  | { ok: false; reason: string };

/**
 * True iff `envelope` is a revocation statement signed by the root whose raw
 * Ed25519 public key is given, about that root: the payload type and
 * statement type are right, the subject is that key, and the predicate is
 * well formed.
 */
export async function verifyRevocationStatement(
  envelope: DsseEnvelope,
  rootPublicRawB64: string,
): Promise<StatementCheck> {
  try {
    if (envelope?.payloadType !== IN_TOTO_PAYLOAD_TYPE) return { ok: false, reason: "payload_type" };
    if (!Array.isArray(envelope.signatures) || envelope.signatures.length === 0) {
      return { ok: false, reason: "unsigned" };
    }
    const payload = unb64(envelope.payload);
    const key = await crypto.subtle.importKey("raw", unb64(rootPublicRawB64), { name: "Ed25519" }, false, [
      "verify",
    ]);
    const pae = dssePae(envelope.payloadType, payload);
    let signed = false;
    for (const s of envelope.signatures) {
      if (await crypto.subtle.verify("Ed25519", key, unb64(s.sig), pae)) {
        signed = true;
        break;
      }
    }
    if (!signed) return { ok: false, reason: "signature" };

    const stmt = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(payload)) as {
      _type?: unknown;
      subject?: Array<{ name?: unknown; digest?: { sha256?: unknown } }>;
      predicateType?: unknown;
      predicate?: Partial<EpochRevocationPredicate>;
    };
    if (stmt._type !== IN_TOTO_STATEMENT_TYPE) return { ok: false, reason: "statement_type" };
    if (stmt.predicateType !== EPOCH_REVOCATION_PREDICATE_TYPE) return { ok: false, reason: "predicate_type" };
    const p = stmt.predicate ?? {};
    if (
      !isUint(p.epoch) ||
      !isUint(p.revokedAt) ||
      !isUint(p.historySeqno) ||
      typeof p.reason !== "string" ||
      typeof p.rootKeyId !== "string"
    ) {
      return { ok: false, reason: "predicate" };
    }
    const want = await sha256Hex(unb64(rootPublicRawB64));
    if (
      !Array.isArray(stmt.subject) ||
      stmt.subject.length !== 1 ||
      stmt.subject[0]?.name !== `${ROOT_SUBJECT_PREFIX}${p.rootKeyId}` ||
      stmt.subject[0]?.digest?.sha256 !== want
    ) {
      return { ok: false, reason: "subject" };
    }
    return {
      ok: true,
      predicate: {
        epoch: p.epoch,
        revokedAt: p.revokedAt,
        reason: p.reason,
        historySeqno: p.historySeqno,
        rootKeyId: p.rootKeyId,
      },
    };
  } catch {
    return { ok: false, reason: "malformed" };
  }
}

// ── Rekor v1 ──────────────────────────────────────────────────────────────

/** RFC 8410 Ed25519 SubjectPublicKeyInfo prefix; the 32 raw key bytes follow. */
const ED25519_SPKI_PREFIX = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);

/** PKIX PEM of a raw Ed25519 public key, as Rekor's `verifiers` expect (before their own base64). */
export function ed25519PublicKeyPem(rootPublicRawB64: string): string {
  const raw = unb64(rootPublicRawB64);
  if (raw.length !== 32) throw new Error("ed25519 public key must be 32 bytes");
  const lines = b64(concat([ED25519_SPKI_PREFIX, raw])).match(/.{1,64}/g)!;
  return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----\n`;
}

/**
 * The body of `POST /api/v1/log/entries` for a `dsse` entry (Rekor openapi
 * `dsse` + pkg/types/dsse/v0.0.1 schema): the envelope as a JSON STRING, and
 * each verifier as base64 of a PEM public key. Rekor verifies the signature
 * against the verifier before it logs anything.
 */
export function rekorDsseProposedEntry(envelope: DsseEnvelope, rootPublicRawB64: string): unknown {
  return {
    kind: "dsse",
    apiVersion: "0.0.1",
    spec: {
      proposedContent: {
        envelope: JSON.stringify(envelope),
        verifiers: [b64(utf8.encode(ed25519PublicKeyPem(rootPublicRawB64)))],
      },
    },
  };
}

/** One log entry as Rekor returns it, the value under its uuid. */
export interface RekorLogEntry {
  logIndex: number;
  integratedTime: number;
  /** base64 of the canonical entry JSON Rekor stored */
  body: string;
  logID?: string;
}

export type RekorSubmitResult =
  | { ok: true; uuid: string; logIndex: number; integratedTime: number }
  | { ok: false; reason: string };

/** Whether a Rekor `dsse` entry body records THIS envelope: its payload hash and its signature. */
async function entryRecords(entry: RekorLogEntry, envelope: DsseEnvelope): Promise<string | null> {
  let body: {
    kind?: unknown;
    spec?: { payloadHash?: { algorithm?: unknown; value?: unknown }; signatures?: Array<{ signature?: unknown }> };
  };
  try {
    body = JSON.parse(new TextDecoder().decode(unb64(entry.body)));
  } catch {
    return "body is not base64 JSON";
  }
  if (body.kind !== "dsse") return `kind ${String(body.kind)}, not dsse`;
  const ph = body.spec?.payloadHash;
  if (ph?.algorithm !== "sha256" || ph.value !== (await sha256Hex(unb64(envelope.payload)))) {
    return "payloadHash is not this statement's";
  }
  const sigs = new Set((body.spec?.signatures ?? []).map((s) => s.signature));
  if (!envelope.signatures.some((s) => sigs.has(s.sig))) return "no signature of this statement";
  return null;
}

/**
 * Read Rekor's `{<uuid>: LogEntry}` answer for `envelope`. Refuses an answer
 * that logged anything else: a misconfigured REKOR_URL, a proxy, or a log that
 * answers for the wrong entry must leave the row pending, not mark it logged.
 * (The worker does not verify Rekor's signed entry timestamp; it holds no
 * Rekor key. A verifier does, and that is where the log is trusted.)
 */
export async function parseRekorEntry(json: unknown, envelope: DsseEnvelope): Promise<RekorSubmitResult> {
  if (!json || typeof json !== "object") return { ok: false, reason: "rekor answer is not an object" };
  const entries = Object.entries(json as Record<string, unknown>);
  if (entries.length !== 1) return { ok: false, reason: `rekor answer has ${entries.length} entries` };
  const [uuid, e] = entries[0]! as [string, Partial<RekorLogEntry>];
  if (!/^[0-9a-f]{64}(?:[0-9a-f]{16})?$/.test(uuid)) return { ok: false, reason: "rekor uuid malformed" };
  if (!e || !isUint(e.logIndex) || !isUint(e.integratedTime) || typeof e.body !== "string") {
    return { ok: false, reason: "rekor entry missing logIndex, integratedTime or body" };
  }
  const why = await entryRecords(e as RekorLogEntry, envelope);
  if (why) return { ok: false, reason: `rekor entry ${uuid}: ${why}` };
  return { ok: true, uuid, logIndex: e.logIndex, integratedTime: e.integratedTime };
}

/**
 * Submit one statement to Rekor v1 and read back where it landed.
 *
 * 201 is the new entry. 409 means an identical entry is already logged — a
 * retry after a lost answer — and Rekor's Location header names it, so it is
 * fetched and recorded like a 201: submission is idempotent, a retry never
 * makes a second entry. Everything else is a failure with a reason. Never
 * throws; bounded by `timeoutMs` per request.
 */
export async function submitToRekor(opts: {
  baseUrl: string;
  envelope: DsseEnvelope;
  rootPublicRawB64: string;
  timeoutMs: number;
  fetch?: typeof fetch;
}): Promise<RekorSubmitResult> {
  const doFetch = opts.fetch ?? ((input: RequestInfo | URL, init?: RequestInit) => fetch(input, init));
  try {
    const base = new URL(opts.baseUrl);
    if (base.protocol !== "https:" && base.protocol !== "http:") {
      return { ok: false, reason: `REKOR_URL ${opts.baseUrl} is not http(s)` };
    }
    const root = opts.baseUrl.replace(/\/+$/, "");
    const res = await doFetch(`${root}/api/v1/log/entries`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(rekorDsseProposedEntry(opts.envelope, opts.rootPublicRawB64)),
      signal: AbortSignal.timeout(opts.timeoutMs),
    });
    if (res.status === 201) return await parseRekorEntry(await res.json(), opts.envelope);
    if (res.status === 409) {
      const location = res.headers.get("location");
      await res.body?.cancel();
      if (!location) return { ok: false, reason: "rekor 409 without a Location" };
      const existing = await doFetch(new URL(location, `${root}/`).href, {
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(opts.timeoutMs),
      });
      if (existing.status !== 200) {
        await existing.body?.cancel();
        return { ok: false, reason: `rekor 409, then ${existing.status} reading ${location}` };
      }
      return await parseRekorEntry(await existing.json(), opts.envelope);
    }
    const text = (await res.text()).slice(0, 200);
    return { ok: false, reason: `rekor answered ${res.status}: ${text}` };
  } catch (err) {
    return { ok: false, reason: `rekor unreachable: ${String(err).slice(0, 200)}` };
  }
}

// ── the verifier's check ──────────────────────────────────────────────────

/** A logged statement: the envelope (epochs.json publishes it) and Rekor's entry for it. */
export interface LoggedRevocation {
  envelope: DsseEnvelope;
  entry: RekorLogEntry;
}

export type LogProblem =
  | { problem: "missing_from_history"; epoch: number; detail: string }
  | { problem: "differs_from_log"; epoch: number; detail: string }
  | { problem: "conflicting_log_entries"; epoch: number; detail: string }
  | { problem: "log_index_mismatch"; epoch: number; detail: string }
  | { problem: "not_logged"; epoch: number; detail: string }
  | { problem: "bad_log_entry"; logIndex: number; detail: string };

export interface LogCheck {
  ok: boolean;
  problems: LogProblem[];
  /** epochs revoked in the document with no valid logged statement (pending, or never logged) */
  unlogged: number[];
}

type HistoryForCheck = Pick<EpochHistory, "seqno" | "epochs"> & {
  revocations: Array<EpochRevocation & Partial<RevocationTransparency>>;
};

/**
 * Does `doc` (epochs.json) agree with the revocation statements the log
 * holds? Call it only on a document whose own signature verified under the
 * trusted root (verifyEpochHistorySignature), with `logged` = every entry the
 * verifier found for the roots in `doc.epochs` (Rekor search by subject digest
 * `sha256:<hex of the raw key>`), each already verified as included in the
 * log by a sigstore client.
 *
 * Each logged entry must record its envelope (payload hash and signature),
 * and the envelope must be a revocation statement signed by the key
 * `doc.epochs` lists under its rootKeyId; anything else is `bad_log_entry` and
 * evidence for nothing. Then, for every valid statement S:
 *   - `doc.seqno > S.historySeqno`: the document was signed after S's
 *     revocation committed, so it MUST carry it — absent is
 *     `missing_from_history`, another revokedAt or reason `differs_from_log`;
 *   - otherwise the document predates S and may lack it, but if it carries
 *     that epoch's revocation it must agree;
 *   - two valid statements about one epoch that disagree are
 *     `conflicting_log_entries` (the authority signed two pasts);
 *   - a `rekorLogIndex` the document claims for that epoch that is not S's is
 *     `log_index_mismatch` (an unsigned pointer, but a wrong one is a lie).
 * A revocation in the document with no valid statement is listed in
 * `unlogged` — normal while submission is pending — and is a problem
 * (`not_logged`) only with `requireLogged`, for a verifier that will not
 * accept a revocation time the log does not also hold.
 */
export async function checkRevocationsAgainstLog(
  doc: HistoryForCheck,
  logged: LoggedRevocation[],
  opts: { requireLogged?: boolean } = {},
): Promise<LogCheck> {
  const problems: LogProblem[] = [];
  const keys = new Map(doc.epochs.map((e) => [e.keyId, e.publicRawB64]));
  const byEpoch = new Map<number, Array<{ p: EpochRevocationPredicate; logIndex: number }>>();

  for (const { envelope, entry } of logged) {
    const logIndex = isUint(entry?.logIndex) ? entry.logIndex : -1;
    const why = await entryRecords(entry, envelope).catch(() => "unreadable entry");
    if (why) {
      problems.push({ problem: "bad_log_entry", logIndex, detail: why });
      continue;
    }
    const keyid = envelope.signatures?.[0]?.keyid;
    const pub = keyid === undefined ? undefined : keys.get(keyid);
    if (!pub) {
      problems.push({ problem: "bad_log_entry", logIndex, detail: `signed by ${String(keyid)}, no key in the history` });
      continue;
    }
    const v = await verifyRevocationStatement(envelope, pub);
    if (!v.ok || v.predicate.rootKeyId !== keyid) {
      problems.push({ problem: "bad_log_entry", logIndex, detail: v.ok ? "rootKeyId is not the signer" : v.reason });
      continue;
    }
    const list = byEpoch.get(v.predicate.epoch) ?? [];
    list.push({ p: v.predicate, logIndex });
    byEpoch.set(v.predicate.epoch, list);
  }

  const same = (a: { revokedAt: number; reason: string }, b: { revokedAt: number; reason: string }) =>
    a.revokedAt === b.revokedAt && a.reason === b.reason;

  for (const [epoch, list] of byEpoch) {
    const first = list[0]!.p;
    if (list.some((s) => !same(s.p, first))) {
      problems.push({
        problem: "conflicting_log_entries",
        epoch,
        detail: `log indexes ${list.map((s) => s.logIndex).join(", ")} disagree`,
      });
    }
    const r = doc.revocations.find((x) => x.epoch === epoch);
    const mustCarry = list.some((s) => doc.seqno > s.p.historySeqno);
    if (!r) {
      if (mustCarry) {
        problems.push({
          problem: "missing_from_history",
          epoch,
          detail: `logged at index ${list[0]!.logIndex}; history seqno ${doc.seqno} > ${Math.min(...list.map((s) => s.p.historySeqno))}`,
        });
      }
      continue;
    }
    if (!list.some((s) => same(s.p, r))) {
      problems.push({
        problem: "differs_from_log",
        epoch,
        detail: `history says revokedAt ${r.revokedAt} "${r.reason}", log says ${first.revokedAt} "${first.reason}"`,
      });
    }
    if (typeof r.rekorLogIndex === "number" && !list.some((s) => s.logIndex === r.rekorLogIndex)) {
      problems.push({
        problem: "log_index_mismatch",
        epoch,
        detail: `history points at ${r.rekorLogIndex}, statement is at ${list.map((s) => s.logIndex).join(", ")}`,
      });
    }
  }

  const unlogged = doc.revocations.filter((r) => !byEpoch.has(r.epoch)).map((r) => r.epoch);
  if (opts.requireLogged) {
    for (const epoch of unlogged) {
      problems.push({ problem: "not_logged", epoch, detail: "no valid logged statement for this revocation" });
    }
  }
  return { ok: problems.length === 0, problems, unlogged };
}
