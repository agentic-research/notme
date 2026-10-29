/**
 * Task-certificate client (notme-486e8a): what a MACHINE runs to hold a
 * delegation tier and mint task certificates offline.
 *
 * The flow it implements:
 *   1. enroll — generate a tier keypair HERE; ask the authority for a device
 *      enrolment; a human approves the user code with their passkey; collect
 *      the tier with a proof over the device code.
 *   2. mint  — per task, with no network: a cert pair whose identity is
 *      <tier identity>/<task> and whose .1.9 extension commits to the task id
 *      and a hash of its goal.
 *   3. verify — root → tier → task.
 *
 * Minting uses the AUTHORITY'S OWN code (worker/src/cert-authority.ts), not a
 * client copy, so the offline mint enforces the same rules the authority
 * would: scopes never exceed the tier's, lifetime never outlives it, an
 * expired tier is refused, and the tier key must match the tier cert.
 */
import { chmodSync, existsSync, linkSync, mkdirSync, readdirSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { X509Certificate, BasicConstraintsExtension } from "@peculiar/x509";
import { mintTaskCertPair } from "../../worker/src/cert-authority";
import { ED25519 } from "../../worker/src/platform";
import {
  deviceCodeHash, RENEWAL_RETRY_WINDOW_S, RENEWAL_SKEW_S, tierEnrolmentBinding, tierRenewalBinding, tierRenewalBindingV2,
} from "../../worker/src/auth/tier-enrolment-binding";

const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const b64url = (b: Uint8Array) => b64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const hex = (b: Uint8Array) => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const pemWrap = (label: string, der: Uint8Array) =>
  `-----BEGIN ${label}-----\n${b64(der).match(/.{1,64}/g)!.join("\n")}\n-----END ${label}-----\n`;
const pemBody = (pem: string) =>
  Uint8Array.from(atob(pem.replace(/-----[A-Z ]+-----|\s/g, "")), (c) => c.charCodeAt(0));

export async function generateTierKey(): Promise<{
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  spki: Uint8Array;
  pem: string;
  fingerprint: string;
}> {
  // Extractable ONLY so it can be written to disk once; it is re-imported
  // non-extractable for every use after that.
  const kp = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = new Uint8Array((await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer);
  const fingerprint = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", spki)));
  return { privateKey: kp.privateKey, publicKey: kp.publicKey, spki, pem: pemWrap("PUBLIC KEY", spki), fingerprint };
}

/** The fingerprint as the approval page shows it — first 64 bits, in fours. */
export function groupFingerprint(fingerprintHex: string): string {
  return fingerprintHex.slice(0, 16).match(/..../g)!.join(" ");
}

export async function exportPrivateKeyPem(key: CryptoKey): Promise<string> {
  return pemWrap("PRIVATE KEY", new Uint8Array((await crypto.subtle.exportKey("pkcs8", key)) as ArrayBuffer));
}

export async function importPrivateKeyPem(pem: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("pkcs8", pemBody(pem), ED25519, false, ["sign"]);
}

/** The collection proof — over the authority's shared binding, byte for byte. */
export async function enrolProof(privateKey: CryptoKey, spki: Uint8Array, deviceCode: string): Promise<string> {
  const input = tierEnrolmentBinding(spki, await deviceCodeHash(deviceCode));
  return b64url(new Uint8Array(await crypto.subtle.sign(ED25519, privateKey, input)));
}

export type EnrolmentStart = {
  device_code: string;
  user_code: string;
  verification_uri: string;
  key_fingerprint: string;
  expires_in: number;
  interval: number;
};

export async function startEnrolment(
  authority: string,
  publicKeyPem: string,
  scopes: string[] | undefined,
  fetchFn: typeof fetch = fetch,
): Promise<EnrolmentStart> {
  const res = await fetchFn(`${authority}/cert/issuing-ca/device`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ public_key: publicKeyPem, ...(scopes ? { scopes } : {}) }),
  });
  const body = (await res.json().catch(() => ({}))) as EnrolmentStart & { error?: string };
  if (!res.ok) throw new Error(`enrolment start refused: ${body.error ?? res.status}`);
  return body;
}

/**
 * Poll until the human approves (RFC 8628 §3.4–3.5). `authorization_pending`
 * and `slow_down` keep polling; anything else is terminal and is thrown with
 * the authority's error name, so a script can tell "denied" from "expired".
 */
export async function pollEnrolment(
  authority: string,
  deviceCode: string,
  proof: string,
  opts: {
    interval: number;
    expiresIn: number;
    fetchFn?: typeof fetch;
    sleep?: (ms: number) => Promise<void>;
  },
): Promise<any> {
  const fetchFn = opts.fetchFn ?? fetch;
  const sleep = opts.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
  let interval = opts.interval;
  const deadline = Date.now() + opts.expiresIn * 1000;
  for (;;) {
    const res = await fetchFn(`${authority}/cert/issuing-ca/device/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ device_code: deviceCode, proof }),
    });
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    if (res.ok) return body;
    if (body.error === "authorization_pending" || body.error === "slow_down") {
      if (body.error === "slow_down") interval += 5;
      if (Date.now() + interval * 1000 > deadline) throw new Error("expired_token");
      await sleep(interval * 1000);
      continue;
    }
    throw new Error(body.error ?? `HTTP ${res.status}`);
  }
}

async function spkiPemOf(key: CryptoKey): Promise<string> {
  return pemWrap("PUBLIC KEY", new Uint8Array((await crypto.subtle.exportKey("spki", key)) as ArrayBuffer));
}

/**
 * Mint a task cert pair OFFLINE under the tier. Generates the task's own
 * keys; the goal is hashed here so the certificate commits to it without
 * carrying the text.
 */
export async function mintTask(
  tierPem: string,
  tierPrivateKey: CryptoKey,
  opts: { task: string; goal: string; epoch: number; scopes?: string[]; ttlMs?: number; parent?: string },
) {
  const mtls = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const signing = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
  const goalHash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(opts.goal))));
  const result = await mintTaskCertPair(
    tierPem,
    tierPrivateKey,
    await spkiPemOf(mtls.publicKey),
    await spkiPemOf(signing.publicKey),
    { task: opts.task, goalHash, scopes: opts.scopes ?? ["bridgeCert"], epoch: opts.epoch, ttlMs: opts.ttlMs, parent: opts.parent },
  );
  return {
    ...result,
    goalHash,
    keys: {
      mtls: pemWrap("PRIVATE KEY", new Uint8Array((await crypto.subtle.exportKey("pkcs8", mtls.privateKey)) as ArrayBuffer)),
      signing: pemWrap("PRIVATE KEY", new Uint8Array((await crypto.subtle.exportKey("pkcs8", signing.privateKey)) as ArrayBuffer)),
    },
  };
}

/**
 * root → tier → task. Signatures checked with the library; validity windows
 * checked HERE, inclusively, because @peculiar/x509's date check is a strict
 * `notBefore < t` and reads a cert as invalid at the instant it was minted.
 */
export async function verifyChain(
  rootPem: string,
  tierPem: string,
  leafPem: string,
  at: Date = new Date(),
): Promise<{ ok: true } | { ok: false; reason: string }> {
  const root = new X509Certificate(rootPem);
  const tier = new X509Certificate(tierPem);
  const leaf = new X509Certificate(leafPem);
  const within = (c: X509Certificate) => c.notBefore.getTime() <= at.getTime() && at.getTime() <= c.notAfter.getTime();

  if (tier.issuer !== root.subject) return { ok: false, reason: "tier was not issued by this root" };
  if (!(await tier.verify({ publicKey: await root.publicKey.export(), signatureOnly: true }))) {
    return { ok: false, reason: "tier signature does not verify under the root" };
  }
  const bc = tier.getExtension(BasicConstraintsExtension);
  if (!bc?.ca || bc.pathLength !== 0) return { ok: false, reason: "tier is not a pathlen=0 CA" };
  if (leaf.issuer !== tier.subject) return { ok: false, reason: "task cert was not issued by this tier" };
  if (!(await leaf.verify({ publicKey: await tier.publicKey.export(), signatureOnly: true }))) {
    return { ok: false, reason: "task cert signature does not verify under the tier" };
  }
  if (leaf.getExtension(BasicConstraintsExtension)?.ca) return { ok: false, reason: "task cert must not be a CA" };
  for (const [c, name] of [[root, "root"], [tier, "tier"], [leaf, "task cert"]] as const) {
    if (!within(c)) return { ok: false, reason: `${name} is not valid at ${at.toISOString()}` };
  }
  return { ok: true };
}

// ── Renewal, subtasks, ledger, local revocation (notme-337d82, notme-9f84e6) ─

/**
 * The renewal proof — over the authority's shared binding, byte for byte. With
 * a generation it is the v2 binding; without one (a legacy tier.json) it is v1.
 */
export async function renewProof(
  privateKey: CryptoKey,
  spki: Uint8Array,
  iat: number,
  generation?: number,
): Promise<string> {
  const input = generation === undefined ? tierRenewalBinding(spki, iat) : tierRenewalBindingV2(spki, iat, generation);
  return b64url(new Uint8Array(await crypto.subtle.sign(ED25519, privateKey, input)));
}

/** A signed renewal request, persisted BEFORE it is sent so it can be resent byte for byte. */
export type PendingRenewal = { body: string; iat: number; generation: number };

export type RenewalResult = {
  certificate: string;
  expires_at: number;
  renew_until: number;
  authority: { epoch: number };
  generation: number;
};

/** The authority definitively refused a FIRST attempt (its JSON `{ error }`, 4xx). */
export class AuthorityRefusal extends Error {
  constructor(public reason: string) {
    super(reason);
  }
}

const STATE_LOST_TAIL = "run `task-cert enroll` to approve this machine again";
const stateLost = (why: string) => new Error(`renewal state lost (${why}) — ${STATE_LOST_TAIL}`);

/**
 * The client stops resending a little before the authority stops treating it
 * as a retry (RENEWAL_RETRY_WINDOW_S), so a resend never lands on the edge of
 * the window and is judged a fork.
 */
export const CLIENT_RESEND_WINDOW_S = RENEWAL_RETRY_WINDOW_S - RENEWAL_SKEW_S;

export const RENEW_FETCH_TIMEOUT_MS = 30_000;

// 4xx statuses that say "try again", not "no".
const TRANSIENT_4XX = new Set([408, 425, 429]);

/**
 * Renew the tier with no human, while the approval holds.
 *
 * A response can be lost after the authority has acted on the request. The
 * authority serves the EXACT same request again as a retry, but treats a
 * newly signed request at the old generation as a fork. So:
 *   - the signed request is saved (savePending) BEFORE the POST;
 *   - while one exists and is inside the client window it is resent verbatim,
 *     and nothing new is ever signed;
 *   - past the window it is not resent and not replaced: a human re-enrolls;
 *   - pending is cleared only on a definitive answer: a valid 2xx, or the
 *     authority's own JSON refusal of a FIRST attempt. A refusal of a RESEND
 *     keeps pending (clearing would let the next run re-sign at the old
 *     generation, which is a fork) and says the state is lost.
 *   - network errors, 5xx, 3xx, 408/425/429 and non-authority 4xx bodies
 *     (edge or HTML error pages) are not definitive and keep pending.
 * `persist` runs on success BEFORE clearPending, so the new tier is on disk
 * before the only copy of the request that can recover it is dropped.
 */
export async function renewTier(
  authority: string,
  key: { privateKey: CryptoKey; spki: Uint8Array; pem: string },
  opts: {
    generation?: number;
    pending?: PendingRenewal | null;
    savePending: (p: PendingRenewal) => void;
    /** Clear the pending request, but only if it is still THIS request (`body`). */
    clearPending: (body: string) => void | Promise<void>;
    persist?: (r: RenewalResult) => void;
    /**
     * Re-reads the generation after the request is reserved. A peer that completed in between
     * (overlapping holders after a sleep or clock jump) advanced it; signing at the old one is a fork.
     */
    currentGeneration?: () => Promise<number | undefined>;
    /** Abort the POST after this long; an aborted request is not definitive. */
    fetchTimeoutMs?: number;
  },
  fetchFn: typeof fetch = fetch,
): Promise<RenewalResult> {
  const now = Math.floor(Date.now() / 1000);
  const resend = !!opts.pending;
  let body: string;
  if (opts.pending) {
    if (now - opts.pending.iat > CLIENT_RESEND_WINDOW_S) {
      throw stateLost("a response never arrived within the retry window");
    }
    body = opts.pending.body;
  } else {
    const gen = opts.generation;
    body = JSON.stringify({
      public_key: key.pem,
      iat: now,
      proof: await renewProof(key.privateKey, key.spki, now, gen),
      ...(gen === undefined ? {} : { generation: gen }),
    });
    opts.savePending({ body, iat: now, generation: gen ?? 0 });
    if (opts.currentGeneration && (await opts.currentGeneration()) !== gen) {
      await opts.clearPending(body); // our own reservation, never sent
      throw new Error("another renewal completed meanwhile — try again");
    }
  }
  let sentGeneration = false;
  try {
    sentGeneration = "generation" in JSON.parse(body);
  } catch { /* unparseable body: no v2 expectation */ }

  const res = await fetchFn(`${authority}/cert/issuing-ca/renew`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
    signal: AbortSignal.timeout(opts.fetchTimeoutMs ?? RENEW_FETCH_TIMEOUT_MS),
  });
  const out = (await res.json().catch(() => null)) as any;

  if (res.status >= 200 && res.status < 300) {
    const valid =
      out && typeof out.certificate === "string" && out.certificate.length > 0 &&
      (!sentGeneration || (Number.isInteger(out.generation) && out.generation >= 0));
    if (!valid) throw new Error("renewal response invalid — kept the pending request to retry");
    opts.persist?.(out);
    await opts.clearPending(body);
    return out;
  }
  const definitive =
    res.status >= 400 && res.status < 500 && !TRANSIENT_4XX.has(res.status) && typeof out?.error === "string";
  if (!definitive) throw new Error(`renewal not answered by the authority (HTTP ${res.status}) — try again`);
  if (resend) throw stateLost(out.error);
  await opts.clearPending(body);
  throw new AuthorityRefusal(out.error);
}

// ── Renewal state on disk (notme-747cc7) ────────────────────────────────────

const PENDING = "renew-pending.json";
const LOCK = "renew.lock";
/** Far longer than a renewal's fetch timeout, so a live holder is never stolen from. */
export const LOCK_STALE_MS = 600_000;

const CLEARING = `${PENDING}.clear-`;
const clearingFiles = (dir: string): string[] => {
  try {
    return readdirSync(dir).filter((f) => f.startsWith(CLEARING));
  } catch (e: any) {
    if (e.code === "ENOENT") return [];
    throw e;
  }
};

/**
 * Read the pending request. Unreadable means the state is lost; it must never lead to signing.
 * A request renamed aside by clearOwnPending (mid-clear, or interrupted by a crash) still counts:
 * the path is tested FIRST, then the directory, so a reader that misses the path during a
 * rename (atomic) must find the renamed file.
 */
export function loadPending(dir: string): PendingRenewal | null {
  const p = join(dir, PENDING);
  if (!existsSync(p)) {
    if (clearingFiles(dir).length > 0) {
      throw stateLost("renewal state conflict — a pending renewal is mid-clear or was interrupted");
    }
    return null;
  }
  try {
    const v = JSON.parse(readFileSync(p, "utf8"));
    if (typeof v?.body !== "string" || !Number.isFinite(v.iat) || !Number.isFinite(v.generation)) throw new Error("shape");
    return v;
  } catch {
    throw stateLost("pending request unreadable");
  }
}

/** Remove the pending request, e.g. after a fresh enrolment makes it moot. */
export function removePending(dir: string): void {
  try { unlinkSync(join(dir, PENDING)); } catch { /* already gone */ }
}

/**
 * Remove the pending request only if it is THIS holder's request (its body,
 * byte for byte). A holder that was suspended past the lock's staleness may
 * wake to find a LATER holder's unknown-outcome request in place; deleting
 * that would let the next run sign anew at its generation, which is a fork.
 * So: rename the file to a name only we know (exactly one renamer wins),
 * compare, and unlink only on a match; otherwise link it back.
 */
export async function clearOwnPending(
  dir: string,
  body: string,
  o: { token?: string; /** test hook: runs before a peer's file is linked back */ beforeLinkBack?: () => void | Promise<void> } = {},
): Promise<void> {
  const path = join(dir, PENDING);
  const moved = `${path}.clear-${o.token ?? crypto.randomUUID()}-${Math.random().toString(36).slice(2)}`;
  try {
    renameSync(path, moved);
  } catch (e: any) {
    if (e.code === "ENOENT") return; // nothing pending
    throw e;
  }
  let mine = false;
  try {
    mine = JSON.parse(readFileSync(moved, "utf8"))?.body === body;
  } catch { /* unreadable: not provably ours, so keep it */ }
  if (mine) {
    unlinkSync(moved);
    return;
  }
  await o.beforeLinkBack?.();
  try {
    linkSync(moved, path);
  } catch (e: any) {
    // Two pending requests at once cannot arise legitimately; keep both for a human.
    if (e.code === "EEXIST") throw new Error(`renewal state conflict — run \`task-cert status\` (kept ${moved})`);
    throw e;
  }
  unlinkSync(moved);
}

/**
 * Write the pending request atomically AND exclusively: a private temp file,
 * then link() into place, which fails if the pending file already exists.
 */
export function savePendingExclusive(dir: string, p: PendingRenewal): void {
  const tmp = join(dir, `${PENDING}.${process.pid}.${Math.random().toString(36).slice(2)}`);
  writeFileSync(tmp, JSON.stringify(p), { mode: 0o600 });
  try {
    linkSync(tmp, join(dir, PENDING));
  } catch (e: any) {
    if (e.code === "EEXIST") throw new Error("another renewal already saved a request — try again");
    throw e;
  } finally {
    try { unlinkSync(tmp); } catch { /* best effort */ }
  }
}

export type LockOpts = { staleMs?: number; /** test hook: runs after a lock is judged stale, before it is stolen */ onStale?: () => void };

/**
 * One renewal at a time per directory. The lock file holds a random owner
 * token and is created atomically (temp file, then link(): EEXIST means held),
 * so a reader never sees a half-written lock. Whether it is stale is decided
 * ONLY by its mtime; an empty or unreadable lock is held. A stale lock is
 * stolen by rename() to a unique name, which succeeds for exactly one stealer.
 * Release unlinks only a lock that still carries the owner's token.
 */
export function acquireRenewLock(dir: string, o: LockOpts = {}): { token: string; release: () => void } {
  const path = join(dir, LOCK);
  const token = `${process.pid}-${crypto.randomUUID()}`;
  const busy = () => new Error("another renewal is in progress — try again in a moment");
  const tryTake = (): boolean => {
    const tmp = `${path}.tmp-${token}`;
    writeFileSync(tmp, token, { mode: 0o600 });
    try {
      linkSync(tmp, path);
      return true;
    } catch (e: any) {
      if (e.code === "EEXIST") return false;
      throw e;
    } finally {
      try { unlinkSync(tmp); } catch { /* best effort */ }
    }
  };
  if (!tryTake()) {
    let mtime: number;
    try {
      mtime = statSync(path).mtimeMs;
    } catch {
      // Released between our attempts: one more try, otherwise someone else has it.
      if (tryTake()) return lockHandle(path, token);
      throw busy();
    }
    if (Date.now() - mtime < (o.staleMs ?? LOCK_STALE_MS)) throw busy();
    o.onStale?.();
    const moved = `${path}.stale-${token}`;
    try {
      renameSync(path, moved);
    } catch {
      // Another stealer (or the holder) got there first.
      if (tryTake()) return lockHandle(path, token);
      throw busy();
    }
    // We may have moved a lock that was taken fresh after we looked. If so, put it back.
    let fresh = false;
    try { fresh = Date.now() - statSync(moved).mtimeMs < (o.staleMs ?? LOCK_STALE_MS); } catch { /* gone */ }
    if (fresh) {
      try { linkSync(moved, path); } catch { /* someone holds the lock now */ }
      try { unlinkSync(moved); } catch { /* best effort */ }
      throw busy();
    }
    try { unlinkSync(moved); } catch { /* best effort */ }
    if (!tryTake()) throw busy();
  }
  return lockHandle(path, token);
}

function lockHandle(path: string, token: string) {
  return {
    token,
    release: () => {
      try {
        if (readFileSync(path, "utf8") === token) unlinkSync(path);
      } catch { /* not ours, or already gone */ }
    },
  };
}

/**
 * renewTier backed by files in `dir`. EVERYTHING the renewal reads — the tier
 * state `load` returns (its generation) and the pending request — is read
 * UNDER the lock, so a renewal that waited behind another never signs at a
 * generation the other has already advanced.
 */
export async function renewTierInDir(
  dir: string,
  load: () => Promise<{ authority: string; key: { privateKey: CryptoKey; spki: Uint8Array; pem: string }; generation?: number }>,
  opts: { persist?: (r: RenewalResult) => void; fetchTimeoutMs?: number; lock?: LockOpts;
    /** test hooks */ beforeReserve?: () => void; beforeLinkBack?: () => void | Promise<void> },
  fetchFn: typeof fetch = fetch,
): Promise<RenewalResult> {
  const lock = acquireRenewLock(dir, opts.lock);
  try {
    const { authority, key, generation } = await load();
    return await renewTier(
      authority,
      key,
      {
        generation,
        pending: loadPending(dir),
        savePending: (p) => {
          opts.beforeReserve?.();
          savePendingExclusive(dir, p);
        },
        clearPending: (body) => clearOwnPending(dir, body, { token: lock.token, beforeLinkBack: opts.beforeLinkBack }),
        currentGeneration: async () => (await load()).generation,
        persist: opts.persist,
        fetchTimeoutMs: opts.fetchTimeoutMs,
      },
      fetchFn,
    );
  } finally {
    lock.release();
  }
}

const RENEWAL_BUSY = "a renewal is in progress — try again";

function acquireForEnrol(dir: string): ReturnType<typeof acquireRenewLock> {
  try {
    return acquireRenewLock(dir);
  } catch (e: any) {
    if (String(e?.message).includes("in progress")) throw new Error(RENEWAL_BUSY);
    throw e;
  }
}

/**
 * Fail fast BEFORE an enrolment starts if a renewal holds the lock, so a
 * passkey approval is never collected into a key that then cannot be saved.
 * (saveEnrolment still takes the lock itself: a renewal may start meanwhile.)
 */
export function assertNoRenewalInProgress(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  acquireForEnrol(dir).release();
}

/**
 * The whole enrolment, from key generation to saved tier. `log` receives the
 * lines a human needs to approve (URL, code, fingerprint).
 */
export async function enrollInDir(
  dir: string,
  authority: string,
  opts: { scopes?: string[]; log?: (line: string) => void; fetchFn?: typeof fetch; sleep?: (ms: number) => Promise<void> } = {},
): Promise<{ tier: any; root: string }> {
  const log = opts.log ?? (() => {});
  const fetchFn = opts.fetchFn ?? fetch;
  assertNoRenewalInProgress(dir);
  const key = await generateTierKey();
  const start = await startEnrolment(authority, key.pem, opts.scopes, fetchFn);
  log(`\nApprove this machine with your passkey:\n\n  ${start.verification_uri}\n`);
  log(`  code:        ${start.user_code}`);
  log(`  fingerprint: ${groupFingerprint(start.key_fingerprint)}`);
  log(`\nApprove only if the page shows the same fingerprint. Waiting (${start.expires_in}s)...`);
  const proof = await enrolProof(key.privateKey, key.spki, start.device_code);
  const tier = await pollEnrolment(authority, start.device_code, proof, {
    interval: start.interval,
    expiresIn: start.expires_in,
    fetchFn,
    sleep: opts.sleep,
  });
  const root = await (await fetchFn(`${authority}/.well-known/ca-bundle.pem`)).text();
  saveEnrolment(dir, {
    keyPem: await exportPrivateKeyPem(key.privateKey),
    tierPem: tier.certificate,
    rootPem: root,
    meta: {
      authority,
      identity: tier.identity,
      scopes: tier.scopes,
      expires_at: tier.expires_at,
      epoch: tier.authority.epoch,
      renew_until: tier.renew_until,
      generation: tier.generation ?? 0,
    },
  });
  return { tier, root };
}

/** Write a freshly enrolled tier. A new enrolment ends any pending renewal of the old one. */
export function saveEnrolment(
  dir: string,
  e: { keyPem: string; tierPem: string; rootPem: string; meta: Record<string, unknown> },
): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  // An in-flight renewal would overwrite this enrolment with its own result.
  const lock = acquireForEnrol(dir);
  try {
    writeFileSync(join(dir, "tier.key.pem"), e.keyPem, { mode: 0o600 });
    chmodSync(join(dir, "tier.key.pem"), 0o600);
    writeFileSync(join(dir, "tier.pem"), e.tierPem);
    writeFileSync(join(dir, "root.pem"), e.rootPem);
    writeFileSync(join(dir, "tier.json"), JSON.stringify(e.meta, null, 2));
    removePending(dir); // unconditional by design: a new enrolment makes any pending request moot
    for (const f of clearingFiles(dir)) { try { unlinkSync(join(dir, f)); } catch { /* already gone */ } }
  } finally {
    lock.release();
  }
}

/**
 * Is this task — or anything it derives from — locally revoked? Prefix match
 * on SEGMENT boundaries: revoking `build` revokes `build/compile`, never
 * `build2`, and never `build`'s ancestors.
 */
export function isRevokedTask(taskPath: string, revoked: readonly string[]): boolean {
  return revoked.some((r) => taskPath === r || taskPath.startsWith(`${r}/`));
}

/** Where a task's files live: one directory per task-path segment. */
export function taskOutDir(base: string, taskPath: string): string {
  return join(base, ...taskPath.split("/"));
}
