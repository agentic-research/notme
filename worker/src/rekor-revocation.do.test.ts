/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * rekor-revocation.do.test.ts — every POST /admin/revoke-epoch is submitted,
 * once, to Rekor as a root-signed DSSE statement, AFTER the revocation
 * commits, and a Rekor outage never touches the revocation (notme-8befcc).
 *
 * Runs under vitest.workers.rekor.config.mts: submission on, REKOR_URL a
 * reserved `.test` host that this file serves by stubbing global fetch (the DO
 * runs in this isolate, so its fetch is the stub). The stub behaves like
 * Rekor v1 where it matters: it verifies the DSSE signature against the PEM
 * verifier it was sent before accepting, answers 201 with {uuid: LogEntry},
 * and 409 + Location for an entry it already holds.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import worker from "../worker";
import { createSessionCookie } from "./auth/session";
import { type EpochHistory, verifyEpochHistorySignature } from "./epoch-history";
import {
  checkRevocationsAgainstLog,
  type DsseEnvelope,
  dssePae,
  type LoggedRevocation,
  type PublishedEpochRevocation,
  type RekorLogEntry,
  verifyRevocationStatement,
} from "./rekor-revocation";
import type { SigningAuthority } from "./signing-authority";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };
const REKOR_HOST = "rekor.notme.test";

const call = (path: string, init: RequestInit = {}) =>
  (worker.fetch as (r: Request, e: unknown) => Promise<Response>)(new Request(`${ORIGIN}${path}`, init), {
    ...env,
    ...LOCAL_ENV,
  });

const authority = () => env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));

type Doc = Omit<EpochHistory, "revocations"> & { revocations: PublishedEpochRevocation[] };

async function history(): Promise<Doc> {
  const res = await call("/.well-known/epochs.json");
  expect(res.status).toBe(200);
  return (await res.json()) as Doc;
}

async function adminCookie(): Promise<string> {
  const pid = crypto.randomUUID();
  await authority().createPrincipalWithCapabilities(pid, ["authorityManage"]);
  return createSessionCookie(
    { principalId: pid, scopes: ["authorityManage"], authMethod: "passkey" },
    await authority().getSessionSecret(),
  );
}

async function revoke(reason: string): Promise<{ ended: number }> {
  const before = (await history()).currentEpoch;
  const res = await call("/admin/revoke-epoch", {
    method: "POST",
    headers: { cookie: await adminCookie(), "content-type": "application/json" },
    body: JSON.stringify({ reason }),
  });
  expect(res.status, await res.clone().text()).toBe(200);
  return { ended: before };
}

const runAlarm = () =>
  runInDurableObject(authority(), async (instance) => {
    await (instance as unknown as SigningAuthority).alarm();
  });

/** Pretend `epoch`'s last attempt was long ago, so the alarm's backoff has elapsed. */
const ageAttempt = (epoch: number) =>
  runInDurableObject(authority(), async (_i, state) => {
    state.storage.sql.exec(
      "UPDATE epoch_revocations SET rekor_last_attempt_at = 0 WHERE epoch = ? AND rekor_last_attempt_at IS NOT NULL",
      epoch,
    );
  });

// ── the stub log ──────────────────────────────────────────────────────────

const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64 = (u: Uint8Array) => btoa(String.fromCharCode(...u));
const hex = (u: ArrayBuffer) => Array.from(new Uint8Array(u), (b) => b.toString(16).padStart(2, "0")).join("");

let mode: "ok" | "503" | "unreachable" = "ok";
/** Every POST the stub received, accepted or not. */
let posts: Array<{ envelope: DsseEnvelope; verifier: string }> = [];
/** What the stub logged, by uuid. */
let log = new Map<string, RekorLogEntry>();
let nextIndex = 5000;
let realFetch: typeof fetch;
/** The POSTs that carried `epoch`'s statement. Rows other tests left pending may be retried too. */
const postsFor = (epoch: number) =>
  posts.filter((p) => JSON.parse(atob(p.envelope.payload)).predicate.epoch === epoch);

async function stubRekor(req: Request): Promise<Response> {
  const url = new URL(req.url);
  if (mode === "unreachable") throw new TypeError("network connection lost");
  if (req.method === "GET") {
    const uuid = url.pathname.split("/").pop()!;
    const e = log.get(uuid);
    return e ? Response.json({ [uuid]: e }) : new Response("not found", { status: 404 });
  }
  if (url.pathname !== "/api/v1/log/entries") return new Response("no route", { status: 404 });
  const body = (await req.json()) as {
    kind: string;
    apiVersion: string;
    spec: { proposedContent: { envelope: string; verifiers: string[] } };
  };
  const envelope = JSON.parse(body.spec.proposedContent.envelope) as DsseEnvelope;
  const verifier = body.spec.proposedContent.verifiers[0]!;
  posts.push({ envelope, verifier });
  if (mode === "503") return new Response('{"code":503,"message":"unavailable"}', { status: 503 });
  if (body.kind !== "dsse" || body.apiVersion !== "0.0.1") return new Response("bad kind", { status: 400 });

  // As Rekor does: verify the envelope against the verifier it was given.
  const pem = new TextDecoder().decode(unb64(verifier));
  const spki = unb64(pem.replace(/-----[A-Z ]+-----|\n/g, ""));
  const key = await crypto.subtle.importKey("spki", spki, { name: "Ed25519" }, false, ["verify"]);
  const payload = unb64(envelope.payload);
  const ok = await crypto.subtle.verify("Ed25519", key, unb64(envelope.signatures[0]!.sig), dssePae(envelope.payloadType, payload));
  if (!ok) return new Response('{"code":400,"message":"signature verification failed"}', { status: 400 });

  const uuid = hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body.spec.proposedContent.envelope)));
  if (log.has(uuid)) {
    return new Response('{"code":409}', { status: 409, headers: { location: `/api/v1/log/entries/${uuid}` } });
  }
  const entry: RekorLogEntry = {
    logIndex: nextIndex++,
    integratedTime: Math.floor(Date.now() / 1000),
    logID: "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
    body: b64(
      new TextEncoder().encode(
        JSON.stringify({
          apiVersion: "0.0.1",
          kind: "dsse",
          spec: {
            envelopeHash: { algorithm: "sha256", value: uuid },
            payloadHash: { algorithm: "sha256", value: hex(await crypto.subtle.digest("SHA-256", payload)) },
            signatures: envelope.signatures.map((s) => ({ signature: s.sig, verifier })),
          },
        }),
      ),
    ),
  };
  log.set(uuid, entry);
  return Response.json({ [uuid]: entry }, { status: 201, headers: { location: `/api/v1/log/entries/${uuid}` } });
}

beforeEach(() => {
  mode = "ok";
  posts = [];
  realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input, init);
    if (new URL(req.url).hostname === REKOR_HOST) return stubRekor(req);
    return realFetch(input, init); // the no-network guard
  }) as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

/** The logged entry for a published revocation, as a verifier would fetch it. */
function loggedFor(r: PublishedEpochRevocation): LoggedRevocation {
  const e = log.get(r.rekorUuid!);
  if (!e || !r.statement) throw new Error(`epoch ${r.epoch} is not logged`);
  return { envelope: r.statement, entry: e };
}

// ── tests ─────────────────────────────────────────────────────────────────

describe("each revocation is submitted to Rekor exactly once (notme-8befcc)", () => {
  it("one POST per revocation, carrying that revocation; the alarm adds none", async () => {
    const a = await revoke("rekor once a");
    const b = await revoke("rekor once b");
    expect(postsFor(a.ended)).toHaveLength(1);
    expect(postsFor(b.ended)).toHaveLength(1);
    expect(JSON.parse(atob(postsFor(a.ended)[0]!.envelope.payload)).predicate.reason).toBe("rekor once a");
    await runAlarm();
    await ageAttempt(a.ended);
    await ageAttempt(b.ended);
    await runAlarm();
    expect(postsFor(a.ended)).toHaveLength(1);
    expect(postsFor(b.ended)).toHaveLength(1);
  });

  it("the published log index and uuid are Rekor's", async () => {
    const { ended } = await revoke("rekor index");
    const r = (await history()).revocations.find((x) => x.epoch === ended)!;
    const [uuid, entry] = [...log.entries()].at(-1)!;
    expect(r.rekorUuid).toBe(uuid);
    expect(r.rekorLogIndex).toBe(entry.logIndex);
    expect(r.rekorIntegratedTime).toBe(entry.integratedTime);
  });
});

describe("the statement (notme-8befcc)", () => {
  it("verifies under the root that signed epochs.json and says what epochs.json says", async () => {
    const { ended } = await revoke("statement verifies");
    const doc = await history();
    const root = await authority().getPublicKeyRawB64();
    expect(await verifyEpochHistorySignature(doc, root)).toBe(true);
    const r = doc.revocations.find((x) => x.epoch === ended)!;
    const v = await verifyRevocationStatement(r.statement!, root);
    expect(v.ok).toBe(true);
    if (!v.ok) return;
    const live = doc.epochs.find((e) => e.untilEpoch === null)!;
    expect(v.predicate).toMatchObject({ epoch: ended, revokedAt: r.revokedAt, reason: r.reason, rootKeyId: live.keyId });
    // The seqno reserved with the revocation is below every document signed since.
    expect(doc.seqno).toBeGreaterThan(v.predicate.historySeqno);
    // And it is the envelope Rekor was sent, unchanged.
    expect(postsFor(ended).at(-1)!.envelope).toEqual(r.statement);
  });
});

describe("a Rekor outage never touches the revocation (notme-8befcc)", () => {
  for (const outage of ["503", "unreachable"] as const) {
    it(`${outage}: the revocation commits and is published, signed and pending`, async () => {
      mode = outage;
      const before = await history();
      const { ended } = await revoke(`outage ${outage}`);
      const after = await history();
      expect(after.currentEpoch).toBe(before.currentEpoch + 1);
      const r = after.revocations.find((x) => x.epoch === ended)!;
      expect(r.reason).toBe(`outage ${outage}`);
      expect(r.statement).not.toBeNull();
      expect(r.rekorLogIndex).toBeNull();
      expect(r.rekorUuid).toBeNull();
    });
  }

  it("the alarm retries a pending revocation once its backoff has passed, and publishes the index", async () => {
    mode = "503";
    const { ended } = await revoke("retry me");
    expect(postsFor(ended)).toHaveLength(1);

    // Backoff: an alarm straight after the failure does not resubmit.
    mode = "ok";
    await runAlarm();
    expect(postsFor(ended)).toHaveLength(1);
    expect((await history()).revocations.find((x) => x.epoch === ended)!.rekorLogIndex).toBeNull();

    await ageAttempt(ended);
    await runAlarm();
    expect(postsFor(ended)).toHaveLength(2);
    const r = (await history()).revocations.find((x) => x.epoch === ended)!;
    expect(r.rekorLogIndex).toBe(log.get(r.rekorUuid!)!.logIndex);
  });

  it("a retry whose first answer was lost records the existing entry (409), not a second one", async () => {
    const { ended } = await revoke("lost answer");
    const uuid = (await history()).revocations.find((x) => x.epoch === ended)!.rekorUuid!;
    // Forget the answer, keep the entry: the next submission meets a 409.
    await runInDurableObject(authority(), async (_i, state) => {
      state.storage.sql.exec(
        "UPDATE epoch_revocations SET rekor_log_index = NULL, rekor_uuid = NULL, rekor_integrated_time = NULL, rekor_last_attempt_at = 0 WHERE epoch = ?",
        ended,
      );
    });
    const sizeBefore = log.size;
    await runAlarm();
    expect(log.size).toBe(sizeBefore);
    const r = (await history()).revocations.find((x) => x.epoch === ended)!;
    expect(r.rekorUuid).toBe(uuid);
    expect(r.rekorLogIndex).toBe(log.get(uuid)!.logIndex);
  });
});

describe("epochs.json is checked against the log (notme-8befcc)", () => {
  it("agrees with what was logged, and a re-signed history that disagrees is caught", async () => {
    await revoke("check against log");
    const doc = await history();
    const logged = doc.revocations.filter((r) => r.rekorUuid).map(loggedFor);
    expect(logged.length).toBeGreaterThan(0);
    expect(await checkRevocationsAgainstLog(doc, logged)).toMatchObject({ ok: true, problems: [] });

    // What the authority could sign but not log: a past with a revocation dropped or moved.
    const victim = doc.revocations.find((r) => r.rekorUuid)!;
    const dropped = { ...doc, revocations: doc.revocations.filter((r) => r !== victim) };
    expect((await checkRevocationsAgainstLog(dropped, logged)).problems).toContainEqual(
      expect.objectContaining({ epoch: victim.epoch, problem: "missing_from_history" }),
    );
    const moved = {
      ...doc,
      revocations: doc.revocations.map((r) => (r === victim ? { ...r, revokedAt: r.revokedAt + 86400 } : r)),
    };
    expect((await checkRevocationsAgainstLog(moved, logged)).problems).toContainEqual(
      expect.objectContaining({ epoch: victim.epoch, problem: "differs_from_log" }),
    );
  });
});
