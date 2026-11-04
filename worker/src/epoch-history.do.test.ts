/// <reference types="@cloudflare/vitest-plugin/types" />
/**
 * epoch-history.do.test.ts — /.well-known/epochs.json is signed by the root
 * and says what ended each epoch (notme-6a4f23, ADR-019 D7).
 *
 * The document listed every key and its epoch span, unsigned, and could not
 * tell a key ROTATED out (old signatures stay good) from an epoch REVOKED by
 * POST /admin/revoke-epoch (signatures from the revocation on are bad). A
 * verifier checking an expired cert as of a trusted time needs exactly that
 * difference, and needs it from a document whoever serves it cannot edit.
 *
 * Runs under vitest.workers.config.mts (`pnpm test:do`).
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../worker";
import { createSessionCookie } from "./auth/session";
import { type EpochHistory, verifyEpochHistorySignature } from "./epoch-history";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };

const call = (path: string, init: RequestInit = {}) =>
  (worker.fetch as (r: Request, e: unknown) => Promise<Response>)(new Request(`${ORIGIN}${path}`, init), {
    ...env,
    ...LOCAL_ENV,
  });

const authority = (name = "default") => env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(name));

async function fetchHistory(): Promise<EpochHistory> {
  const res = await call("/.well-known/epochs.json");
  expect(res.status).toBe(200);
  return (await res.json()) as EpochHistory;
}

async function adminCookie(): Promise<string> {
  const pid = crypto.randomUUID();
  await authority().createPrincipalWithCapabilities(pid, ["authorityManage"]);
  return createSessionCookie(
    { principalId: pid, scopes: ["authorityManage"], authMethod: "passkey" },
    await authority().getSessionSecret(),
  );
}

const revoke = (cookie: string, body?: unknown) =>
  call("/admin/revoke-epoch", {
    method: "POST",
    headers: { cookie, ...(body === undefined ? {} : { "content-type": "application/json" }) },
    ...(body === undefined ? {} : { body: typeof body === "string" ? body : JSON.stringify(body) }),
  });

const now = () => Math.floor(Date.now() / 1000);

describe("epochs.json is signed by the root (notme-6a4f23)", () => {
  it("verifies under the authority's root key", async () => {
    const doc = await fetchHistory();
    const root = await authority().getPublicKeyRawB64();
    expect(typeof doc.signature).toBe("string");
    expect(await verifyEpochHistorySignature(doc, root)).toBe(true);
  });

  it("a tampered document fails verification", async () => {
    const doc = await fetchHistory();
    const root = await authority().getPublicKeyRawB64();
    const forged: EpochHistory[] = [
      { ...doc, seqno: doc.seqno + 1 },
      { ...doc, currentEpoch: doc.currentEpoch + 1 },
      { ...doc, revocations: [...doc.revocations, { epoch: doc.currentEpoch, revokedAt: 1, reason: "forged" }] },
      { ...doc, epochs: doc.epochs.map((e) => ({ ...e, retiredAt: 12345 })) },
    ];
    for (const f of forged) expect(await verifyEpochHistorySignature(f, root)).toBe(false);
  });

  it("keeps every existing epochs entry field exactly as it was", async () => {
    const doc = await fetchHistory();
    expect(doc.epochs).toEqual(await authority().listEpochKeys());
    for (const e of doc.epochs) {
      expect(Object.keys(e).sort()).toEqual(["epoch", "keyId", "publicRawB64", "retiredAt", "untilEpoch"]);
    }
  });

  it("seqno strictly increases with every signed document, and issuedAt never goes back", async () => {
    const stub = authority("epoch-history-seqno");
    const docs = [];
    for (let i = 0; i < 4; i++) docs.push(await stub.getSignedEpochHistory());
    for (let i = 1; i < docs.length; i++) {
      expect(docs[i]!.seqno).toBeGreaterThan(docs[i - 1]!.seqno);
      expect(docs[i]!.issuedAt).toBeGreaterThanOrEqual(docs[i - 1]!.issuedAt);
    }
    // And across the levers that change the document.
    const beforeLevers = docs.at(-1)!.seqno;
    await stub.rotate();
    await stub.revokeEpoch("seqno test");
    expect((await stub.getSignedEpochHistory()).seqno).toBeGreaterThan(beforeLevers);
  });
});

describe("what ended an epoch: revokedAt vs retiredAt (notme-6a4f23)", () => {
  it("POST /admin/revoke-epoch records revokedAt and the reason for the epoch it ended", async () => {
    const cookie = await adminCookie();
    const before = await fetchHistory();
    const t0 = now();
    const res = await revoke(cookie, { reason: "key compromise suspected" });
    expect(res.status, await res.clone().text()).toBe(200);
    const t1 = now();

    const after = await fetchHistory();
    expect(after.currentEpoch).toBe(before.currentEpoch + 1);
    const r = after.revocations.find((x) => x.epoch === before.currentEpoch);
    expect(r).toBeDefined();
    expect(r!.reason).toBe("key compromise suspected");
    expect(r!.revokedAt).toBeGreaterThanOrEqual(t0);
    expect(r!.revokedAt).toBeLessThanOrEqual(t1);
    // Revocation is about the epoch, not a key: no key was retired by it.
    expect(after.epochs.filter((e) => e.retiredAt !== null)).toEqual(
      before.epochs.filter((e) => e.retiredAt !== null),
    );
  });

  it("a revoke with no body records reason \"unspecified\"", async () => {
    const cookie = await adminCookie();
    const before = await fetchHistory();
    expect((await revoke(cookie)).status).toBe(200);
    const after = await fetchHistory();
    expect(after.revocations.find((x) => x.epoch === before.currentEpoch)?.reason).toBe("unspecified");
  });

  it("refuses an unusable reason with 400 and moves nothing", async () => {
    const cookie = await adminCookie();
    const before = await fetchHistory();
    for (const body of [{ reason: "x".repeat(201) }, { reason: "line\nbreak" }, { reason: 7 }, { reason: "  " }, "{not json"]) {
      const res = await revoke(cookie, body);
      expect(res.status, JSON.stringify(body)).toBe(400);
    }
    const after = await fetchHistory();
    expect(after.currentEpoch).toBe(before.currentEpoch);
    expect(after.revocations).toEqual(before.revocations);
  });

  it("a rotation sets retiredAt on the outgoing key and records no revocation", async () => {
    const stub = authority("epoch-history-rotate");
    const before = await stub.getSignedEpochHistory();
    const outgoing = before.epochs.find((e) => e.untilEpoch === null)!;
    expect(outgoing.retiredAt).toBeNull();

    await stub.rotate();
    const after = await stub.getSignedEpochHistory();

    expect(after.currentEpoch).toBe(before.currentEpoch);
    expect(after.revocations).toEqual(before.revocations);
    const retired = after.epochs.find((e) => e.keyId === outgoing.keyId)!;
    expect(retired.retiredAt).toBeTypeOf("number");
    expect(retired.untilEpoch).toBe(before.currentEpoch);
  });

  it("revokeEpoch() on the authority records the reason, signed into the next document", async () => {
    const stub = authority("epoch-history-revoke-rpc");
    const before = await stub.getSignedEpochHistory();
    await stub.revokeEpoch("rpc reason");
    const after = await stub.getSignedEpochHistory();
    expect(after.revocations).toEqual([
      ...before.revocations,
      { epoch: before.currentEpoch, revokedAt: expect.any(Number), reason: "rpc reason" },
    ]);
    expect(await verifyEpochHistorySignature(after, await stub.getPublicKeyRawB64())).toBe(true);
  });
});
