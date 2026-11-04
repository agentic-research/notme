// rekor-revocation.test.ts — the root-signed DSSE statement of a revocation
// and the check of epochs.json against what the log holds (notme-8befcc).
//
// Pure-function tests: the statement's signing input (DSSE PAE) and its golden
// fixture in schema/fixtures/ (the bytes a Go verifier such as signet
// vendors), its signature under the fixture root, the Rekor v1 `dsse` request
// and response shapes, and the verifier helper that catches an epochs.json
// whose revocations disagree with the logged statements. The Durable Object
// path (submit after commit, retry from the alarm) is
// rekor-revocation.do.test.ts.

import { createHash, createPrivateKey, sign as edSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { assertFixtures } from "../../../scripts/fixture-manifest";
import type { EpochHistory } from "../epoch-history";
import {
  checkRevocationsAgainstLog,
  type DsseEnvelope,
  dssePae,
  EPOCH_REVOCATION_PREDICATE_TYPE,
  IN_TOTO_PAYLOAD_TYPE,
  IN_TOTO_STATEMENT_TYPE,
  type LoggedRevocation,
  parseRekorEntry,
  rekorDsseProposedEntry,
  revocationStatementPayload,
  signRevocationStatement,
  verifyRevocationStatement,
} from "../rekor-revocation";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "../../../schema/fixtures");

/** The fixtures' signing root (seed 0x00..0x1f), as in epoch-history.test.ts. */
const FIXTURE_ROOT_PUB_B64 = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=";
const FIXTURE_ROOT_KEY_ID = "a050837d85070582ccf7394b0988847c";

function load(): { envelope: DsseEnvelope; pae: Uint8Array; history: EpochHistory } {
  // No fixture byte is trusted until every file matches SHA256SUMS (notme-1629fe).
  assertFixtures(FIXTURES);
  const envelope = JSON.parse(
    readFileSync(join(FIXTURES, "revocationstatement-epoch1.json"), "utf-8"),
  ) as DsseEnvelope;
  const hex = readFileSync(join(FIXTURES, "revocationstatement-epoch1.expected.hex"), "utf-8").trim();
  const history = JSON.parse(readFileSync(join(FIXTURES, "epochhistory-revoked.json"), "utf-8")) as EpochHistory;
  return { envelope, pae: new Uint8Array(Buffer.from(hex, "hex")), history };
}

const payloadOf = (e: DsseEnvelope) => new Uint8Array(Buffer.from(e.payload, "base64"));
const sha256Hex = (b: Uint8Array | string) => createHash("sha256").update(b).digest("hex");

/** What Rekor answers for an accepted dsse entry: the body it stores, base64. */
function rekorEntryFor(envelope: DsseEnvelope, logIndex: number, overrides: { payloadHash?: string } = {}) {
  const body = {
    apiVersion: "0.0.1",
    kind: "dsse",
    spec: {
      envelopeHash: { algorithm: "sha256", value: sha256Hex(JSON.stringify(envelope)) },
      payloadHash: { algorithm: "sha256", value: overrides.payloadHash ?? sha256Hex(payloadOf(envelope)) },
      signatures: envelope.signatures.map((s) => ({ signature: s.sig, verifier: "dW51c2Vk" })),
    },
  };
  return {
    logIndex,
    integratedTime: 1767232805,
    logID: "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
    body: Buffer.from(JSON.stringify(body)).toString("base64"),
  };
}

const logged = (envelope: DsseEnvelope, logIndex = 7): LoggedRevocation => ({
  envelope,
  entry: rekorEntryFor(envelope, logIndex),
});

describe("the DSSE signing input (notme-8befcc)", () => {
  it("is the DSSE v1 PAE, byte for byte against the spec's own vector", () => {
    // github.com/secure-systems-lab/dsse protocol.md, "Test vector".
    const pae = dssePae("http://example.com/HelloWorld", new TextEncoder().encode("hello world"));
    expect(new TextDecoder().decode(pae)).toBe("DSSEv1 29 http://example.com/HelloWorld 11 hello world");
  });

  it("counts payload length in BYTES, not characters", () => {
    const pae = dssePae("t", new TextEncoder().encode("é"));
    expect(new TextDecoder().decode(pae)).toBe("DSSEv1 1 t 2 é");
  });

  it("matches the golden fixture's .bin", () => {
    const { envelope, pae } = load();
    expect(dssePae(envelope.payloadType, payloadOf(envelope))).toEqual(pae);
  });

  it("the fixture payload is exactly what revocationStatementPayload emits for its predicate", async () => {
    const { envelope } = load();
    const stmt = JSON.parse(Buffer.from(payloadOf(envelope)).toString("utf-8"));
    expect(await revocationStatementPayload(stmt.predicate, FIXTURE_ROOT_PUB_B64)).toEqual(payloadOf(envelope));
  });

  it("never starts like any other root-signed input (domain separation)", () => {
    // The root also signs canonical CBOR maps (bundle, epoch history: first
    // byte 0xa0-0xbb), DER (0x30) and JWT signing inputs ("eyJ"). PAE starts
    // "DSSEv1 " and names its payload type, so none can stand in for it.
    const { pae } = load();
    expect(new TextDecoder().decode(pae.subarray(0, 7))).toBe("DSSEv1 ");
    expect(pae[0]).not.toBe(0x30);
    expect(pae[0] >= 0xa0 && pae[0] <= 0xbb).toBe(false);
  });
});

describe("the revocation statement (notme-8befcc)", () => {
  it("is an in-toto Statement v1 whose subject is the root key that signed it", async () => {
    const { envelope } = load();
    expect(envelope.payloadType).toBe(IN_TOTO_PAYLOAD_TYPE);
    const stmt = JSON.parse(Buffer.from(payloadOf(envelope)).toString("utf-8"));
    expect(stmt._type).toBe(IN_TOTO_STATEMENT_TYPE);
    expect(stmt.predicateType).toBe(EPOCH_REVOCATION_PREDICATE_TYPE);
    expect(stmt.subject).toEqual([
      {
        name: `notme-authority-root:${FIXTURE_ROOT_KEY_ID}`,
        digest: { sha256: sha256Hex(Buffer.from(FIXTURE_ROOT_PUB_B64, "base64")) },
      },
    ]);
    expect(Object.keys(stmt.predicate)).toEqual(["epoch", "revokedAt", "reason", "historySeqno", "rootKeyId"]);
  });

  it("verifies under the fixture root and agrees with the epochhistory-revoked fixture", async () => {
    const { envelope, history } = load();
    const v = await verifyRevocationStatement(envelope, FIXTURE_ROOT_PUB_B64);
    expect(v.ok).toBe(true);
    if (!v.ok) return;
    const r = history.revocations[0]!;
    expect(v.predicate).toEqual({
      epoch: r.epoch,
      revokedAt: r.revokedAt,
      reason: r.reason,
      historySeqno: 41,
      rootKeyId: FIXTURE_ROOT_KEY_ID,
    });
    // seqno 42 > historySeqno 41: that document must carry the revocation.
    expect(history.seqno).toBeGreaterThan(v.predicate.historySeqno);
  });

  it("does not verify under another key, or with any byte of the payload changed", async () => {
    const { envelope } = load();
    expect((await verifyRevocationStatement(envelope, Buffer.alloc(32, 7).toString("base64"))).ok).toBe(false);
    const p = payloadOf(envelope);
    for (const i of [0, Math.floor(p.length / 2), p.length - 1]) {
      const q = new Uint8Array(p);
      q[i] ^= 0x01;
      const forged = { ...envelope, payload: Buffer.from(q).toString("base64") };
      expect((await verifyRevocationStatement(forged, FIXTURE_ROOT_PUB_B64)).ok, `byte ${i}`).toBe(false);
    }
  });

  it("refuses a validly signed envelope that is not a revocation statement", async () => {
    const { envelope } = load();
    // Same signature, payload type swapped: PAE covers the type, so it fails.
    expect((await verifyRevocationStatement({ ...envelope, payloadType: "application/json" }, FIXTURE_ROOT_PUB_B64)).ok).toBe(false);
  });
});

describe("Rekor v1 dsse entry (notme-8befcc)", () => {
  it("proposes kind dsse 0.0.1 with the envelope as a string and the root as a PEM verifier", () => {
    const { envelope } = load();
    const entry = rekorDsseProposedEntry(envelope, FIXTURE_ROOT_PUB_B64) as {
      kind: string;
      apiVersion: string;
      spec: { proposedContent: { envelope: string; verifiers: string[] } };
    };
    expect(entry.kind).toBe("dsse");
    expect(entry.apiVersion).toBe("0.0.1");
    expect(JSON.parse(entry.spec.proposedContent.envelope)).toEqual(envelope);
    expect(entry.spec.proposedContent.verifiers).toHaveLength(1);
    const pem = Buffer.from(entry.spec.proposedContent.verifiers[0]!, "base64").toString("utf-8");
    expect(pem).toMatch(/^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+\n-----END PUBLIC KEY-----\n$/);
    const der = Buffer.from(pem.replace(/-----[A-Z ]+-----|\n/g, ""), "base64");
    // RFC 8410 Ed25519 SPKI: fixed 12-byte prefix, then the raw key.
    expect(der.subarray(0, 12).toString("hex")).toBe("302a300506032b6570032100");
    expect(der.subarray(12).toString("base64")).toBe(FIXTURE_ROOT_PUB_B64);
  });

  it("reads uuid, logIndex and integratedTime from Rekor's answer", async () => {
    const { envelope } = load();
    const uuid = "24296fb24b8ad77a" + "ab".repeat(32);
    const r = await parseRekorEntry({ [uuid]: rekorEntryFor(envelope, 1234567) }, envelope);
    expect(r).toEqual({ ok: true, uuid, logIndex: 1234567, integratedTime: 1767232805 });
  });

  it("refuses an answer that logged some other payload", async () => {
    const { envelope } = load();
    const uuid = "ab".repeat(32);
    const r = await parseRekorEntry({ [uuid]: rekorEntryFor(envelope, 1, { payloadHash: "00".repeat(32) }) }, envelope);
    expect(r.ok).toBe(false);
  });
});

describe("epochs.json against the log (notme-8befcc)", () => {
  it("agrees: the fixture history and the logged fixture statement", async () => {
    const { envelope, history } = load();
    const r = await checkRevocationsAgainstLog(history, [logged(envelope)]);
    expect(r).toEqual({ ok: true, problems: [], unlogged: [] });
  });

  it("a history that DROPS a logged revocation is caught", async () => {
    const { envelope, history } = load();
    const r = await checkRevocationsAgainstLog({ ...history, revocations: [] }, [logged(envelope)]);
    expect(r.ok).toBe(false);
    expect(r.problems).toEqual([expect.objectContaining({ epoch: 1, problem: "missing_from_history" })]);
  });

  it("a history that MOVES a revocation's time, or rewrites its reason, is caught", async () => {
    const { envelope, history } = load();
    for (const change of [{ revokedAt: history.revocations[0]!.revokedAt + 3600 }, { reason: "routine rotation" }]) {
      const doc = { ...history, revocations: history.revocations.map((x) => ({ ...x, ...change })) };
      const r = await checkRevocationsAgainstLog(doc, [logged(envelope)]);
      expect(r.ok, JSON.stringify(change)).toBe(false);
      expect(r.problems).toEqual([expect.objectContaining({ epoch: 1, problem: "differs_from_log" })]);
    }
  });

  it("a history older than the statement may lack it, but may not contradict it", async () => {
    const { envelope, history } = load();
    const older = { ...history, seqno: 41, revocations: [] };
    expect((await checkRevocationsAgainstLog(older, [logged(envelope)])).ok).toBe(true);
    const contradicts = {
      ...history,
      seqno: 41,
      revocations: history.revocations.map((x) => ({ ...x, revokedAt: x.revokedAt + 1 })),
    };
    expect((await checkRevocationsAgainstLog(contradicts, [logged(envelope)])).ok).toBe(false);
  });

  it("a revocation nobody logged is reported, and fails only when the log is required", async () => {
    const { history } = load();
    const r = await checkRevocationsAgainstLog(history, []);
    expect(r).toEqual({ ok: true, problems: [], unlogged: [1] });
    const strict = await checkRevocationsAgainstLog(history, [], { requireLogged: true });
    expect(strict.ok).toBe(false);
    expect(strict.problems).toEqual([expect.objectContaining({ epoch: 1, problem: "not_logged" })]);
  });

  it("a log entry that does not match its envelope is not evidence for anything", async () => {
    const { envelope, history } = load();
    const bad: LoggedRevocation = { envelope, entry: rekorEntryFor(envelope, 7, { payloadHash: "00".repeat(32) }) };
    const r = await checkRevocationsAgainstLog(history, [bad], { requireLogged: true });
    expect(r.problems.map((p) => p.problem).sort()).toEqual(["bad_log_entry", "not_logged"]);
  });

  it("a statement no key in the history signed is not evidence for anything", async () => {
    const { envelope, history } = load();
    const keyless = { ...history, epochs: history.epochs.filter((e) => e.keyId !== FIXTURE_ROOT_KEY_ID) };
    const r = await checkRevocationsAgainstLog(keyless, [logged(envelope)]);
    expect(r.problems).toEqual([expect.objectContaining({ problem: "bad_log_entry" })]);
  });

  it("two logged statements that disagree about one epoch are caught (the root signed two pasts)", async () => {
    const { envelope, history } = load();
    const v = await verifyRevocationStatement(envelope, FIXTURE_ROOT_PUB_B64);
    if (!v.ok) throw new Error("fixture does not verify");
    const seed = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
    const priv = createPrivateKey({
      key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
      format: "der",
      type: "pkcs8",
    });
    const second = await signRevocationStatement(
      { ...v.predicate, revokedAt: v.predicate.revokedAt + 60 },
      FIXTURE_ROOT_PUB_B64,
      async (m) => edSign(null, m, priv),
    );
    const r = await checkRevocationsAgainstLog(history, [logged(envelope, 7), logged(second, 9)]);
    expect(r.problems).toEqual([expect.objectContaining({ epoch: 1, problem: "conflicting_log_entries" })]);
  });

  it("an unsigned rekorLogIndex pointing elsewhere is reported", async () => {
    const { envelope, history } = load();
    const doc = { ...history, revocations: history.revocations.map((x) => ({ ...x, rekorLogIndex: 8 })) };
    const r = await checkRevocationsAgainstLog(doc, [logged(envelope, 7)]);
    expect(r.problems).toEqual([expect.objectContaining({ epoch: 1, problem: "log_index_mismatch" })]);
  });
});
