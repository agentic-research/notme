/// <reference types="@cloudflare/vitest-plugin/types" />
/**
 * receipt-signer.do.test.ts — receipt signing against a REAL SigningAuthority
 * in REAL workerd (ADR-014).
 *
 * The unit suite proves the validator refuses malformed and cross-protocol
 * input. It cannot prove the two things that only exist end-to-end:
 *
 *   1. The signature actually VERIFIES against the authority's published
 *      Ed25519 key, over the bytes an Interlace verifier would recompute. A
 *      validator that is correct and a signer that signs the wrong buffer
 *      both pass their own tests.
 *   2. `actor_fp` and `epoch` are derived from real authority state, so a
 *      caller cannot assert either.
 */

import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { Encoder } from "cbor-x";
import { commitmentVector } from "./__tests__/helpers/commitment-vector";
import { encodeCanonicalMap, type CborValue } from "./receipts/canonical-cbor";
import type { SigningAuthority } from "./signing-authority";
import { ReceiptSigner } from "../worker";

const cbor = new Encoder({
  mapsAsObjects: false,
  useRecords: false,
  tagUint8Array: false,
});

function authority() {
  return env.SIGNING_AUTHORITY.get(
    env.SIGNING_AUTHORITY.idFromName("receipt-test"),
  );
}

/**
 * Build a commitment from the authority's OWN facts.
 *
 * An earlier draft of this test discovered the epoch by parsing it out of a
 * rejection message. That is the shape of a missing API, not a clever test —
 * and `getReceiptFacts` now exists partly because writing this made the gap
 * obvious: cloister would have had the same problem, sourcing actor_fp and
 * epoch from .well-known and drifting on rotation.
 */
/**
 * Spec-built commitment bytes. NOT encoded with cbor-x: a fixture built by the
 * same encoder the validator re-encodes with is a fixed point that any
 * self-consistent encoder passes, including a wrong one.
 */
function commitment(
  facts: { actorFp: Uint8Array; epoch: number },
  overrides: Partial<{ status: number; timestampMs: number }> = {},
) {
  return commitmentVector({
    actorFp: facts.actorFp,
    epoch: facts.epoch,
    timestampMs: overrides.timestampMs ?? Date.now(),
    status: overrides.status,
  });
}

describe("receipt signing — real SigningAuthority (ADR-014)", () => {
  it("produces a signature that verifies against the authority's published key", async () => {
    // The end-to-end property every Interlace verifier depends on: recompute
    // the commitment bytes, resolve A's pubkey, check the signature. A correct
    // validator and a signer that signs the wrong buffer would each pass their
    // own tests; only this catches the pair being wrong together.
    const stub = authority();
    const facts = await stub.getReceiptFacts();
    const bytes = commitment(facts);

    const res = await stub.signReceiptCommitment(bytes);
    expect(res.ok, res.ok ? "" : `${res.code}: ${res.message}`).toBe(true);
    if (!res.ok) return;
    expect(res.epoch).toBe(facts.epoch);

    const jwk = await stub.getPublicKeyJwk();
    const verifyKey = await crypto.subtle.importKey(
      "jwk",
      jwk as JsonWebKey,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    // Verified against the key published at /.well-known/jwks.json — the one
    // a third party actually resolves — not against an internal handle.
    expect(
      await crypto.subtle.verify(
        { name: "Ed25519" },
        verifyKey,
        res.signature,
        bytes,
      ),
    ).toBe(true);
  });

  it("refuses a commitment claiming a different actor", async () => {
    // Otherwise a caller mints receipts attributed to another actor, signed
    // by this authority's key.
    const stub = authority();
    const facts = await stub.getReceiptFacts();
    const res = await stub.signReceiptCommitment(
      commitmentVector({
        actorFp: new Uint8Array(32).fill(0xff),
        epoch: facts.epoch,
        timestampMs: Date.now(),
      }),
    );
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.code).toBe("ACTOR_FP_MISMATCH");
  });

  it("refuses a commitment claiming a different epoch", async () => {
    // Otherwise a caller pins the receipt to a retired key epoch, changing
    // which public key a verifier resolves it against.
    const stub = authority();
    const facts = await stub.getReceiptFacts();
    const res = await stub.signReceiptCommitment(
      commitmentVector({
        actorFp: facts.actorFp,
        epoch: facts.epoch + 1,
        timestampMs: Date.now(),
      }),
    );
    expect(res.ok).toBe(false);
    if (res.ok) return;
    // The code cloister branches on to re-read receiptFacts().
    expect(res.code).toBe("EPOCH_MISMATCH");
  });

  it("refuses a backdated or postdated timestamp against the authority's own clock", async () => {
    // notme-ad2a7a, at the real boundary. The unit suite injects nowMs; this
    // proves the DO actually supplies its clock rather than anything the
    // caller sent. Otherwise a compromised binding holder backfills a
    // fabricated history of validly-signed receipts across years.
    const stub = authority();
    const facts = await stub.getReceiptFacts();
    for (const timestampMs of [0, Date.now() - 86_400_000, Date.now() + 86_400_000]) {
      const res = await stub.signReceiptCommitment(
        commitment(facts, { timestampMs }),
      );
      expect(res.ok, `timestamp_ms=${timestampMs} was signed`).toBe(false);
      if (res.ok) return;
      expect(res.code).toBe("TIMESTAMP_OUT_OF_RANGE");
    }
  });

  it("refuses an X.509 TBSCertificate body at the real boundary", async () => {
    // The forgery ADR-014 exists to prevent, asserted where it would actually
    // happen rather than only against the validator in isolation.
    const stub = authority();
    const der = new Uint8Array([0x30, 0x82, 0x01, 0x0a, 0x02, 0x01, 0x02]);
    const res = await stub.signReceiptCommitment(der);
    expect(res.ok).toBe(false);
  });

  it("refuses non-canonical CBOR that decodes to a valid commitment", async () => {
    // The subtle one: structurally valid, but the bytes differ from the
    // canonical encoding, so a caller could carry chosen layout into the
    // signature.
    const stub = authority();
    const facts = await stub.getReceiptFacts();
    const scrambled = new Map<string, unknown>([
      ["timestamp_ms", Date.now()],
      ["nonce", new Uint8Array(16).fill(0x11)],
      ["epoch", facts.epoch],
      ["actor_fp", facts.actorFp],
      ["status", 200],
      ["body_hash", new Uint8Array(32).fill(0xbb)],
      ["headers_hash", new Uint8Array(32).fill(0xcc)],
      ["request_hash", new Uint8Array(32).fill(0xdd)],
    ]);
    const res = await stub.signReceiptCommitment(
      new Uint8Array(cbor.encode(scrambled)),
    );
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.code).toBe("NOT_CANONICAL");
  });

  it("returns only a signature and an epoch — never key material", async () => {
    const stub = authority();
    const facts = await stub.getReceiptFacts();
    const out = await stub.signReceiptCommitment(commitment(facts));
    expect(out.ok).toBe(true);
    expect(Object.keys(out).sort()).toEqual(["epoch", "ok", "signature"]);
  });
});

/**
 * A nine-key commitment from the authority's own facts, carrying `delegation`.
 * Built with encodeCanonicalMap (as receipt-delegation.test.ts does): the
 * hand vector has no ninth key, and the refusal below fires before the
 * canonical-bytes check, so the encoder is not what is under test.
 */
function nineKeyCommitment(facts: { actorFp: Uint8Array; epoch: number }, delegation: Uint8Array) {
  const d = (fill: number) => new Uint8Array(32).fill(fill);
  const entries: Array<[string, CborValue]> = [
    ["epoch", { uint: facts.epoch }],
    ["nonce", { bytes: new Uint8Array(16).fill(0x11) }],
    ["status", { uint: 200 }],
    ["actor_fp", { bytes: facts.actorFp }],
    ["body_hash", { bytes: d(0xbb) }],
    ["delegation", { bytes: delegation }],
    ["headers_hash", { bytes: d(0xcc) }],
    ["request_hash", { bytes: d(0xdd) }],
    ["timestamp_ms", { uint: Date.now() }],
  ];
  return encodeCanonicalMap(entries);
}

// THE GAP (notme-c0db9b). receipt-delegation.test.ts proves the validator's
// handling of the optional ninth key, `delegation`, but every case there
// hands validateCommitment a facts object carrying a delegation, a shape the
// production entry point never builds. signReceiptCommitment passes only
// actorFp, epoch and nowMs, and ReceiptSigner.signReceipt receives only the
// commitment bytes, so there is no presented credential to derive a
// delegation from. Every nine-key commitment is therefore refused. That is
// production's behaviour today, pinned so it cannot be read as "inert
// pending cloister" (ADR-014, "The optional ninth key").
describe("receipt delegation through the production entry point (notme-c0db9b)", () => {
  const DELEGATION = new TextEncoder().encode(
    "wimse://notme.bot/principal/11111111-1111-1111-1111-111111111111/" + "a".repeat(64) + "/task-1",
  );

  it("refuses every nine-key commitment: no producer derives a delegation", async () => {
    const stub = authority();
    const facts = await stub.getReceiptFacts();
    // The same request without the ninth key signs, so the refusal is the
    // delegation and nothing else.
    expect((await stub.signReceiptCommitment(commitment(facts))).ok).toBe(true);
    const res = await stub.signReceiptCommitment(nineKeyCommitment(facts, DELEGATION));
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.code).toBe("DELEGATION_MISMATCH");
    expect(res.message).toMatch(/derived none/);
  });

  // The desired end state, under the repo's gap convention (`it.fails` marks
  // a gap, not a bug). When a producer passes facts.delegation from a
  // verified credential, this goes red: drop `.fails`, and replace the
  // refusal test above with one driving the credential through the entry
  // point.
  it.fails("signs a nine-key commitment carrying the delegation the authority derived", async () => {
    const stub = authority();
    const facts = await stub.getReceiptFacts();
    const res = await stub.signReceiptCommitment(nineKeyCommitment(facts, DELEGATION));
    expect(res.ok).toBe(true);
  });
});

describe("ReceiptSigner.epochPublicKey — epochs cloister never observed (notme-a0cff4)", () => {
  // Through the ENTRYPOINT, not the DO stub: the gap was that ReceiptSigner,
  // the one binding cloister holds, could not hand over a retired key.
  // ReceiptSigner talks to the "default" authority, so these tests do too.
  const signer = () => new ReceiptSigner({} as any, env as any);
  const defaultAuthority = () => env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
  const b64ToBytes = (b64: string) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const sha256 = async (b: Uint8Array) => new Uint8Array(await crypto.subtle.digest("SHA-256", b));

  it("verifies a receipt signed under a key rotated away before anyone archived it", async () => {
    const rs = signer();
    const facts = await rs.receiptFacts();
    const bytes = commitment(facts);
    const signed = await rs.signReceipt(bytes);
    expect(signed.ok).toBe(true);
    if (!signed.ok) return;

    // Two rotations between polls: the key that signed is in neither the
    // current nor the previous slot of /internal/ca-bundle any more.
    await defaultAuthority().rotate();
    await defaultAuthority().rotate();

    const res = await rs.epochPublicKey(signed.epoch);
    expect(res.ok, res.ok ? "" : `${res.code}: ${res.message}`).toBe(true);
    if (!res.ok) return;
    expect(res.epoch).toBe(signed.epoch);
    expect(res.keys.length).toBeGreaterThanOrEqual(3);

    // Disambiguate by actor_fp, as an auditor does: the epoch is the filter,
    // the fingerprint is the index.
    const matches: typeof res.keys = [];
    for (const k of res.keys) {
      const fp = await sha256(b64ToBytes(k.publicRawB64));
      if (fp.every((b, i) => b === facts.actorFp[i])) matches.push(k);
    }
    expect(matches).toHaveLength(1);
    const key = matches[0]!;
    expect(key.retiredAt).toBeTypeOf("number");
    expect(key.kid).toMatch(/\S/);

    const verifyKey = await crypto.subtle.importKey("raw", b64ToBytes(key.publicRawB64), { name: "Ed25519" }, false, [
      "verify",
    ]);
    expect(await crypto.subtle.verify({ name: "Ed25519" }, verifyKey, signed.signature, bytes)).toBe(true);
  });

  it("names the live key with retiredAt null", async () => {
    const rs = signer();
    const { epoch } = await rs.receiptFacts();
    const res = await rs.epochPublicKey(epoch);
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    const live = res.keys.filter((k) => k.retiredAt === null);
    expect(live).toHaveLength(1);
    expect(live[0]!.publicRawB64).toBe(await defaultAuthority().getPublicKeyRawB64());
  });

  it("still resolves an epoch after revokeEpoch() moves past it", async () => {
    const rs = signer();
    const { epoch } = await rs.receiptFacts();
    await defaultAuthority().revokeEpoch();
    expect((await rs.receiptFacts()).epoch).toBe(epoch + 1);
    const res = await rs.epochPublicKey(epoch);
    expect(res.ok).toBe(true);
  });

  it("answers EPOCH_UNKNOWN, not a throw, for an epoch notme has no key for", async () => {
    const rs = signer();
    const { epoch } = await rs.receiptFacts();
    // A generation the authority has not reached. Answering with the live key
    // would hand a verifier a working key for an epoch that does not exist.
    const res = await rs.epochPublicKey(epoch + 1);
    expect(res).toEqual({ ok: false, code: "EPOCH_UNKNOWN", message: expect.stringContaining(String(epoch + 1)) });
  });

  it.each([-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, "1", null])(
    "answers EPOCH_INVALID for %s rather than coercing it",
    async (bad) => {
      const res = await signer().epochPublicKey(bad as any);
      expect(res.ok).toBe(false);
      if (res.ok) return;
      expect(res.code).toBe("EPOCH_INVALID");
    },
  );
});
