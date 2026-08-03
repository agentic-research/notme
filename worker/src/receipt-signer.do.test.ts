/// <reference types="@cloudflare/vitest-pool-workers/types" />
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
import type { SigningAuthority } from "./signing-authority";

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
function commitment(
  facts: { actorFp: Uint8Array; epoch: number },
  overrides: Record<string, unknown> = {},
) {
  const m = new Map<string, unknown>([
    ["epoch", facts.epoch],
    ["nonce", new Uint8Array(16).fill(0x11)],
    ["status", 200],
    ["actor_fp", facts.actorFp],
    ["body_hash", new Uint8Array(32).fill(0xbb)],
    ["headers_hash", new Uint8Array(32).fill(0xcc)],
    ["request_hash", new Uint8Array(32).fill(0xdd)],
    ["timestamp_ms", 1_775_000_000_000],
  ]);
  for (const [k, v] of Object.entries(overrides)) m.set(k, v);
  return new Uint8Array(cbor.encode(m));
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
      commitment(facts, { actor_fp: new Uint8Array(32).fill(0xff) }),
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
      commitment(facts, { epoch: facts.epoch + 1 }),
    );
    expect(res.ok).toBe(false);
    if (res.ok) return;
    // The code cloister branches on to re-read receiptFacts().
    expect(res.code).toBe("EPOCH_MISMATCH");
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
      ["timestamp_ms", 1_775_000_000_000],
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
