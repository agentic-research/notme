/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * epoch-lever.do.test.ts — the epoch is a REVOCATION lever, not a side effect
 * of replacing a key (notme-77a024 finding (a)).
 *
 * THE DEFECT THIS FILE DRIVES OUT. `rotate()` did two unrelated things in one
 * statement: `UPDATE state SET epoch = epoch + 1` alongside the key swap. So
 * notme had no way to say "every credential issued so far is void" without
 * also destroying the signing key — and destroying the key is the one action
 * that cannot be undone, because every receipt naming the old epoch becomes
 * unverifiable past the retention depth. Mass revocation therefore cost an
 * audit trail, which means in practice it was never going to be used.
 *
 * The inverse failed too: a key rotation implied a mass revocation nobody
 * asked for. `checkRevocation` tests epoch (step 5) BEFORE keyId (step 6), so
 * every token minted before a routine rotation died on epoch and the
 * republished `prevKeyId` grace window built for notme-54f84b guarded a
 * branch no token could enter. revocation.do.test.ts pinned that as the
 * actual behaviour and said these tests should fail when the decision landed.
 *
 * THE DECISION. Two independent axes:
 *
 *   epoch  — the revocation generation. Moves ONLY on revokeEpoch().
 *   keyId  — which key signed. Moves ONLY on rotate().
 *
 * WHAT THAT BREAKS, AND WHY IT IS THE POINT. `retired_keys` was keyed
 * `epoch INTEGER PRIMARY KEY` — one key per epoch, which is only true while
 * the two axes move together. Decouple them and a second rotation inside one
 * epoch collides on that primary key, where the archive write is
 * `INSERT OR IGNORE` — so it is dropped SILENTLY and that key's receipts go
 * unverifiable. That is the exact failure the table was created to prevent
 * ("A can defeat audits by aggressive key rotation", Interlace RECEIPTS.md
 * §2.3), reintroduced by the fix if the schema is left alone. Hence the
 * archive is keyed on the KEY, and records the epoch span it served.
 *
 * Runs under vitest.workers.config.mts (`pnpm test:do`).
 */

import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { bundleCanonical, type CABundle } from "./revocation";

// Unique DO name per test: this pool shares storage across tests in a file.
const authority = (name: string) =>
  env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(name));

describe("epoch and key identity move independently (notme-77a024)", () => {
  it("rotate() replaces the key and leaves the epoch alone", async () => {
    const stub = authority("epoch-lever-rotate");
    const before = await stub.generateBundle();
    const { newKeyId, epoch } = await stub.rotate();

    expect(newKeyId).not.toBe(before.keyId);
    // The whole finding: a key rotation is not a mass revocation.
    expect(epoch).toBe(before.epoch);

    const after = await stub.generateBundle();
    expect(after.epoch).toBe(before.epoch);
    expect(after.keyId).toBe(newKeyId);
    // seqno still advances — the published bundle genuinely changed, and
    // rollback protection must not accept the pre-rotation bundle again.
    expect(after.seqno).toBeGreaterThan(before.seqno);
  });

  it("revokeEpoch() advances the epoch and leaves the key alone", async () => {
    const stub = authority("epoch-lever-revoke");
    const before = await stub.generateBundle();
    const { epoch } = await stub.revokeEpoch();

    expect(epoch).toBe(before.epoch + 1);

    const after = await stub.generateBundle();
    expect(after.epoch).toBe(before.epoch + 1);
    // The lever that mass-revokes must not cost the signing key: same key,
    // same bytes, so every receipt the old epoch names stays verifiable.
    expect(after.keyId).toBe(before.keyId);
    expect(after.keys[after.keyId]).toBe(before.keys[before.keyId]);
    expect(after.seqno).toBeGreaterThan(before.seqno);
  });

  it("archives every key retired inside one epoch, not just the first", async () => {
    const stub = authority("epoch-lever-archive");
    const first = await stub.generateBundle();
    const r1 = await stub.rotate();
    const r2 = await stub.rotate();

    // Three distinct keys, all at the same epoch — impossible before the
    // decoupling, and the case `epoch INTEGER PRIMARY KEY` silently dropped.
    expect(new Set([first.keyId, r1.newKeyId, r2.newKeyId]).size).toBe(3);

    const keys = await stub.listEpochKeys();
    const byKeyId = new Map(keys.map((k) => [k.keyId, k]));
    expect(byKeyId.has(first.keyId)).toBe(true);
    expect(byKeyId.has(r1.newKeyId)).toBe(true);
    expect(byKeyId.has(r2.newKeyId)).toBe(true);

    // The two retired keys kept their real material — an archive that holds
    // the row but loses the bytes verifies nothing.
    expect(byKeyId.get(first.keyId)!.publicRawB64).toBe(first.keys[first.keyId]);
    expect(byKeyId.get(first.keyId)!.retiredAt).toBeTypeOf("number");
    expect(byKeyId.get(r1.newKeyId)!.retiredAt).toBeTypeOf("number");
    expect(byKeyId.get(r2.newKeyId)!.retiredAt).toBeNull(); // still serving
  });

  it("resolves every key that served a given epoch, not one of them", async () => {
    const stub = authority("epoch-lever-resolve");
    const first = await stub.generateBundle();
    const r1 = await stub.rotate();
    const r2 = await stub.rotate();
    const epoch = first.epoch;

    const serving = await stub.getEpochPublicKey(epoch);
    const ids = serving.map((k) => k.keyId).sort();
    expect(ids).toEqual([first.keyId, r1.newKeyId, r2.newKeyId].sort());

    // An auditor holding a receipt that names this epoch disambiguates by
    // actor_fp = SHA-256(public key), so the SET is the answer; returning any
    // single member would be a coin flip dressed as a lookup.
    expect(await stub.getEpochPublicKey(epoch + 99)).toEqual([]);
  });

  it("records the epoch span a key served, so a later epoch still resolves it", async () => {
    const stub = authority("epoch-lever-span");
    const first = await stub.generateBundle();
    // The key signs through a revocation generation, then retires.
    await stub.revokeEpoch();
    const r1 = await stub.rotate();

    const keys = await stub.listEpochKeys();
    const original = keys.find((k) => k.keyId === first.keyId)!;
    expect(original.epoch).toBe(first.epoch); // first epoch served
    expect(original.untilEpoch).toBe(first.epoch + 1); // last epoch served

    // Resolvable from BOTH epochs it served. Keying the archive on a single
    // epoch number made one of these two answers a lie.
    for (const e of [first.epoch, first.epoch + 1]) {
      const ids = (await stub.getEpochPublicKey(e)).map((k) => k.keyId);
      expect(ids).toContain(first.keyId);
    }

    const live = keys.find((k) => k.keyId === r1.newKeyId)!;
    expect(live.untilEpoch).toBeNull(); // still serving
  });

  it("publishes the new generation, signed, where a verifier actually reads it", async () => {
    // WITHOUT THIS THE LEVER IS A NO-OP. `checkRevocation` reads the bundle
    // from CA_BUNDLE_CACHE, not from the DO — so bumping the epoch in SQLite
    // and leaving the published bundle alone revokes nothing until the next
    // alarm fires, and an alarm is the one thing here that cannot be relied
    // on (production measured totalFires: 0 across 130 days, notme-4896d8).
    const stub = authority("epoch-lever-publish");
    const before = await stub.generateBundle();
    const { epoch } = await stub.revokeEpoch();

    const raw = await env.CA_BUNDLE_CACHE.get("bundle:current");
    expect(raw).toBeTruthy();
    const published = JSON.parse(raw!) as CABundle;
    expect(published.epoch).toBe(epoch);
    expect(published.epoch).toBe(before.epoch + 1);

    // And it is SIGNED by this authority. An unsigned or stale-signed bundle
    // is rejected as `bundle_invalid`, which would also make the lever a
    // no-op — in a way that looks like a transport problem.
    const pubRaw = Uint8Array.from(
      atob(await stub.getPublicKeyRawB64()),
      (c) => c.charCodeAt(0),
    );
    const verifyKey = await crypto.subtle.importKey(
      "raw",
      pubRaw,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    const sig = Uint8Array.from(atob(published.signature), (c) =>
      c.charCodeAt(0),
    );
    const { signature: _omit, ...unsigned } = published;
    expect(
      await crypto.subtle.verify(
        "Ed25519",
        verifyKey,
        sig,
        bundleCanonical(unsigned),
      ),
    ).toBe(true);
  });

  it("a revoked epoch is never reused, so a reissued credential cannot be mistaken for an old one", async () => {
    const stub = authority("epoch-lever-monotonic");
    const start = (await stub.generateBundle()).epoch;
    await stub.revokeEpoch();
    await stub.rotate();
    await stub.revokeEpoch();
    expect((await stub.generateBundle()).epoch).toBe(start + 2);
  });
});
