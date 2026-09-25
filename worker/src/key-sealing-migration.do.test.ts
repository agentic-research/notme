/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * key-sealing-migration.do.test.ts — the transition an operator actually
 * performs (notme-41d0d3).
 *
 * `key-encryption.test.ts` covers the primitives thoroughly: round-trip, no
 * cleartext scalar, KEK derivation, tampered envelope, fail-closed on a
 * sealed row with no KEK. What none of it covers is the DURABLE OBJECT
 * migrating an EXISTING cleartext key in place when `NOTME_KEK_SECRET`
 * appears — the only path a live authority can take, because production
 * already holds an unsealed key.
 *
 * Measured 2026-09-25: `wrangler secret list` on the production Worker
 * returns `[]`. No NOTME_KEK_SECRET is set, so `detectKeyStorage` resolves to
 * cf-managed and the CA master key plus every delegated JWT key are plaintext
 * JWK in DO SQLite. The envelope implementation is finished, wired for both
 * tables, and switched off — so this transition is the whole remaining
 * question, and it must not lose the key.
 *
 * HOW THESE DRIVE THE BRANCH. `#getOrCreateSigningKey` short-circuits on the
 * in-memory key, so only the FIRST key load in an isolate reads storage and
 * only that call can migrate. A first draft of this file tried to force a
 * cold load by assigning `a["#signingKey"] = undefined` — which sets a
 * string-keyed property and leaves the real ECMAScript private field alone,
 * so the isolate stayed warm, the branch never ran, and one case passed
 * anyway. These plant the row FIRST, through SQL, so the branch under test is
 * the isolate's first load.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { deriveKek, readStoredJwk, serialiseJwkForStorage } from "./key-encryption";

const KEK_SECRET = "k".repeat(64);

type Internals = {
  env: Record<string, unknown>;
  getSessionSecret(): Promise<string>; // ensures schema, never loads the key
  getPublicKeyPem(): Promise<string>;
  ctx: { storage: { sql: { exec(q: string, ...a: unknown[]): { toArray(): unknown[] } } } };
};

function storedJwk(a: Internals): string {
  const rows = a.ctx.storage.sql
    .exec("SELECT private_jwk FROM keys WHERE id = 'authority'")
    .toArray() as Array<{ private_jwk: string }>;
  return rows[0]?.private_jwk ?? "";
}

/** A real Ed25519 authority key, exported the way the DO stores it. */
async function freshKeyRow() {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", kp.privateKey)) as JsonWebKey;
  const spki = (await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer;
  const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
  return {
    jwk,
    publicSpkiB64: b64,
    pem: `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----\n`,
  };
}

describe("key-storage.migration", () => {
  it("seals an existing cleartext key in place, and keeps the SAME key", async () => {
    const stub = env.SIGNING_AUTHORITY.get(
      env.SIGNING_AUTHORITY.idFromName("kek-migration"),
    );
    const key = await freshKeyRow();

    const result = await runInDurableObject(stub, async (auth) => {
      const a = auth as unknown as Internals;
      // Schema without warming the key.
      await a.getSessionSecret();
      // Plant production's current state: a BARE JWK, scalar in the clear.
      a.ctx.storage.sql.exec("DELETE FROM keys WHERE id = 'authority'");
      a.ctx.storage.sql.exec(
        "INSERT INTO keys (id, private_jwk, public_spki, key_id) VALUES ('authority', ?, ?, ?)",
        JSON.stringify(key.jwk),
        key.publicSpkiB64,
        "planted-kid",
      );
      const planted = storedJwk(a);

      // The operator sets the secret; this isolate's first key load follows.
      a.env = { ...a.env, NOTME_KEK_SECRET: KEK_SECRET };
      const pem = await a.getPublicKeyPem();
      return { planted, pem, after: storedJwk(a) };
    });

    // The bare row is the `cat *.sqlite | strings | grep '"d"'` ADR-007 says
    // a secretless system cannot have.
    expect(JSON.parse(result.planted).d, "the planted row was bare").toBeTruthy();

    // THE KEY MUST BE THE SAME ONE. A migration that regenerated would
    // invalidate every certificate and token ever issued, silently, and look
    // like success.
    expect(result.pem).toBe(key.pem);

    // ...and the PRIVATE half must be that key too. The public PEM alone does
    // not prove it: `verifyKey` is imported from the stored `public_spki`
    // column, so a migration that swapped only the private key would still
    // serve the planted public key — beside a signing key that does not match
    // it, making every signature fail against the published JWKS. A mutation
    // doing exactly that survived the first version of this test.
    //
    // Unsealing the row is the direct check: what got written must be the
    // scalar that was planted.
    const unsealed = await readStoredJwk(result.after, await deriveKek(KEK_SECRET));
    expect(unsealed.wasSealed, "the migrated row is not an envelope").toBe(true);
    expect(unsealed.jwk.d).toBe(key.jwk.d);
    expect(unsealed.jwk.x).toBe(key.jwk.x);

    // And it is sealed now — not merely reachable.
    expect(result.after).not.toBe(result.planted);
    expect(result.after).not.toContain(String(key.jwk.d));
    expect(() => JSON.parse(result.after).d).not.toThrow();
    expect(JSON.parse(result.after).d, "a sealed envelope has no bare scalar").toBeUndefined();
  });

  it("leaves the row alone when no KEK is configured — cf-managed is unchanged", async () => {
    // The negative control. Without it, a migration that ran unconditionally
    // would satisfy the case above and quietly change behaviour for every
    // deployment that never opted in.
    const stub = env.SIGNING_AUTHORITY.get(
      env.SIGNING_AUTHORITY.idFromName("kek-absent"),
    );
    const key = await freshKeyRow();

    const result = await runInDurableObject(stub, async (auth) => {
      const a = auth as unknown as Internals;
      await a.getSessionSecret();
      a.ctx.storage.sql.exec("DELETE FROM keys WHERE id = 'authority'");
      a.ctx.storage.sql.exec(
        "INSERT INTO keys (id, private_jwk, public_spki, key_id) VALUES ('authority', ?, ?, ?)",
        JSON.stringify(key.jwk),
        key.publicSpkiB64,
        "planted-kid",
      );
      const before = storedJwk(a);
      const pem = await a.getPublicKeyPem();
      return { before, pem, after: storedJwk(a) };
    });

    expect(result.pem).toBe(key.pem);
    expect(result.after).toBe(result.before);
  });

  it("a sealed row with the KEK withdrawn fails closed — it does not regenerate", async () => {
    // The irreversibility that makes setting the secret an operator decision
    // rather than a default: lose NOTME_KEK_SECRET and the authority refuses
    // to start, rather than quietly minting a NEW root and leaving every
    // issued credential unverifiable against a CA nobody revoked.
    const stub = env.SIGNING_AUTHORITY.get(
      env.SIGNING_AUTHORITY.idFromName("kek-withdrawn"),
    );
    const key = await freshKeyRow();
    const sealed = await serialiseJwkForStorage(key.jwk, await deriveKek(KEK_SECRET));

    await expect(
      runInDurableObject(stub, async (auth) => {
        const a = auth as unknown as Internals;
        await a.getSessionSecret();
        a.ctx.storage.sql.exec("DELETE FROM keys WHERE id = 'authority'");
        a.ctx.storage.sql.exec(
          "INSERT INTO keys (id, private_jwk, public_spki, key_id) VALUES ('authority', ?, ?, ?)",
          sealed,
          key.publicSpkiB64,
          "planted-kid",
        );
        // No KEK in env — the secret was lost or never redeployed.
        a.env = { ...a.env, NOTME_KEK_SECRET: undefined };
        return a.getPublicKeyPem();
      }),
    ).rejects.toThrow(/sealed|KEK/i);
  });
});
