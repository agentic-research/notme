/// <reference types="@cloudflare/vitest-plugin/types" />
/**
 * rotate-atomic.do.test.ts — rotate() and cold-start key creation are atomic
 * (notme-b54368, audit 2026-11-03 M3).
 *
 * rotate() used to archive the old key, DELETE it, then generate the new one
 * across several awaits and write prevKeyId / prevPubKey with two separately
 * awaited puts. A throw anywhere after the DELETE left the authority with no
 * key row: the next call silently generated a fresh key and the rotation
 * grace record was never written. Cloudflare's SQLite storage API: a
 * `transactionSync` callback that throws is rolled back, and only
 * synchronous storage operations can be part of it — so all crypto now runs
 * first and every storage change commits in one `transactionSync`.
 *
 * Cold start had the two-first-callers race: both saw no row, both
 * generated, and the second INSERT hit the primary key (persistent mode) or
 * silently replaced the first caller's key (ephemeral mode).
 *
 * Faults are injected by patching `ctx.storage.sql.exec` (or
 * `crypto.subtle.generateKey`) inside runInDurableObject: the instance and
 * the test share one isolate, so the patch is what the DO calls.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { SigningAuthority } from "./signing-authority";
import { AUTH_METHOD } from "./auth/session";

type Sql = { exec: (q: string, ...a: unknown[]) => unknown };

function stubFor(name: string) {
  return env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(name));
}

/** Run `fn` with sql.exec throwing on the first statement `match` accepts. */
async function withSqlFault<T>(
  state: DurableObjectState,
  match: (q: string) => boolean,
  fn: () => Promise<T>,
): Promise<T> {
  const sql = state.storage.sql as unknown as Sql;
  const orig = sql.exec.bind(sql);
  sql.exec = (q: string, ...a: unknown[]) => {
    if (match(q)) throw new Error(`injected fault on: ${q.slice(0, 40)}`);
    return orig(q, ...a);
  };
  try {
    return await fn();
  } finally {
    delete (sql as Partial<Sql>).exec;
  }
}

/** Everything rotate() is allowed to change, read straight from storage. */
function snapshot(state: DurableObjectState) {
  const one = <T>(q: string) => state.storage.sql.exec(q).toArray()[0] as T | undefined;
  return {
    key: one<{ key_id: string; public_spki: string }>(
      "SELECT key_id, public_spki FROM keys WHERE id = 'authority'",
    ),
    seqno: one<{ seqno: number }>("SELECT seqno FROM state WHERE id = 'authority'")?.seqno,
    retired: state.storage.sql.exec("SELECT key_id FROM retired_keys").toArray().length,
    prevKeyId: state.storage.kv.get("prevKeyId"),
    prevPubKey: state.storage.kv.get("prevPubKey"),
  };
}

describe("rotate() is atomic (notme-b54368)", () => {
  for (const [label, match] of [
    // The write that follows the archive INSERT and the DELETE: on the old
    // code those two had already committed when this threw.
    ["the new key's INSERT", (q: string) => q.startsWith("INSERT INTO keys")],
    // The last write of the rotation.
    ["the seqno bump", (q: string) => q.startsWith("UPDATE state SET seqno")],
  ] as const) {
    it(`a rotate() that throws on ${label} leaves the old key fully in place`, async () => {
      const stub = stubFor(`rotate-atomic-${label}`);
      await runInDurableObject(stub, async (inst, state) => {
        const auth = inst as SigningAuthority;
        // One completed rotation first, so a prev-key record exists to lose.
        await auth.getAuthorityState();
        await auth.rotate();
        const before = snapshot(state);
        const jwkBefore = await auth.getPublicKeyJwk();
        expect(before.key?.key_id).toBe(jwkBefore.kid);

        await expect(
          withSqlFault(state, match, () => auth.rotate()),
        ).rejects.toThrow(/injected fault/);

        // Storage: exactly as before the failed rotate.
        expect(snapshot(state)).toEqual(before);
        // In memory: still signing with the old key, under the old kid.
        const jwkAfter = await auth.getPublicKeyJwk();
        expect(jwkAfter).toEqual(jwkBefore);
        expect((await auth.getAuthorityState()).keyId).toBe(jwkBefore.kid);
        const bundle = await auth.generateBundle();
        expect(bundle.keyId).toBe(jwkBefore.kid);
        expect(bundle.prevKeyId).toBe(before.prevKeyId);

        // And the authority can still rotate cleanly afterwards.
        const { newKeyId } = await auth.rotate();
        expect(newKeyId).not.toBe(jwkBefore.kid);
        expect(state.storage.kv.get("prevKeyId")).toBe(jwkBefore.kid);
      });
    });
  }

  it("a rotate() whose key generation throws writes nothing", async () => {
    const stub = stubFor("rotate-atomic-crypto");
    await runInDurableObject(stub, async (inst, state) => {
      const auth = inst as SigningAuthority;
      const { keyId } = await auth.getAuthorityState();
      const before = snapshot(state);
      const subtle = crypto.subtle as { generateKey: SubtleCrypto["generateKey"] };
      const orig = subtle.generateKey;
      subtle.generateKey = (() => Promise.reject(new Error("injected keygen fault"))) as never;
      try {
        await expect(auth.rotate()).rejects.toThrow(/injected keygen fault/);
      } finally {
        subtle.generateKey = orig;
      }
      expect(snapshot(state)).toEqual(before);
      expect((await auth.getAuthorityState()).keyId).toBe(keyId);
    });
  });

  it("a successful rotate() commits the archive, the new key, seqno and the prev-key record together", async () => {
    const stub = stubFor("rotate-atomic-ok");
    await runInDurableObject(stub, async (inst, state) => {
      const auth = inst as SigningAuthority;
      const old = await auth.getPublicKeyJwk();
      const before = snapshot(state);
      const { newKeyId } = await auth.rotate();
      const after = snapshot(state);
      expect(after.key?.key_id).toBe(newKeyId);
      // rotate() bumps seqno once; #publishBundle's generateBundle once more.
      expect(after.seqno).toBe(before.seqno! + 2);
      expect(after.retired).toBe(before.retired + 1);
      expect(after.prevKeyId).toBe(old.kid);
      expect(typeof after.prevPubKey).toBe("string");
      expect((await auth.getPublicKeyJwk()).kid).toBe(newKeyId);
    });
  });
});

describe("cold-start key creation converges (notme-b54368)", () => {
  it("two concurrent first callers agree on one kid, and it is the stored one", async () => {
    const stub = stubFor("cold-start-race");
    await runInDurableObject(stub, async (inst, state) => {
      const auth = inst as SigningAuthority;
      // Both calls start before either finishes: each finds no key row.
      const [a, b] = await Promise.all([auth.getPublicKeyJwk(), auth.getPublicKeyJwk()]);
      expect(a.kid).toBe(b.kid);
      expect(a.x).toBe(b.x);
      expect(snapshot(state).key?.key_id).toBe(a.kid);
    });
  });

  it("ephemeral mode: concurrent first callers agree on one kid, and it is the stored one", async () => {
    const stub = stubFor("cold-start-race-ephemeral");
    await runInDurableObject(stub, async (inst, state) => {
      const auth = inst as SigningAuthority;
      // This DO's own env only: the instance reads its mode from this.env.
      const e = (auth as unknown as { env: Record<string, unknown> }).env;
      const prior = e.NOTME_KEY_STORAGE;
      e.NOTME_KEY_STORAGE = "ephemeral";
      try {
        const [a, b] = await Promise.all([auth.getPublicKeyJwk(), auth.getPublicKeyJwk()]);
        expect(a.kid).toBe(b.kid);
        expect(snapshot(state).key?.key_id).toBe(a.kid);
        // The kid the authority reports is the key it signs with.
        const bundle = await auth.generateBundle();
        expect(bundle.keyId).toBe(a.kid);
      } finally {
        if (prior === undefined) delete e.NOTME_KEY_STORAGE;
        else e.NOTME_KEY_STORAGE = prior;
      }
    });
  });
});

/**
 * Every cert mint path re-checks key + epoch immediately before signing
 * (notme-b54368's comment). The no-log path signed with no re-check: a
 * revokeEpoch() landing between the capture and the signature was minted
 * into a certificate carrying the revoked epoch. The interleave is simulated
 * by bumping the epoch on a re-check read: capture and re-check each read
 * "SELECT epoch FROM state" once, capture first, so the re-checks are the
 * even-numbered reads.
 *
 * A refusal is retried once under a fresh capture (review L2): one move
 * mints under the MOVED epoch, never the captured one; a state that moves
 * again on the retry is refused.
 */
describe("every mint path refuses if key or epoch moved before signing (notme-b54368)", () => {
  const spkiPem = async (k: CryptoKey) => {
    const s = (await crypto.subtle.exportKey("spki", k)) as ArrayBuffer;
    const b = btoa(String.fromCharCode(...new Uint8Array(s)));
    return `-----BEGIN PUBLIC KEY-----\n${b.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
  };
  const newPem = async (alg: "Ed25519" | "P-256") =>
    spkiPem(
      (
        (await crypto.subtle.generateKey(
          alg === "Ed25519" ? { name: "Ed25519" } : { name: "ECDSA", namedCurve: "P-256" },
          true,
          ["sign", "verify"],
        )) as CryptoKeyPair
      ).publicKey,
    );

  async function epochMovesAfterCapture(
    name: string,
    moves: "once" | "always",
    mint: (a: SigningAuthority) => Promise<{ authority: { epoch: number } }>,
  ) {
    const stub = stubFor(name);
    return runInDurableObject(stub, async (inst, state) => {
      const auth = inst as SigningAuthority;
      const start = (await auth.getAuthorityState()).epoch; // key loaded before the fault is armed
      const sql = state.storage.sql as unknown as Sql;
      const orig = sql.exec.bind(sql);
      let reads = 0;
      sql.exec = (q: string, ...a: unknown[]) => {
        if (q === "SELECT epoch FROM state WHERE id = 'authority'") {
          reads++;
          if (reads % 2 === 0 && (moves === "always" || reads === 2)) {
            orig("UPDATE state SET epoch = epoch + 1 WHERE id = 'authority'");
          }
        }
        return orig(q, ...a);
      };
      try {
        const r = await mint(auth).then(
          (v) => ({ ok: true as const, epoch: v.authority.epoch }),
          (e: Error) => ({ ok: false as const, e: e.message }),
        );
        return { r, start };
      } finally {
        delete (sql as Partial<Sql>).exec;
      }
    });
  }

  const paths: Array<[string, () => Promise<(a: SigningAuthority) => Promise<{ authority: { epoch: number } }>>]> = [
    [
      "mintIssuingCa",
      async () => {
        const pem = await newPem("Ed25519");
        return (a) =>
          a.mintIssuingCa({
            subject: "tier",
            identity: "wimse://notme.bot/principal/tier",
            publicKeyPem: pem,
            scopes: ["bridgeCert"],
            authMethod: "passkey",
          });
      },
    ],
    [
      "mintBridgeCertPair",
      async () => {
        const [mtls, signing] = [await newPem("P-256"), await newPem("Ed25519")];
        return (a) =>
          a.mintBridgeCertPair({
            subject: "pair",
            identity: "wimse://notme.bot/principal/pair",
            mtlsPublicKeyPem: mtls,
            signingPublicKeyPem: signing,
            scopes: ["bridgeCert"],
            authMethod: AUTH_METHOD.ghaOidc,
          });
      },
    ],
  ];

  for (const [label, make] of paths) {
    it(`${label} (no CT log bound): one move is retried under the moved epoch, never the captured one`, async () => {
      const { r, start } = await epochMovesAfterCapture(`uniform-once-${label}`, "once", await make());
      expect(r.ok ? r.epoch : r.e).toBe(start + 1);
    });

    it(`${label} (no CT log bound): a state still moving on the retry is refused`, async () => {
      const { r } = await epochMovesAfterCapture(`uniform-always-${label}`, "always", await make());
      expect(r.ok ? `minted at epoch ${r.epoch}` : r.e).toMatch(/changed while the mint was in flight/);
    });
  }
});
