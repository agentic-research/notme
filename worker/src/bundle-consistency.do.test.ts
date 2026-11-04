/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * bundle-consistency.do.test.ts — the prev-key record carries over and the
 * bundle names the key that signs it (notme-b54368, review L1 and L4).
 *
 * L1: rotate() used to write prevKeyId / prevPubKey with the async
 * `ctx.storage.put()`. It now writes, and generateBundle reads, through the
 * synchronous `ctx.storage.kv`. Cloudflare's docs say both are KV methods
 * over the hidden `__cf_kv` table but never say outright that a value put()
 * through one reads back through the other. A deployment that rotated
 * shortly before this change depends on exactly that, so it is pinned here
 * with the real key names.
 *
 * L4: generateBundle read the key, awaited exportKey, then read seqno and
 * the prev-key record. A rotate() committing inside that await produced a
 * bundle naming the retired key as current with no prev record. The window
 * is driven for real: exportKey is wrapped so that generateBundle's export
 * awaits a complete rotate() before returning.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { SigningAuthority } from "./signing-authority";

const fresh = (name: string) =>
  env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(`${name}-${crypto.randomUUID()}`));

describe("a prev-key record written by the async put() reads back through ctx.storage.kv (review L1)", () => {
  it("the raw values, under the key names rotate() uses", async () => {
    await runInDurableObject(fresh("kv-compat-raw"), async (_inst, state) => {
      await state.storage.put("prevKeyId", "0123456789abcdef0123456789abcdef");
      await state.storage.put("prevPubKey", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=");
      expect(state.storage.kv.get("prevKeyId")).toBe("0123456789abcdef0123456789abcdef");
      expect(state.storage.kv.get("prevPubKey")).toBe("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=");
    });
  });

  it("a pre-change rotation's record is republished by generateBundle", async () => {
    await runInDurableObject(fresh("kv-compat-bundle"), async (inst, state) => {
      const auth = inst as SigningAuthority;
      const { keyId } = await auth.getAuthorityState(); // the key, created by a cold start
      // What the OLD rotate() left behind: two async puts.
      const oldKid = "fedcba9876543210fedcba9876543210";
      const oldPub = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
      await state.storage.put("prevKeyId", oldKid);
      await state.storage.put("prevPubKey", oldPub);
      const bundle = await auth.generateBundle();
      expect(bundle.keyId).toBe(keyId);
      expect(bundle.prevKeyId).toBe(oldKid);
      expect(bundle.keys[oldKid]).toBe(oldPub);
    });
  });
});

describe("generateBundle names the key that signs it, across its exportKey await (review L4)", () => {
  it("a rotate() committing inside the export: the bundle is the post-rotation one", async () => {
    await runInDurableObject(fresh("bundle-l4"), async (inst) => {
      const auth = inst as SigningAuthority;
      const { keyId: oldKid } = await auth.getAuthorityState();
      const subtle = crypto.subtle as { exportKey: SubtleCrypto["exportKey"] };
      const orig = subtle.exportKey.bind(crypto.subtle);
      let armed = true;
      let newKid = "";
      subtle.exportKey = (async (format: string, key: CryptoKey) => {
        if (armed && format === "raw") {
          armed = false; // rotate() itself exports raw too
          newKid = (await auth.rotate()).newKeyId;
        }
        return orig(format as "raw", key);
      }) as SubtleCrypto["exportKey"];
      let bundle;
      try {
        bundle = await auth.generateBundle();
      } finally {
        subtle.exportKey = orig as SubtleCrypto["exportKey"];
      }
      expect(newKid).not.toBe("");
      expect(bundle.keyId).toBe(newKid);
      expect(bundle.prevKeyId).toBe(oldKid);
      expect(Object.keys(bundle.keys).sort()).toEqual([oldKid, newKid].sort());
    });
  });
});
