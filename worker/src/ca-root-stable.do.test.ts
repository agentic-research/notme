/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * ca-root-stable.do.test.ts — the root a fresh authority serves first is
 * the root it keeps serving (notme-7aa6dd).
 *
 * getCACertificatePem read the current key id BEFORE #getOrCreateSigningKey
 * created the key, so on a fresh authority the cached root row was written
 * under a key id that did not exist ("unknown"), and the next call saw the
 * mismatch and re-issued: same key and subject, new random serial. Anything
 * pinning the root by bytes or fingerprint (a CT log's roots,
 * trust/notme-root.pem) saw it change once at boot.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { SigningAuthority } from "./signing-authority";

const fresh = (name: string) =>
  env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(`${name}-${crypto.randomUUID()}`));

describe("the root on a fresh authority (notme-7aa6dd)", () => {
  it("two consecutive getCACertificatePem calls return byte-identical PEMs", async () => {
    await runInDurableObject(fresh("root-stable"), async (inst, state) => {
      const auth = inst as SigningAuthority;
      const first = await auth.getCACertificatePem();
      const second = await auth.getCACertificatePem();
      expect(second).toBe(first);
      // Cached under the real key id, not a placeholder.
      const [row] = state.storage.sql.exec("SELECT key_id FROM ca_cert WHERE id = 'cert'").toArray() as Array<{
        key_id: string;
      }>;
      expect(row?.key_id).toBe((await auth.getAuthorityState()).keyId);
    });
  });

  it("is the same root a mint chains to, before and after the first mint", async () => {
    await runInDurableObject(fresh("root-stable-mint"), async (inst) => {
      const auth = inst as SigningAuthority;
      const before = await auth.getCACertificatePem();
      await auth.generateBundle(); // touches the key on the warm path
      expect(await auth.getCACertificatePem()).toBe(before);
    });
  });

  it("a rotation still re-issues the root under the new key", async () => {
    await runInDurableObject(fresh("root-stable-rotate"), async (inst) => {
      const auth = inst as SigningAuthority;
      const before = await auth.getCACertificatePem();
      await auth.rotate();
      const after = await auth.getCACertificatePem();
      expect(after).not.toBe(before);
      expect(await auth.getCACertificatePem()).toBe(after);
    });
  });
});
