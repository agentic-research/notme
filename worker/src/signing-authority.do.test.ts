// Real-Durable-Object test for the SigningAuthority rotation grace window.
//
// Maps to notme-b49020 (this test) guarding the notme-54f84b fix: rotate()
// must PRESERVE the previous public key so a subsequently-generated bundle
// republishes it (under prevKeyId) for the grace window during which tokens
// signed by the old key still verify. The regression this pins was rotate()
// deleting the old key row + generateBundle() dropping prevKeyId, which
// silently broke grace-window verification the moment a key rotated.
//
// Runs under vitest.workers.config.ts (vitest-pool-workers → real workerd +
// real DO SQLite), NOT the default plain-vitest suite. Invoke with
// `pnpm test:do`.

import { env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import type { SigningAuthority } from "./signing-authority";

describe("SigningAuthority rotation grace window (notme-b49020 / notme-54f84b)", () => {
  it("republishes the previous key + prevKeyId in the signed bundle after rotate()", async () => {
    const id = env.SIGNING_AUTHORITY.idFromName("grace-test");
    const stub = env.SIGNING_AUTHORITY.get(id);

    // Baseline: a fresh authority publishes exactly one key and no prevKeyId.
    const before = await runInDurableObject(stub, (auth: SigningAuthority) =>
      auth.generateBundle(),
    );
    expect(Object.keys(before.keys)).toHaveLength(1);
    expect(before.prevKeyId).toBeUndefined();
    const oldKeyId = before.keyId;
    const oldPub = before.keys[oldKeyId];
    expect(oldPub).toBeTruthy();

    // Rotate: mints a new key. Must preserve the OLD public key + kid.
    const { newKeyId } = await runInDurableObject(stub, (auth: SigningAuthority) =>
      auth.rotate(),
    );
    expect(newKeyId).not.toBe(oldKeyId);

    // The next signed bundle carries BOTH keys; prevKeyId points at the old one.
    const after = await runInDurableObject(stub, (auth: SigningAuthority) =>
      auth.generateBundle(),
    );
    expect(after.keyId).toBe(newKeyId);
    expect(after.prevKeyId).toBe(oldKeyId);
    // Both keys present — the notme-54f84b regression dropped the old one.
    expect(Object.keys(after.keys).sort()).toEqual([oldKeyId, newKeyId].sort());
    // The OLD public-key bytes survive rotation (grace-window verify needs them).
    expect(after.keys[oldKeyId]).toBe(oldPub);
    // The new key is distinct material, not a copy of the old one.
    expect(after.keys[newKeyId]).not.toBe(oldPub);
  });
});
