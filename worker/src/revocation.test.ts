//
// revocation.test.ts — Unit tests for the APAS edge revocation module.
//
// Runs in the Workerd runtime via @cloudflare/vitest-pool-workers, which
// provides real WebCrypto (Ed25519) and Durable Object support.
//
// DORMANT — this file is NOT currently run or typechecked. It is excluded
// from tsconfig.json because:
//   1. vitest.config.ts only globs src/__tests__/**/*.test.ts, so it never
//      runs.
//   2. It imports from cloudflare:test (vitest-pool-workers) and references
//      DO bindings (env.REVOCATION) that aren't declared in the project's
//      Env type — typechecking fails without configuring the pool.
//
// To revive: move into src/__tests__/, add pool config + ProvidedEnv module
// augmentation declaring REVOCATION, drop the tsconfig exclude. Tracked as
// a follow-up bead.

import { describe, expect, it, beforeAll } from "vitest";
import { env, runInDurableObject } from "cloudflare:test";
import {
  type CABundle,
  BUNDLE_MAX_AGE_MS,
  bundleCanonical,
  checkRevocation,
  RevocationAuthority,
  verifyBundleSignature,
} from "./revocation";

// ── Test key generation ───────────────────────────────────────────────────────

let rootPublicKeyB64: string;
let signBundle: (bundle: CABundle) => Promise<string>;

beforeAll(async () => {
  const kp = (await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;

  const pubRaw = new Uint8Array(
    (await crypto.subtle.exportKey("raw", kp.publicKey)) as ArrayBuffer,
  );
  rootPublicKeyB64 = btoa(String.fromCharCode(...pubRaw));

  signBundle = async (bundle: CABundle): Promise<string> => {
    const sig = (await crypto.subtle.sign(
      "Ed25519",
      kp.privateKey,
      bundleCanonical(bundle),
    )) as ArrayBuffer;
    return btoa(String.fromCharCode(...new Uint8Array(sig)));
  };
});

function makeBundle(overrides: Partial<CABundle> = {}): CABundle {
  return {
    epoch: 1,
    seqno: 100,
    keys: { key001: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" },
    keyId: "key001",
    issuedAt: Math.floor(Date.now() / 1000),
    signature: "", // filled in by signBundle
    ...overrides,
  };
}

// ── bundleCanonical ───────────────────────────────────────────────────────────

describe("bundleCanonical", () => {
  it("excludes signature field", () => {
    const bundle = makeBundle({ signature: "abc123" });
    const canonical = new TextDecoder().decode(bundleCanonical(bundle));
    expect(canonical).not.toContain("signature");
  });

  it("produces stable output regardless of key insertion order", () => {
    const a = makeBundle();
    const b: CABundle = {
      signature: a.signature,
      keyId: a.keyId,
      epoch: a.epoch,
      seqno: a.seqno,
      keys: a.keys,
      issuedAt: a.issuedAt,
    };
    expect(bundleCanonical(a)).toEqual(bundleCanonical(b));
  });
});

// ── verifyBundleSignature ─────────────────────────────────────────────────────

describe("verifyBundleSignature", () => {
  it("accepts a valid bundle signature", async () => {
    const bundle = makeBundle();
    bundle.signature = await signBundle(bundle);
    expect(await verifyBundleSignature(bundle, rootPublicKeyB64)).toBe(true);
  });

  it("rejects a tampered bundle", async () => {
    const bundle = makeBundle();
    bundle.signature = await signBundle(bundle);
    bundle.epoch = 999; // tamper after signing
    expect(await verifyBundleSignature(bundle, rootPublicKeyB64)).toBe(false);
  });

  it("rejects a wrong key", async () => {
    const otherKp = (await crypto.subtle.generateKey(
      { name: "Ed25519" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const otherPubRaw = new Uint8Array(
      (await crypto.subtle.exportKey("raw", otherKp.publicKey)) as ArrayBuffer,
    );
    const otherKeyB64 = btoa(String.fromCharCode(...otherPubRaw));

    const bundle = makeBundle();
    bundle.signature = await signBundle(bundle);
    expect(await verifyBundleSignature(bundle, otherKeyB64)).toBe(false);
  });
});

// ── RevocationAuthority DO ────────────────────────────────────────────────────

describe("RevocationAuthority", () => {
  async function seqnoCheck(
    instance: RevocationAuthority,
    issuerId: string,
    seqno: number,
  ): Promise<{ ok: boolean; reason?: string }> {
    const resp = await instance.fetch(
      new Request("http://do/seqno", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ issuerId, seqno }),
      }),
    );
    return resp.json();
  }

  it("accepts first seqno", async () => {
    const id = env.REVOCATION.idFromName("test-accept-first");
    const stub = env.REVOCATION.get(id);
    await runInDurableObject(stub, async (instance: RevocationAuthority) => {
      const result = await seqnoCheck(instance, "test", 100);
      expect(result.ok).toBe(true);
    });
  });

  it("accepts same seqno (same bundle re-fetched)", async () => {
    const id = env.REVOCATION.idFromName("test-accept-same");
    const stub = env.REVOCATION.get(id);
    await runInDurableObject(stub, async (instance: RevocationAuthority) => {
      await seqnoCheck(instance, "test", 100);
      const result = await seqnoCheck(instance, "test", 100);
      expect(result.ok).toBe(true);
    });
  });

  it("accepts higher seqno (bundle rotated)", async () => {
    const id = env.REVOCATION.idFromName("test-accept-higher");
    const stub = env.REVOCATION.get(id);
    await runInDurableObject(stub, async (instance: RevocationAuthority) => {
      await seqnoCheck(instance, "test", 100);
      const result = await seqnoCheck(instance, "test", 101);
      expect(result.ok).toBe(true);
    });
  });

  it("rejects lower seqno (rollback attack)", async () => {
    const id = env.REVOCATION.idFromName("test-reject-rollback");
    const stub = env.REVOCATION.get(id);
    await runInDurableObject(stub, async (instance: RevocationAuthority) => {
      await seqnoCheck(instance, "test", 100);
      const result = await seqnoCheck(instance, "test", 99);
      expect(result.ok).toBe(false);
      expect(result.reason).toBe("rollback");
    });
  });

  it("isolates seqno state per issuer", async () => {
    const id = env.REVOCATION.idFromName("test-isolation");
    const stub = env.REVOCATION.get(id);
    await runInDurableObject(stub, async (instance: RevocationAuthority) => {
      await seqnoCheck(instance, "issuer-a", 200);
      // Different issuer starts at 0
      const result = await seqnoCheck(instance, "issuer-b", 1);
      expect(result.ok).toBe(true);
    });
  });
});

// ── checkRevocation ───────────────────────────────────────────────────────────

describe("checkRevocation", () => {
  it("fails open when no bundle in KV (bootstrap)", async () => {
    const result = await checkRevocation(
      { keyId: "key001", epoch: 1 },
      env,
      rootPublicKeyB64,
    );
    expect(result.revoked).toBe(false);
  });

  it("accepts valid token", async () => {
    const bundle = makeBundle({ seqno: 1 }); // fresh seqno to avoid state leakage
    bundle.signature = await signBundle(bundle);

    await env.CA_BUNDLE_CACHE.put("bundle:current", JSON.stringify(bundle));

    const result = await checkRevocation(
      { keyId: "key001", epoch: 1 },
      env,
      rootPublicKeyB64,
    );
    expect(result.revoked).toBe(false);
  });

  it("revokes token with old epoch", async () => {
    const bundle = makeBundle({ epoch: 5, seqno: 2 });
    bundle.signature = await signBundle(bundle);
    await env.CA_BUNDLE_CACHE.put("bundle:current", JSON.stringify(bundle));

    const result = await checkRevocation(
      { keyId: "key001", epoch: 3 }, // epoch 3 < bundle epoch 5
      env,
      rootPublicKeyB64,
    );
    expect(result.revoked).toBe(true);
    if (result.revoked) expect(result.reason).toBe("epoch_mismatch");
  });

  it("revokes token with unknown key ID", async () => {
    const bundle = makeBundle({ seqno: 3 });
    bundle.signature = await signBundle(bundle);
    await env.CA_BUNDLE_CACHE.put("bundle:current", JSON.stringify(bundle));

    const result = await checkRevocation(
      { keyId: "unknown-key", epoch: 1 },
      env,
      rootPublicKeyB64,
    );
    expect(result.revoked).toBe(true);
    if (result.revoked) expect(result.reason).toBe("unknown_key");
  });

  it("accepts token matching prevKeyId during rotation grace period", async () => {
    const bundle = makeBundle({ seqno: 4, keyId: "key002", prevKeyId: "key001" });
    bundle.signature = await signBundle(bundle);
    await env.CA_BUNDLE_CACHE.put("bundle:current", JSON.stringify(bundle));

    const result = await checkRevocation(
      { keyId: "key001", epoch: 1 }, // old key but in prevKeyId
      env,
      rootPublicKeyB64,
    );
    expect(result.revoked).toBe(false);
  });

  it("rejects bundle with invalid signature", async () => {
    const bundle = makeBundle({ seqno: 5, signature: "invalidsignaturedata" });
    await env.CA_BUNDLE_CACHE.put("bundle:current", JSON.stringify(bundle));

    const result = await checkRevocation(
      { keyId: "key001", epoch: 1 },
      env,
      rootPublicKeyB64,
    );
    expect(result.revoked).toBe(true);
    if (result.revoked) expect(result.reason).toBe("bundle_invalid");
  });

  it("rejects stale bundle", async () => {
    const oldIssuedAt = Math.floor(
      (Date.now() - BUNDLE_MAX_AGE_MS - 1000) / 1000,
    );
    const bundle = makeBundle({ seqno: 6, issuedAt: oldIssuedAt });
    bundle.signature = await signBundle(bundle);
    await env.CA_BUNDLE_CACHE.put("bundle:current", JSON.stringify(bundle));

    const result = await checkRevocation(
      { keyId: "key001", epoch: 1 },
      env,
      rootPublicKeyB64,
    );
    expect(result.revoked).toBe(true);
    if (result.revoked) expect(result.reason).toBe("bundle_stale");
  });
});
