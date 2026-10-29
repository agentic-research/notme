/// <reference types="@cloudflare/vitest-pool-workers/types" />
//
// revocation.do.test.ts — tests for the APAS edge revocation module.
//
// Runs in the Workerd runtime via @cloudflare/vitest-pool-workers, which
// provides real WebCrypto (Ed25519) and Durable Object support.
//
// Runs under vitest.workers.config.mts (the vitest-pool-workers pool), NOT the
// default plain-vitest suite. The `.do.test.ts` suffix is what the pool glob
// (src/**/*.do.test.ts) matches; the pool config declares the bindings this
// file needs — REVOCATION (classic DO), CA_BUNDLE_CACHE (KV), and the shared
// SIGNING_AUTHORITY. Invoke via `pnpm test:do`; gated by `task worker:check`.
// Not in tsconfig (excluded via **/*.test.ts): the pool transpiles via esbuild
// and provides cloudflare:test + the bindings at runtime.
//
// History: this file was dormant — no config ran it — until notme-97b3ff wired
// it into the pool; notme-c38bb6 flagged the dead-test gap.

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

describe("bundle.signature.verification — verifyBundleSignature", () => {
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

  it("revocation.seqno.monotonic — rejects lower seqno (rollback attack)", async () => {
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

  it("revocation.epoch.mismatch — revokes token with old epoch", async () => {
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

// ── The rotation grace window, exercised through the production door ─────────
//
// signing-authority.do.test.ts proves rotate() REPUBLISHES the previous key
// and sets prevKeyId — i.e. that the bundle carries the material a grace
// window needs. These tests ask the question that material exists to answer:
// is a token signed by the previous key actually accepted after a rotation?
//
// IT WAS NOT, FOR MOST OF THIS REPO'S LIFE, and the earlier version of this
// block pinned that as the actual behaviour: rotate() incremented epoch and
// replaced the key in one statement, so a token minted before the rotation
// carried BOTH the old keyId and the old epoch — and checkRevocation's epoch
// check (step 5) rejected it before the prevKeyId check (step 6) could admit
// it. The grace window built for notme-b49020 / notme-54f84b guarded a branch
// no token could enter, and that block said it should FAIL when notme-77a024's
// decision landed, deliberately rather than by inheriting a misleading pass.
//
// IT LANDED. rotate() no longer touches the epoch; `revokeEpoch()` is the only
// thing that moves it. So the window is reachable, and these tests now assert
// that it WORKS — with the revocation lever itself as the control, because a
// grace window that admitted a genuinely revoked generation would be worse
// than the dead branch it replaced.
//
// SEQNO MUST INCREASE ACROSS THE TESTS BELOW. They share one RevocationAuthority
// DO, which remembers the highest seqno it has seen per issuer — that is the
// rollback protection working. A new test with a lower seqno than one above it
// is rejected as `rollback_attack`, which looks like whatever the test was
// actually about having broken.
describe("rotation grace window (notme-77a024, decoupled)", () => {
  it("accepts a pre-rotation token: same epoch, previous key", async () => {
    // The post-rotation bundle: new key current, old key republished as prev —
    // exactly what signing-authority.do.test.ts proves rotate() produces. The
    // epoch is UNCHANGED, which is the whole of the fix.
    const bundle = makeBundle({
      seqno: 300,
      epoch: 1, // rotate() leaves it alone
      keyId: "key002",
      prevKeyId: "key001",
      keys: {
        key001: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        key002: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      },
    });
    bundle.signature = await signBundle(bundle);
    await env.CA_BUNDLE_CACHE.put("bundle:current", JSON.stringify(bundle));

    // A token minted just before the rotation: previous key, same epoch.
    // This is the exact token the grace window exists to keep working.
    const result = await checkRevocation(
      { keyId: "key001", epoch: 1 },
      env,
      rootPublicKeyB64,
    );

    expect(result.revoked).toBe(false);
  });

  it("still revokes that token once revokeEpoch() moves the generation", async () => {
    // THE CONTROL. Same key, same prevKeyId, same grace window — only the
    // epoch has advanced, as `revokeEpoch()` advances it. The window must not
    // launder a revoked generation, or decoupling would have traded a dead
    // branch for a bypass.
    const bundle = makeBundle({
      seqno: 302,
      epoch: 2, // revokeEpoch() moved it
      keyId: "key002",
      prevKeyId: "key001",
      keys: {
        key001: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        key002: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      },
    });
    bundle.signature = await signBundle(bundle);
    await env.CA_BUNDLE_CACHE.put("bundle:current", JSON.stringify(bundle));

    const result = await checkRevocation(
      { keyId: "key001", epoch: 1 },
      env,
      rootPublicKeyB64,
    );

    expect(result.revoked).toBe(true);
    expect((result as { reason: string }).reason).toBe("epoch_mismatch");
  });

  it("rejects a token claiming an epoch the authority has never issued", async () => {
    // The epoch check was one-sided: `token.epoch < bundle.epoch`. A token
    // naming a FUTURE generation sailed through it and then matched the
    // current keyId at step 6, so a forward-dated epoch verified. Nothing
    // legitimate produces one — the authority derives the epoch itself — so
    // the only thing it can be is a bug or a forgery, and both are revoked.
    const bundle = makeBundle({
      seqno: 303,
      epoch: 2,
      keyId: "key002",
      keys: { key002: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" },
    });
    bundle.signature = await signBundle(bundle);
    await env.CA_BUNDLE_CACHE.put("bundle:current", JSON.stringify(bundle));

    const result = await checkRevocation(
      { keyId: "key002", epoch: 99 },
      env,
      rootPublicKeyB64,
    );

    expect(result.revoked).toBe(true);
    expect((result as { reason: string }).reason).toBe("epoch_mismatch");
  });

  it("accepts the current epoch — the bound is exclusive, not off by one", async () => {
    const bundle = makeBundle({
      seqno: 304,
      epoch: 2,
      keyId: "key002",
      keys: { key002: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" },
    });
    bundle.signature = await signBundle(bundle);
    await env.CA_BUNDLE_CACHE.put("bundle:current", JSON.stringify(bundle));

    const result = await checkRevocation(
      { keyId: "key002", epoch: 2 },
      env,
      rootPublicKeyB64,
    );
    expect(result.revoked).toBe(false);
  });

});
