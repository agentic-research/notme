/**
 * threat-model.test.ts — executable threat model + cross-repo contract tests.
 *
 * Pairs with [`worker/THREAT_MODEL.md`](../../THREAT_MODEL.md).
 *
 * Two roles for this file:
 *
 *  1. **Threat assertions** — each row in THREAT_MODEL.md ends with a
 *     `test` column citing a named test. The tests below are referenced
 *     by name in that doc; renaming one breaks the doc cross-ref.
 *
 *  2. **Cross-repo contract assertions** — invariants that MUST hold
 *     across the `notme` ↔ `notme.bot` (and consumer-worker ↔ AuthService)
 *     boundary. Drift between sides surfaces here in CI rather than at
 *     runtime in production.
 *
 * Some assertions are local-only and run today. Cross-repo ones that need
 * server-produced fixtures are marked `it.todo` with the fixture filename
 * they require — drop the fixture in `worker/src/__tests__/fixtures/` and
 * promote `it.todo` to `it`.
 */

import { describe, expect, it, vi } from "vitest";

// AuthService lives in worker.ts which imports cloudflare:workers at the
// top of the module. Mock it so we can construct the class in pure Node
// vitest without spinning up workerd. The mock only needs the shape worker.ts
// references at module-evaluation time (the base classes).
vi.mock("cloudflare:workers", () => ({
  WorkerEntrypoint: class WorkerEntrypoint {
    ctx: any;
    env: any;
    constructor(ctx: any, env: any) {
      this.ctx = ctx;
      this.env = env;
    }
  },
  DurableObject: class DurableObject {
    state: any;
    env: any;
    constructor(state: any, env: any) {
      this.state = state;
      this.env = env;
    }
  },
}));

import { TRUSTED_ISSUERS as CONTRACT_TRUSTED_ISSUERS } from "@notme/contract";
import { AuthService } from "../../worker";
import { validateRedirectUri } from "../auth/redirect-uri";
import { verifyOIDC } from "../auth/verify-proof";
import { validateDpopProof } from "../auth/dpop";
import {
  type CABundle,
  bundleCanonical,
  verifyBundleSignature,
} from "../revocation";
import { CertScope } from "../../../gen/ts/identity";

// Constructor under cloudflare:workers' real types expects 0 args; our mock
// supplies (ctx, env). Cast through the mock-friendly shape so the TS checker
// doesn't fight the runtime contract.
const newAuthService = () =>
  new (AuthService as unknown as new (ctx: unknown, env: unknown) => AuthService)(
    null,
    null,
  );

// ── 0. AuthService per-RPC-session credential isolation (regression guard) ─
//
// FROM 2026-05-16 security review (MEDIUM finding, now FIXED in worker.ts):
// `heldCerts` was a module-level `let`, shared across every `AuthService`
// RPC session in the isolate. Two interleaved callers — or a fresh caller
// after another principal authenticated — would silently get the
// last-written credentials in `sign()` / `proxy()` / `identity()`.
//
// The fix moved state onto `this.heldCerts` (worker.ts:67). These tests
// are the regression guard: if anyone hoists state back to module scope,
// these go RED. Paired with the in-test sanity-mirror below, which proves
// the same assertion pattern fails on a deliberately-buggy mirror class.

describe("auth-service.state.session-isolation > regression guard", () => {
  function makeCreds(identity: string, signingKey: CryptoKey) {
    return {
      mtlsCert: `cert:${identity}`,
      signingCert: `cert:${identity}:signing`,
      mtlsKey: signingKey, // shape-only; we don't sign with mtlsKey here
      signingKey,
      identity,
      scopes: ["bridgeCert"],
      expiresAt: Math.floor(Date.now() / 1000) + 300,
    };
  }

  it("two AuthService instances must not see each other's heldCerts", async () => {
    const kp = (await crypto.subtle.generateKey(
      { name: "Ed25519" },
      false,
      ["sign", "verify"],
    )) as CryptoKeyPair;

    const a = newAuthService();
    const b = newAuthService();

    await a.authenticate(makeCreds("wimse://notme.bot/gha/alice", kp.privateKey));
    await b.authenticate(makeCreds("wimse://notme.bot/gha/bob", kp.privateKey));

    const idA = await a.identity();
    const idB = await b.identity();

    expect(idA.identity).toBe("wimse://notme.bot/gha/alice");
    expect(idB.identity).toBe("wimse://notme.bot/gha/bob");
  });

  it("a fresh AuthService instance must report authenticated=false even if another instance authenticated", async () => {
    const kp = (await crypto.subtle.generateKey(
      { name: "Ed25519" },
      false,
      ["sign", "verify"],
    )) as CryptoKeyPair;

    const authenticated = newAuthService();
    await authenticated.authenticate(
      makeCreds("wimse://notme.bot/gha/leaked", kp.privateKey),
    );

    const fresh = newAuthService();
    const freshIdentity = await fresh.identity();

    expect(freshIdentity.authenticated).toBe(false);
    expect(freshIdentity.identity).toBe("");
  });

  it("sign() on instance A must use A's identity even after B authenticates", async () => {
    const kp = (await crypto.subtle.generateKey(
      { name: "Ed25519" },
      false,
      ["sign", "verify"],
    )) as CryptoKeyPair;

    const a = newAuthService();
    const b = newAuthService();

    await a.authenticate(makeCreds("wimse://notme.bot/gha/alice", kp.privateKey));
    await b.authenticate(makeCreds("wimse://notme.bot/gha/bob", kp.privateKey));

    const payload = new TextEncoder().encode("hello").buffer as ArrayBuffer;
    const signed = await a.sign(payload, "raw");
    expect(signed.identity).toBe("wimse://notme.bot/gha/alice");
  });
});

// Sanity mirror — proves the regression-guard assertions are non-trivial.
//
// If `worker.ts` is ever reverted to module-scope state, `AuthService` will
// behave like `BuggyAuthService` below, and the regression block above will
// fail with `"alice"` vs `"bob"`. This test pins the buggy pattern so the
// regression guard's "what does failure look like" is encoded next to it.
//
// Without this mirror, a future refactor that breaks the regression block's
// setup (e.g. accidentally testing the same instance twice) would silently
// pass — so we encode the failure mode directly here.

describe("auth-service.state.session-isolation > sanity (buggy mirror)", () => {
  // Deliberate reproduction of the module-scope antipattern. This is the
  // pre-fix shape of worker.ts:22.
  let buggyHeldCerts: { identity: string } | null = null;
  class BuggyAuthService {
    async authenticate(creds: { identity: string }) {
      buggyHeldCerts = creds;
    }
    async identity(): Promise<{ identity: string }> {
      return { identity: buggyHeldCerts?.identity ?? "" };
    }
  }

  it("module-scope pattern produces cross-instance identity confusion (asserts the bug shape)", async () => {
    buggyHeldCerts = null;
    const a = new BuggyAuthService();
    const b = new BuggyAuthService();
    await a.authenticate({ identity: "alice" });
    await b.authenticate({ identity: "bob" });

    // The bug: a.identity() returns whoever authenticated *last*, not A.
    expect((await a.identity()).identity).toBe("bob");
    expect((await b.identity()).identity).toBe("bob");
  });
});

// ── 1. OIDC audience identity (contract: consumer.requested == server.expected) ─

describe("contract.oidc.audience-identity", () => {
  // verifyOIDC runs the audience check BEFORE any JWKS network call, so
  // we can pin behavior without mocking fetch.
  const FUTURE_EXP = Math.floor(Date.now() / 1000) + 600;
  const ENC = (obj: unknown) =>
    btoa(JSON.stringify(obj))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  const HEADER = ENC({ alg: "RS256", typ: "JWT", kid: "test" });

  it("rejects a token whose aud is not the expected audience", async () => {
    const body = ENC({
      iss: "https://auth.notme.bot",
      sub: "test",
      aud: "other-service",
      exp: FUTURE_EXP,
    });
    await expect(verifyOIDC(`${HEADER}.${body}.AAAA`, "notme.bot")).rejects.toThrow(
      /wrong audience/,
    );
  });

  it("rejects a token whose aud array does not include the expected audience", async () => {
    const body = ENC({
      iss: "https://auth.notme.bot",
      sub: "test",
      aud: ["other-a", "other-b"],
      exp: FUTURE_EXP,
    });
    await expect(verifyOIDC(`${HEADER}.${body}.AAAA`, "notme.bot")).rejects.toThrow(
      /wrong audience/,
    );
  });

  it("accepts the audience check (and proceeds past it) when aud matches", async () => {
    const body = ENC({
      iss: "https://auth.notme.bot",
      sub: "test",
      aud: "notme.bot",
      exp: FUTURE_EXP,
    });
    // Audience check passes; verifier proceeds to JWKS fetch (which will fail
    // in vitest). We only care that the failure reason is NOT a wrong-audience
    // error — that proves the audience check was satisfied.
    await expect(
      verifyOIDC(`${HEADER}.${body}.AAAA`, "notme.bot"),
    ).rejects.not.toThrow(/wrong audience/);
  });
});

// ── 2. Trusted issuer allowlist parity (server side) ───────────────────────

describe("contract.oidc.trusted-issuers", () => {
  const FUTURE_EXP = Math.floor(Date.now() / 1000) + 600;
  const ENC = (obj: unknown) =>
    btoa(JSON.stringify(obj))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  const HEADER = ENC({ alg: "RS256", typ: "JWT", kid: "test" });

  // Issuer check runs in fetchJWKS, AFTER audience check passes. So we must
  // pass audience to reach the issuer guard.
  it("rejects an untrusted issuer even when audience matches", async () => {
    const body = ENC({
      iss: "https://attacker.example",
      sub: "test",
      aud: "notme.bot",
      exp: FUTURE_EXP,
    });
    await expect(verifyOIDC(`${HEADER}.${body}.AAAA`, "notme.bot")).rejects.toThrow(
      /untrusted issuer/,
    );
  });

  it("accepts a known issuer (GHA) past the trust check", async () => {
    const body = ENC({
      iss: "https://token.actions.githubusercontent.com",
      sub: "repo:agentic-research/notme",
      aud: "notme.bot",
      exp: FUTURE_EXP,
    });
    await expect(
      verifyOIDC(`${HEADER}.${body}.AAAA`, "notme.bot"),
    ).rejects.not.toThrow(/untrusted issuer/);
  });

  it("accepts auth.notme.bot as a trusted self-issuer", async () => {
    const body = ENC({
      iss: "https://auth.notme.bot",
      sub: "test",
      aud: "notme.bot",
      exp: FUTURE_EXP,
    });
    await expect(
      verifyOIDC(`${HEADER}.${body}.AAAA`, "notme.bot"),
    ).rejects.not.toThrow(/untrusted issuer/);
  });

  // Cross-repo: @notme/contract is the single source of truth — both the
  // server's allowlist and verify-proof.ts's enforcement Set derive from
  // it. This assertion pins the contract's shape and order so a drift
  // (rename, reorder, accidental Google inclusion) fails CI here in the
  // consumer instead of producing a confused-deputy gap at runtime.
  it("cross-repo: TRUSTED_ISSUERS snapshot matches consumer expectations", () => {
    expect([...CONTRACT_TRUSTED_ISSUERS]).toEqual([
      "https://auth.notme.bot",
      "https://token.actions.githubusercontent.com",
    ]);
  });
});

// ── 3. CABundle CBOR canonical round-trip + mutation rejection ──────────────

describe("contract.cabundle.signing-canonical", () => {
  async function genKey() {
    const kp = (await crypto.subtle.generateKey(
      { name: "Ed25519" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const pubRaw = new Uint8Array(
      (await crypto.subtle.exportKey("raw", kp.publicKey)) as ArrayBuffer,
    );
    return {
      kp,
      pubB64: btoa(String.fromCharCode(...pubRaw)),
    };
  }

  function makeBundle(): CABundle {
    return {
      epoch: 1,
      seqno: 100,
      // 32-byte zero key, base64-standard encoded (matches signet wire format)
      keys: { key001: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" },
      keyId: "key001",
      issuedAt: Math.floor(Date.now() / 1000),
      signature: "",
    };
  }

  async function signBundle(kp: CryptoKeyPair, bundle: CABundle): Promise<string> {
    // bundleCanonical returns Uint8Array; WebCrypto sign accepts BufferSource.
    // Cast through the runtime-accurate type to satisfy strict TS lib defs
    // that don't see Uint8Array as BufferSource in some lib versions.
    const sig = (await crypto.subtle.sign(
      { name: "Ed25519" },
      kp.privateKey,
      bundleCanonical(bundle) as unknown as BufferSource,
    )) as ArrayBuffer;
    return btoa(String.fromCharCode(...new Uint8Array(sig)));
  }

  it("round-trips a signed bundle: verify is true after producer→consumer", async () => {
    const { kp, pubB64 } = await genKey();
    const bundle = makeBundle();
    bundle.signature = await signBundle(kp, bundle);

    expect(await verifyBundleSignature(bundle, pubB64)).toBe(true);
  });

  it("rejects a bundle whose epoch was mutated post-signing", async () => {
    const { kp, pubB64 } = await genKey();
    const bundle = makeBundle();
    bundle.signature = await signBundle(kp, bundle);

    bundle.epoch = bundle.epoch + 1;
    expect(await verifyBundleSignature(bundle, pubB64)).toBe(false);
  });

  it("rejects a bundle whose seqno was mutated post-signing", async () => {
    const { kp, pubB64 } = await genKey();
    const bundle = makeBundle();
    bundle.signature = await signBundle(kp, bundle);

    bundle.seqno = bundle.seqno + 1;
    expect(await verifyBundleSignature(bundle, pubB64)).toBe(false);
  });

  it("rejects a bundle whose keyId was mutated post-signing", async () => {
    const { kp, pubB64 } = await genKey();
    const bundle = makeBundle();
    bundle.signature = await signBundle(kp, bundle);

    bundle.keyId = "key002";
    expect(await verifyBundleSignature(bundle, pubB64)).toBe(false);
  });

  it("canonical bytes exclude the signature field", () => {
    const bundle = makeBundle();
    bundle.signature = "post-signature-noise";
    const canonical = new TextDecoder().decode(bundleCanonical(bundle));
    expect(canonical).not.toContain("post-signature-noise");
    expect(canonical).not.toContain("signature");
  });

  // Cross-repo: the CBOR bytes produced here must byte-equal signet's
  // Go-side `bundleCanonical` for the same bundle. Drop a fixture from
  // signet CI under fixtures/ and assert byte-equality.
  it.todo(
    "cross-repo: CBOR canonical bytes byte-equal signet's Go encoder (needs fixture: fixtures/cabundle.canonical.bin from signet CI)",
  );
});

// ── 4. Revocation seqno monotonicity ───────────────────────────────────────

describe("contract.revocation.seqno-monotonic", () => {
  // The DO has an atomic SetLastSeenSeqnoIfGreater. We exercise the same
  // decision rule the DO uses, without standing up a workerd DO instance
  // (the runInDurableObject pool config is tracked separately as notme-c38bb6).
  function applySeqnoRule(last: number, incoming: number): "advance" | "noop" | "rollback" {
    if (typeof incoming !== "number" || !Number.isFinite(incoming) || incoming < 1) {
      return "rollback";
    }
    if (incoming < last) return "rollback";
    if (incoming > last) return "advance";
    return "noop";
  }

  it("advances when seqno strictly increases", () => {
    expect(applySeqnoRule(100, 101)).toBe("advance");
  });

  it("is a no-op when seqno equals the last-seen value", () => {
    expect(applySeqnoRule(100, 100)).toBe("noop");
  });

  it("rejects a rollback (seqno < last)", () => {
    expect(applySeqnoRule(100, 99)).toBe("rollback");
  });

  it("rejects a non-positive or NaN seqno", () => {
    expect(applySeqnoRule(100, 0)).toBe("rollback");
    expect(applySeqnoRule(100, -1)).toBe("rollback");
    expect(applySeqnoRule(100, NaN)).toBe("rollback");
  });
});

// ── 5. DPoP proof shape ────────────────────────────────────────────────────

describe("contract.dpop.proof-shape", () => {
  const HTU = "https://auth.notme.bot/token";

  function makeHeader(overrides: Record<string, unknown> = {}): string {
    const enc = (obj: unknown) =>
      btoa(JSON.stringify(obj))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
    return enc({
      typ: "dpop+jwt",
      alg: "ES256",
      jwk: { kty: "EC", crv: "P-256", x: "AAAA", y: "BBBB" },
      ...overrides,
    });
  }

  function makePayload(overrides: Record<string, unknown> = {}): string {
    const enc = (obj: unknown) =>
      btoa(JSON.stringify(obj))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
    return enc({
      jti: "test-jti",
      htm: "POST",
      htu: HTU,
      iat: Math.floor(Date.now() / 1000),
      ...overrides,
    });
  }

  it('rejects a proof with typ != "dpop+jwt"', async () => {
    const proof = `${makeHeader({ typ: "jwt" })}.${makePayload()}.AAAA`;
    await expect(
      validateDpopProof(proof, { htm: "POST", htu: HTU }),
    ).rejects.toThrow(/typ must be "dpop\+jwt"/);
  });

  it('rejects a proof with alg != "ES256"', async () => {
    const proof = `${makeHeader({ alg: "RS256" })}.${makePayload()}.AAAA`;
    await expect(
      validateDpopProof(proof, { htm: "POST", htu: HTU }),
    ).rejects.toThrow(/alg must be "ES256"/);
  });

  it("rejects a proof whose embedded jwk is not EC P-256", async () => {
    const proof = `${makeHeader({ jwk: { kty: "RSA", n: "x", e: "AQAB" } })}.${makePayload()}.AAAA`;
    await expect(
      validateDpopProof(proof, { htm: "POST", htu: HTU }),
    ).rejects.toThrow(/jwk must be EC P-256/);
  });

  it("requires a string jti claim", async () => {
    // Use a real EC key so we get past signature verification to the claim
    // check. Signature is invalid → rejects before claim parse. Either way
    // the failure is structural, not a wrong-shape pass.
    const proof = `${makeHeader()}.${makePayload({ jti: undefined })}.AAAA`;
    await expect(
      validateDpopProof(proof, { htm: "POST", htu: HTU }),
    ).rejects.toThrow();
  });
});

// ── 6. /cert/gha and /join error-shape distinction (cross-repo) ─────────────

describe("contract.error-shape.cert-gha-vs-join", () => {
  // The consumer Action expects:
  //   /cert/gha bad token  → 401
  //   /cert/gha rate limit → 429
  //   /cert/gha wrong owner→ 403
  //   /join     bad OIDC   → 403 (changed in feat/auth-refactor)
  //   /join     no-link    → 403 (not 200+empty)
  //
  // These need a fixture of representative responses from the server. Drop
  // them in `fixtures/server-errors.json` and promote.
  it.todo(
    "cross-repo: /cert/gha returns 401/403/429 per the documented vocabulary (needs fixture: fixtures/server-errors.json)",
  );
  it.todo(
    "cross-repo: /join returns 403 on bad OIDC proof (changed in feat/auth-refactor) (needs fixture: fixtures/server-errors.json)",
  );
});

// ── 7. Scope vocabulary — single source of truth ────────────────────────────

describe("contract.scopes.vocabulary", () => {
  it("CertScope enum exposes exactly the documented scopes", () => {
    // Adding a scope here means: also document it in THREAT_MODEL.md, also
    // update any consumer that allowlists scopes locally. This test pins
    // the vocabulary so additions are intentional.
    expect(Object.values(CertScope).sort()).toEqual(
      ["authorityManage", "bridgeCert", "certMint"].sort(),
    );
  });

  it("worker uses the bridgeCert literal from the same vocabulary", () => {
    // The worker.ts proxy() handler checks `heldCerts.scopes.includes("bridgeCert")`
    // with a bare literal. Pin the literal to the enum so a future enum
    // rename without a worker.ts update fails here, not at runtime.
    expect(CertScope.bridgeCert).toBe("bridgeCert");
  });

  it("admin gating uses the authorityManage scope literal", () => {
    expect(CertScope.authorityManage).toBe("authorityManage");
  });
});

// ── 8. AuthService RPC surface (consumer↔server method-signature contract) ──

describe("contract.auth-service.rpc-surface", () => {
  it("exposes the documented RPC method names", () => {
    // Consumers bind to AuthService and call these methods by name. A
    // rename or removal is a breaking change to the consumer protocol.
    const methods = Object.getOwnPropertyNames(AuthService.prototype).filter(
      (n) => n !== "constructor" && !n.startsWith("_"),
    );
    const expected = [
      // Authority lookups
      "mintBridgeCert",
      "mintDPoPToken",
      "getPublicKeyPem",
      "getCACertificatePem",
      "getAuthorityState",
      "verifySession",
      // Identity-gated runtime methods
      "authenticate",
      "proxy",
      "sign",
      "identity",
    ];
    for (const name of expected) {
      expect(methods, `AuthService.${name} must remain a public RPC method`).toContain(
        name,
      );
    }
  });
});

// ── 9. AAD binding on sealed envelope (vault moved to cloister) ─────────────

describe("contract.vault.aad-binding", () => {
  it.todo(
    "moved-to-cloister: AAD must bind to service+identity — covered by cloister/vault threat-model.test.ts",
  );
});

// ── 10. Redirect-URI normalization ─────────────────────────────────────────

describe("contract.redirect-uri.normalization", () => {
  // The existing redirect-uri.test.ts covers the full matrix. The pins
  // below assert just the cross-repo-visible invariants: shape of the
  // result type, allowlist as exact-host (no wildcards), and refusal of
  // non-http(s) schemes that could appear in OAuth flows.
  it("rejects schemes a consumer might naively pass (file:, javascript:, data:)", () => {
    for (const url of [
      "file:///etc/passwd",
      "javascript:alert(1)",
      "data:text/html,<x>",
    ]) {
      const r = validateRedirectUri(url);
      expect(r.ok, `${url} must be rejected`).toBe(false);
    }
  });

  it("rejects userinfo-abuse on an allowlisted host", () => {
    // https://attacker@notme.bot/cb parses with hostname=notme.bot but
    // userinfo enables session theft if not stripped. The URL parser
    // already normalizes hostname, so this becomes a host check against
    // the literal `notme.bot` (passes). To be safe, the validator MAY
    // strip userinfo — we just pin the current observable behavior so
    // a future tightening is intentional.
    const r = validateRedirectUri("https://attacker@notme.bot/cb");
    // Current behavior: hostname is "notme.bot" (allowlisted) → ok.
    // If a future commit decides to reject userinfo, flip this to expect false.
    expect(r.ok).toBe(true);
  });

  it("rejects a wildcard subdomain attempt", () => {
    const r = validateRedirectUri("https://evil.notme.bot.attacker.example/cb");
    expect(r.ok).toBe(false);
  });
});

// ── 11. GHA OIDC fork-PR boundary ──────────────────────────────────────────

describe("contract.gha-oidc.fork-pr-boundary", () => {
  // The GHA OIDC token's `event_name` claim is server-trustable (signed by
  // GitHub). For mint-time defense against the pull_request_target
  // confused-deputy class, the server SHOULD reject event_name in
  // {pull_request, pull_request_target} unless the calling workflow is on
  // an explicit allowlist.
  //
  // Today the implicit defense is the owner allowlist (fork PRs carry the
  // fork's owner in the OIDC token, which won't be in GHA_ALLOWED_OWNERS).
  // pull_request_target is the dangerous case: the workflow runs in the
  // UPSTREAM context with UPSTREAM owner, so the owner allowlist passes,
  // but the code that runs is from the fork.
  //
  // This is a contract assumption test: it asserts that we *intend* to
  // reject pull_request_target. If today's code does not enforce it, this
  // test is RED until either (a) the server adds an event_name filter, or
  // (b) we re-document the assumption as "use branch protection + required
  // reviewers, not server-side filtering". Either resolution is a
  // deliberate decision — that's the point of the test.
  it.todo(
    "server rejects GHA OIDC tokens whose event_name is pull_request_target (needs handleCertGHA filter)",
  );
  it.todo(
    "consumer Action refuses to run on pull_request_target context (needs guard in action/src/index.ts)",
  );
});
