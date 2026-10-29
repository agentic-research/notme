/**
 * task-cert-client.test.ts — the client a MACHINE runs to hold a tier and mint
 * task certificates offline (notme-486e8a).
 *
 * The authority half is covered end to end in tier-enrolment.do.test.ts. This
 * file covers what runs on the machine: the proof it sends, the device-flow
 * poll, minting offline, and the chain check — against a locally built root
 * and tier, because the point of a task cert is that minting needs no
 * authority at all.
 */
import { X509Certificate, X509CertificateGenerator, BasicConstraintsExtension, KeyUsagesExtension, KeyUsageFlags } from "@peculiar/x509";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, existsSync, readFileSync, writeFileSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mintIssuingCaCert } from "../cert-authority";
import { ED25519 } from "../platform";
import { deviceCodeHash, tierEnrolmentBinding } from "../auth/tier-enrolment-binding";
import {
  generateTierKey, enrolProof, pollEnrolment, mintTask, verifyChain, groupFingerprint,
  exportPrivateKeyPem, importPrivateKeyPem,
} from "../../../scripts/task-cert/lib";

const ROOT_NAME = "CN=signet-authority,O=notme";

async function rootAndTier(opts: { tierTtlMs?: number } = {}) {
  const root = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
  const rootCert = await X509CertificateGenerator.createSelfSigned({
    name: ROOT_NAME,
    notBefore: new Date(Date.now() - 86_400_000),
    notAfter: new Date(Date.now() + 86_400_000 * 365),
    signingAlgorithm: ED25519,
    keys: root,
    serialNumber: "01",
    extensions: [
      new BasicConstraintsExtension(true, 1, true),
      new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign, true),
    ],
  });
  const tier = await generateTierKey();
  const tierCert = await mintIssuingCaCert(
    "alice",
    "wimse://notme.bot/principal/alice",
    tier.pem,
    root.privateKey,
    { scopes: ["bridgeCert"], epoch: 3, authMethod: "passkey", ttlMs: opts.tierTtlMs },
  );
  return { rootPem: rootCert.toString("pem"), tier, tierPem: tierCert.certificate };
}

describe("the enrolment proof", () => {
  it("verifies under the SHARED binding the authority checks", async () => {
    const k = await generateTierKey();
    const proof = await enrolProof(k.privateKey, k.spki, "device-code-1");
    const sig = Uint8Array.from(atob(proof.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (proof.length % 4)) % 4)), (c) => c.charCodeAt(0));
    const input = tierEnrolmentBinding(k.spki, await deviceCodeHash("device-code-1"));
    expect(await crypto.subtle.verify(ED25519, k.publicKey, sig, input)).toBe(true);
    // Bound to the device code: the same key over a different code fails.
    const other = tierEnrolmentBinding(k.spki, await deviceCodeHash("device-code-2"));
    expect(await crypto.subtle.verify(ED25519, k.publicKey, sig, other)).toBe(false);
  });

  it("fingerprints group in fours, matching the approval page", () => {
    expect(groupFingerprint("546b822cdad7f8c9aaaa")).toBe("546b 822c dad7 f8c9");
  });
});

describe("the private key survives a round trip to disk format", () => {
  it("PKCS#8 PEM out, non-extractable key back, still signs", async () => {
    const k = await generateTierKey();
    const back = await importPrivateKeyPem(await exportPrivateKeyPem(k.privateKey));
    expect(back.extractable).toBe(false);
    const msg = new TextEncoder().encode("x");
    const sig = await crypto.subtle.sign(ED25519, back, msg);
    expect(await crypto.subtle.verify(ED25519, k.publicKey, sig, msg)).toBe(true);
  });
});

describe("polling the device flow", () => {
  const reply = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });

  it("waits through authorization_pending, then returns the tier", async () => {
    const seq = [
      reply(400, { error: "authorization_pending" }),
      reply(400, { error: "authorization_pending" }),
      reply(200, { certificate: "PEM", authority: { epoch: 3 } }),
    ];
    let calls = 0;
    const r = await pollEnrolment("https://a.example", "dc", "proof", {
      interval: 0, expiresIn: 60, fetchFn: (async () => seq[calls++]!) as any, sleep: async () => {},
    });
    expect(calls).toBe(3);
    expect(r.certificate).toBe("PEM");
  });

  it("stops on a terminal error instead of polling forever", async () => {
    for (const error of ["expired_token", "invalid_grant", "invalid_proof"]) {
      let calls = 0;
      await expect(
        pollEnrolment("https://a.example", "dc", "p", {
          interval: 0, expiresIn: 60,
          fetchFn: (async () => { calls++; return reply(error === "invalid_proof" ? 401 : 400, { error }); }) as any,
          sleep: async () => {},
        }),
      ).rejects.toThrow(error);
      expect(calls).toBe(1);
    }
  });
});

describe("minting a task certificate offline", () => {
  it("produces a pair that chains root → tier → task, named for the task", async () => {
    const { rootPem, tier, tierPem } = await rootAndTier();
    const t = await mintTask(tierPem, tier.privateKey, { task: "rosary-056d96", goal: "dispatch identity", epoch: 3 });
    expect(t.identity).toBe("wimse://notme.bot/principal/alice/rosary-056d96");
    for (const leaf of [t.certificates.signing, t.certificates.mtls]) {
      expect(await verifyChain(rootPem, tierPem, leaf)).toEqual({ ok: true });
    }
  });

  it("commits to the goal: the goal hash is SHA-256 of the goal text", async () => {
    const { tier, tierPem } = await rootAndTier();
    const t = await mintTask(tierPem, tier.privateKey, { task: "t1", goal: "the goal", epoch: 3 });
    const want = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("the goal"))))
      .map((b) => b.toString(16).padStart(2, "0")).join("");
    expect(t.goalHash).toBe(want);
  });

  it("verifyChain refuses a task cert from a DIFFERENT tier", async () => {
    const a = await rootAndTier();
    const b = await rootAndTier();
    const t = await mintTask(b.tierPem, b.tier.privateKey, { task: "t1", goal: "g", epoch: 3 });
    const r = await verifyChain(a.rootPem, a.tierPem, t.certificates.signing);
    expect(r.ok).toBe(false);
  });

  it("verifyChain refuses a task cert outside its validity window", async () => {
    const { rootPem, tier, tierPem } = await rootAndTier();
    const t = await mintTask(tierPem, tier.privateKey, { task: "t1", goal: "g", epoch: 3 });
    const later = new Date(Date.now() + 24 * 3600_000);
    const r = await verifyChain(rootPem, tierPem, t.certificates.signing, later);
    expect(r).toMatchObject({ ok: false });
  });

  it("refuses to mint under a tier whose key it does not hold", async () => {
    const { tierPem } = await rootAndTier();
    const wrong = await generateTierKey();
    await expect(mintTask(tierPem, wrong.privateKey, { task: "t1", goal: "g", epoch: 3 })).rejects.toThrow();
  });
});

// ── renewal, subtasks, ledger, revocation (notme-337d82, notme-9f84e6) ──────
import { renewProof, isRevokedTask, taskOutDir } from "../../../scripts/task-cert/lib";
import { tierRenewalBinding } from "../auth/tier-enrolment-binding";

describe("renewal proof", () => {
  it("verifies under the SHARED renewal binding, bound to its timestamp", async () => {
    const k = await generateTierKey();
    const iat = 1_800_000_000;
    const proof = await renewProof(k.privateKey, k.spki, iat);
    const sig = Uint8Array.from(atob(proof.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (proof.length % 4)) % 4)), (c) => c.charCodeAt(0));
    expect(await crypto.subtle.verify(ED25519, k.publicKey, sig, tierRenewalBinding(k.spki, iat))).toBe(true);
    expect(await crypto.subtle.verify(ED25519, k.publicKey, sig, tierRenewalBinding(k.spki, iat + 1))).toBe(false);
  });
});

describe("local revocation is by task PREFIX, on segment boundaries", () => {
  const revoked = ["build", "deploy/prod"];
  it("revokes the task itself and everything derived from it", () => {
    expect(isRevokedTask("build", revoked)).toBe(true);
    expect(isRevokedTask("build/compile", revoked)).toBe(true);
    expect(isRevokedTask("build/compile/linker", revoked)).toBe(true);
    expect(isRevokedTask("deploy/prod/canary", revoked)).toBe(true);
  });
  it("does not revoke a sibling that merely shares characters", () => {
    expect(isRevokedTask("build2", revoked)).toBe(false);
    expect(isRevokedTask("deploy/production", revoked)).toBe(false);
  });
  it("does not revoke an ancestor of a revoked task", () => {
    expect(isRevokedTask("deploy", revoked)).toBe(false);
  });
});

describe("task output paths", () => {
  it("nest subtasks under their parent, one directory per segment", () => {
    expect(taskOutDir("/home/u/.notme/tasks", "build/compile")).toBe("/home/u/.notme/tasks/build/compile");
  });
});

// ── renewal with a generation (notme-747cc7) ────────────────────────────────
import {
  renewTier, renewTierInDir, saveEnrolment, loadPending, acquireRenewLock, savePendingExclusive, AuthorityRefusal, CLIENT_RESEND_WINDOW_S, type PendingRenewal,
} from "../../../scripts/task-cert/lib";
import { tierRenewalBindingV2 } from "../auth/tier-enrolment-binding";

describe("renewal with a generation", () => {
  afterEach(() => vi.useRealTimers());
  const fromB64url = (s: string) =>
    Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4)), (c) => c.charCodeAt(0));
  const okBody = { certificate: "PEM", expires_at: 1, renew_until: 2, authority: { epoch: 3 }, generation: 4 };
  const reply = (status: number, body: unknown) =>
    ({ ok: status >= 200 && status < 300, status, json: async () => body }) as unknown as Response;

  function harness() {
    const events: string[] = [];
    let saved: PendingRenewal | null = null;
    return {
      events,
      get saved() { return saved; },
      opts: (extra: { generation?: number; pending?: PendingRenewal | null } = {}) => ({
        ...extra,
        savePending: (p: PendingRenewal) => { saved = p; events.push("save"); },
        clearPending: () => { saved = null; events.push("clear"); },
      }),
    };
  }

  it("signs v2 over the stored generation", async () => {
    const k = await generateTierKey();
    const h = harness();
    let sent: any;
    const fetchFn = (async (_u: string, init: any) => { sent = JSON.parse(init.body); return reply(200, okBody); }) as unknown as typeof fetch;
    await renewTier("https://a", k, h.opts({ generation: 3 }), fetchFn);
    expect(sent.generation).toBe(3);
    expect(await crypto.subtle.verify(ED25519, k.publicKey, fromB64url(sent.proof), tierRenewalBindingV2(k.spki, sent.iat, 3))).toBe(true);
  });

  it("saves the request before sending, clears it after a definitive answer", async () => {
    for (const status of [200, 403]) {
      const k = await generateTierKey();
      const h = harness();
      const fetchFn = (async () => { h.events.push("fetch"); return reply(status, status === 200 ? okBody : { error: "fork_detected" }); }) as unknown as typeof fetch;
      const p = renewTier("https://a", k, h.opts({ generation: 0 }), fetchFn);
      if (status === 403) await expect(p).rejects.toThrow("fork_detected"); else await p;
      expect(h.events).toEqual(["save", "fetch", "clear"]);
      expect(h.saved).toBeNull();
    }
  });

  it("a network failure leaves the pending request; the next call resends the same bytes", async () => {
    const k = await generateTierKey();
    const h = harness();
    const bodies: string[] = [];
    const boom = (async (_u: string, init: any) => { bodies.push(init.body); throw new Error("network down"); }) as unknown as typeof fetch;
    await expect(renewTier("https://a", k, h.opts({ generation: 2 }), boom)).rejects.toThrow("network down");
    expect(h.saved).not.toBeNull();
    expect(h.events).toEqual(["save"]);
    const ok = (async (_u: string, init: any) => { bodies.push(init.body); return reply(200, okBody); }) as unknown as typeof fetch;
    await renewTier("https://a", k, h.opts({ generation: 2, pending: h.saved }), ok);
    expect(bodies).toHaveLength(2);
    expect(bodies[1]).toBe(bodies[0]);
    expect(h.saved).toBeNull();
  });

  it("a pending request older than the retry window stops instead of signing", async () => {
    const k = await generateTierKey();
    const h = harness();
    let called = false;
    const fetchFn = (async () => { called = true; return reply(200, okBody); }) as unknown as typeof fetch;
    const pending: PendingRenewal = { body: "{}", iat: Math.floor(Date.now() / 1000) - (CLIENT_RESEND_WINDOW_S + 1), generation: 1 };
    await expect(renewTier("https://a", k, h.opts({ generation: 1, pending }), fetchFn)).rejects.toThrow("renewal state lost");
    expect(called).toBe(false);
    expect(h.events).toEqual([]);
  });

  it("a pending request is resent verbatim and never re-signed, even when a generation is known", async () => {
    const k = await generateTierKey();
    const h = harness();
    let sent = "";
    const fetchFn = (async (_u: string, init: any) => { sent = init.body; return reply(200, okBody); }) as unknown as typeof fetch;
    const pending: PendingRenewal = { body: '{"exact":"bytes"}', iat: Math.floor(Date.now() / 1000) - 60, generation: 9 };
    await renewTier("https://a", k, h.opts({ generation: 9, pending }), fetchFn);
    expect(sent).toBe(pending.body);
    expect(h.events).toEqual(["clear"]);
  });

  it("legacy tier.json without a generation renews with v1", async () => {
    const k = await generateTierKey();
    const h = harness();
    let sent: any;
    const fetchFn = (async (_u: string, init: any) => { sent = JSON.parse(init.body); return reply(200, okBody); }) as unknown as typeof fetch;
    await renewTier("https://a", k, h.opts(), fetchFn);
    expect("generation" in sent).toBe(false);
    expect(await crypto.subtle.verify(ED25519, k.publicKey, fromB64url(sent.proof), tierRenewalBinding(k.spki, sent.iat))).toBe(true);
  });

  it("returns the response generation to persist", async () => {
    const k = await generateTierKey();
    const r = await renewTier("https://a", k, harness().opts({ generation: 3 }), (async () => reply(200, okBody)) as unknown as typeof fetch);
    expect(r.generation).toBe(4);
  });

  const NOW = 1_900_000_000;
  const freeze = () => vi.useFakeTimers({ toFake: ["Date"], now: NOW * 1000 });
  const pendingAt = (age: number): PendingRenewal => ({ body: '{"sealed":1}', iat: NOW - age, generation: 5 });
  const withFetch = (res: () => Response | Promise<Response>, seen: string[] = []) =>
    (async (_u: string, init: any) => { seen.push(init.body); return res(); }) as unknown as typeof fetch;
  const textReply = (status: number) =>
    ({ ok: false, status, json: async () => { throw new SyntaxError("not json"); } }) as unknown as Response;

  it("the client stops resending at the window minus the skew (boundary)", async () => {
    freeze();
    const k = await generateTierKey();
    expect(CLIENT_RESEND_WINDOW_S).toBe(3480);
    const seen: string[] = [];
    await renewTier("https://a", k, harness().opts({ pending: pendingAt(3480) }), withFetch(() => reply(200, okBody), seen));
    expect(seen).toHaveLength(1);
    await expect(renewTier("https://a", k, harness().opts({ pending: pendingAt(3481) }), withFetch(() => reply(200, okBody), seen))).rejects.toThrow("renewal state lost");
    expect(seen).toHaveLength(1);
  });

  it("keeps pending on 429, 5xx, 3xx, 408 and on a non-JSON 4xx", async () => {
    freeze();
    for (const mk of [() => reply(429, { error: "rate_limited" }), () => reply(503, { error: "x" }), () => reply(302, {}), () => reply(408, { error: "t" }), () => textReply(403), () => textReply(404)]) {
      const k = await generateTierKey();
      const h = harness();
      await expect(renewTier("https://a", k, h.opts({ pending: pendingAt(10) }), withFetch(mk))).rejects.toThrow();
      expect(h.events).not.toContain("clear");
      // and on a first attempt too
      const h2 = harness();
      await expect(renewTier("https://a", k, h2.opts({ generation: 1 }), withFetch(mk))).rejects.toThrow();
      expect(h2.events).toEqual(["save"]);
    }
  });

  it("a definitive refusal of a RESEND keeps pending and says the state is lost", async () => {
    freeze();
    const k = await generateTierKey();
    const h = harness();
    await expect(renewTier("https://a", k, h.opts({ pending: pendingAt(10) }), withFetch(() => reply(403, { error: "fork_detected" }))))
      .rejects.toThrow(/renewal state lost \(fork_detected\).*task-cert enroll/);
    expect(h.events).toEqual([]);
  });

  it("a definitive refusal on a FIRST attempt clears pending and throws the reason", async () => {
    const k = await generateTierKey();
    const h = harness();
    const err = await renewTier("https://a", k, h.opts({ generation: 1 }), withFetch(() => reply(403, { error: "revoked" }))).catch((e) => e);
    expect(err).toBeInstanceOf(AuthorityRefusal);
    expect(err.reason).toBe("revoked");
    expect(h.events).toEqual(["save", "clear"]);
  });

  it("an invalid 2xx keeps pending and never persists", async () => {
    for (const bad of [{ ...okBody, certificate: undefined }, { ...okBody, generation: -1 }, { ...okBody, generation: 1.5 }, {}]) {
      const k = await generateTierKey();
      const h = harness();
      let persisted = false;
      await expect(renewTier("https://a", k, { ...h.opts({ generation: 1 }), persist: () => { persisted = true; } }, withFetch(() => reply(200, bad)))).rejects.toThrow("invalid");
      expect(h.events).toEqual(["save"]);
      expect(persisted).toBe(false);
    }
  });

  it("persist throwing keeps pending", async () => {
    const k = await generateTierKey();
    const h = harness();
    await expect(renewTier("https://a", k, { ...h.opts({ generation: 1 }), persist: () => { throw new Error("disk full"); } }, withFetch(() => reply(200, okBody)))).rejects.toThrow("disk full");
    expect(h.events).toEqual(["save"]);
  });

  describe("on disk", () => {
    const tmp = () => mkdtempSync(join(tmpdir(), "task-cert-test-"));
    const inDir = (dir: string, k: Awaited<ReturnType<typeof generateTierKey>>, generation: number | undefined, f: typeof fetch, o: { fetchTimeoutMs?: number; persist?: (r: any) => void } = {}) =>
      renewTierInDir(dir, async () => ({ authority: "https://a", key: k, generation }), o, f);

    it("re-enrolling clears a stale pending file", () => {
      const dir = tmp();
      writeFileSync(join(dir, "renew-pending.json"), JSON.stringify(pendingAt(99999)));
      saveEnrolment(dir, { keyPem: "K", tierPem: "T", rootPem: "R", meta: { generation: 0 } });
      expect(existsSync(join(dir, "renew-pending.json"))).toBe(false);
      expect(JSON.parse(readFileSync(join(dir, "tier.json"), "utf8")).generation).toBe(0);
    });

    it("two concurrent renewals produce one signed request", async () => {
      const dir = tmp();
      const k = await generateTierKey();
      const seen: string[] = [];
      let release!: () => void;
      const gate = new Promise<void>((r) => (release = r));
      const slow = withFetch(async () => { await gate; return reply(200, okBody); }, seen);
      const first = inDir(dir, k, 2, slow);
      await vi.waitFor(() => expect(seen).toHaveLength(1));
      await expect(inDir(dir, k, 2, slow)).rejects.toThrow("in progress");
      expect(seen).toHaveLength(1);
      release();
      await first;
      expect(existsSync(join(dir, "renew-pending.json"))).toBe(false);
      expect(existsSync(join(dir, "renew.lock"))).toBe(false);
    });

    it("an existing pending file is resent by the next call, not replaced", async () => {
      const dir = tmp();
      const k = await generateTierKey();
      const seen: string[] = [];
      await expect(inDir(dir, k, 2, (async (_u: string, i: any) => { seen.push(i.body); throw new Error("down"); }) as unknown as typeof fetch)).rejects.toThrow("down");
      await inDir(dir, k, 2, withFetch(() => reply(200, okBody), seen));
      expect(seen).toHaveLength(2);
      expect(seen[1]).toBe(seen[0]);
    });

    it("a corrupt pending file never signs", async () => {
      const dir = tmp();
      writeFileSync(join(dir, "renew-pending.json"), "{not json");
      const k = await generateTierKey();
      let called = false;
      await expect(inDir(dir, k, 2, withFetch(() => { called = true; return reply(200, okBody); })))
        .rejects.toThrow("renewal state lost (pending request unreadable)");
      expect(called).toBe(false);
      expect(() => loadPending(dir)).toThrow("unreadable");
      expect(existsSync(join(dir, "renew.lock"))).toBe(false);
    });

    it("the generation is read under the lock", async () => {
      const dir = tmp();
      const k = await generateTierKey();
      writeFileSync(join(dir, "tier.json"), JSON.stringify({ generation: 2 }));
      const loads: string[] = [];
      const load = async () => {
        const g = JSON.parse(readFileSync(join(dir, "tier.json"), "utf8")).generation;
        loads.push(`g${g}`);
        return { authority: "https://a", key: k, generation: g };
      };
      const persist = (r: any) => writeFileSync(join(dir, "tier.json"), JSON.stringify({ generation: r.generation }));
      const seen: string[] = [];
      let release!: () => void;
      const gate = new Promise<void>((r) => (release = r));
      const p1 = renewTierInDir(dir, load, { persist }, withFetch(async () => { await gate; return reply(200, { ...okBody, generation: 3 }); }, seen));
      await vi.waitFor(() => expect(seen).toHaveLength(1));
      await expect(renewTierInDir(dir, load, { persist }, withFetch(() => reply(200, okBody), seen))).rejects.toThrow("in progress");
      expect(loads).toEqual(["g2"]); // the second never even read state while the first held the lock
      release();
      await p1;
      await renewTierInDir(dir, load, { persist }, withFetch(() => reply(200, okBody), seen));
      expect(loads).toEqual(["g2", "g3"]);
      expect(JSON.parse(seen[1]!).generation).toBe(3);
    });

    it("a live lock is never stolen, even if empty", () => {
      const dir = tmp();
      writeFileSync(join(dir, "renew.lock"), "");
      expect(() => acquireRenewLock(dir)).toThrow("in progress");
      writeFileSync(join(dir, "renew.lock"), "garbage");
      expect(() => acquireRenewLock(dir)).toThrow("in progress");
    });

    it("release does not remove someone else's lock", () => {
      const dir = tmp();
      const a = acquireRenewLock(dir);
      writeFileSync(join(dir, "renew.lock"), "someone-else");
      a.release();
      expect(readFileSync(join(dir, "renew.lock"), "utf8")).toBe("someone-else");
    });

    it("a stale lock is stolen by exactly one of two stealers", () => {
      const dir = tmp();
      const lock = join(dir, "renew.lock");
      writeFileSync(lock, "dead-holder");
      utimesSync(lock, 1, 1);
      let b: ReturnType<typeof acquireRenewLock> | undefined;
      // Stealer A has judged the lock stale; before it moves, stealer B steals it and takes a fresh one.
      expect(() => acquireRenewLock(dir, { onStale: () => { b = acquireRenewLock(dir, { onStale: undefined }); } })).toThrow("in progress");
      expect(b).toBeDefined();
      expect(readFileSync(lock, "utf8")).toBe(b!.token);
    });

    it("the fetch is aborted at the timeout and pending is kept", async () => {
      const dir = tmp();
      const k = await generateTierKey();
      const hang = ((_u: string, init: any) =>
        new Promise((_res, rej) => init.signal?.addEventListener("abort", () => rej(new DOMException("aborted", "TimeoutError"))))) as unknown as typeof fetch;
      await expect(inDir(dir, k, 1, hang, { fetchTimeoutMs: 20 })).rejects.toThrow();
      expect(loadPending(dir)).not.toBeNull();
      expect(existsSync(join(dir, "renew.lock"))).toBe(false);
    });

    it("the link() backstop alone prevents a double sign", () => {
      const dir = tmp();
      savePendingExclusive(dir, pendingAt(1));
      expect(() => savePendingExclusive(dir, { body: "second", iat: NOW, generation: 5 })).toThrow("already saved");
      expect(loadPending(dir)!.body).toBe('{"sealed":1}');
    });
  });
});
