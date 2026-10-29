/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * ct-mint.do.test.ts — every bridge pair the authority mints is logged, or
 * backlogged, and never refused because of the log (notme-1b46a8, Task 2).
 *
 * Runs ONLY under vitest.workers.ct.config.mts, which binds CT_LOG to a stub
 * log whose behaviour each test selects over the binding itself
 * (POST /__control) and which records what it received (GET /__received).
 * The main pool config excludes this file, so every other suite mints with no
 * binding at all.
 *
 * What it pins, against the plan's Review Focus:
 *   - RF5 / absent: no binding → today's extension set, no backlog, no calls.
 *   - ok: both certs embed an SCT from THIS log, pinned to their precerts.
 *   - RF2: the SCT signs exactly the final cert's bytes — the RFC 6962 §3.2
 *     reconstruction from the final cert equals the precert the log saw.
 *   - RF1: one half of the pair fails → neither is logged, both backlogged,
 *     the caller still gets a working pair.
 *   - RF3: a log that never answers → the mint finishes inside the bound.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { X509Certificate } from "@peculiar/x509";
import { describe, expect, it } from "vitest";
import { CT_POISON_OID, CT_SCT_LIST_OID, type SctResponse } from "./ct/sct";
import { parseLogPin, spkiOf, tbsWithout, verifySct, type LogPin } from "./ct/verify-sct";

const SUBJECT = "repo:agentic-research/notme:ref:refs/heads/main";
const CT_TIMEOUT_MS = 2000;

type Mode =
  | "ok"
  | "500"
  | "hang"
  | "ok-then-fail"
  | "fail-second"
  | "fail-signing"
  | "wrong-id"
  | "bad-sig";
interface Received {
  path: string;
  chain: string[];
}
interface BacklogRow {
  chain_json: string;
  created_at: number;
  attempts: number;
  logged_at: number | null;
}
type AuthLike = {
  env: Record<string, unknown>;
  getCACertificatePem(): Promise<string>;
  getAuthorityState(): Promise<{ epoch: number }>;
  mintBridgeCertPair(p: {
    subject: string;
    identity: string;
    mtlsPublicKeyPem: string;
    signingPublicKeyPem: string;
    scopes: string[];
    authMethod: string;
    ttlMs?: number;
  }): Promise<{ certificates: { mtls: string; signing: string } }>;
  getAlarmHealth(): Promise<{ ct: CtHealthView }>;
  ctx: { storage: { sql: { exec(q: string): { toArray(): unknown[] } } } };
};
interface CtHealthView {
  backlog: number;
  oldestUnloggedAgeS: number | null;
  gaveUp: number;
  lastError: string;
  lastErrorAt: number;
  unloggable: { count: number; lastAt: number; reason: string };
  embedFailed: { count: number; lastAt: number };
  configError: string | null;
}

const ctLog = (): Fetcher => {
  const f = (env as unknown as { CT_LOG?: Fetcher }).CT_LOG;
  if (!f) throw new Error("CT_LOG is not bound — run under vitest.workers.ct.config.mts");
  return f;
};

/** Select the stub's behaviour; returns its log id and public key (SPKI). */
async function setMode(mode: Mode): Promise<string> {
  return (await control(mode)).id;
}
async function control(mode: Mode): Promise<{ id: string; spki: string }> {
  const r = await ctLog().fetch("https://ct-log/__control", {
    method: "POST",
    body: JSON.stringify({ mode }),
  });
  return (await r.json()) as { id: string; spki: string };
}

async function received(): Promise<Received[]> {
  return (await (await ctLog().fetch("https://ct-log/__received")).json()) as Received[];
}

const spkiPem = async (k: CryptoKey) => {
  const s = (await crypto.subtle.exportKey("spki", k)) as ArrayBuffer;
  const b = btoa(String.fromCharCode(...new Uint8Array(s)));
  return `-----BEGIN PUBLIC KEY-----\n${b.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
};
const pemBody = (p: string) => p.replace(/-----[A-Z ]+-----|\s/g, "");
const fromB64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

let seq = 0;

/**
 * Mint through the DO's public method, on a fresh authority so its backlog is
 * this test's alone. `unbind` deletes CT_LOG from that DO's env first: the
 * exact "absent binding" state, in the same isolate as the bound runs.
 * `envPatch` overrides (undefined deletes) env vars such as CT_LOG_KEY;
 * `before` runs inside the DO just before the mint.
 */
async function mint(
  opts: {
    unbind?: boolean;
    envPatch?: Record<string, string | undefined>;
    before?: (a: AuthLike) => Promise<void> | void;
  } = {},
) {
  const name = `ct-mint-${++seq}-${crypto.randomUUID()}`;
  const stub = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(name));
  const mtls = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
  )) as CryptoKeyPair;
  const sign = (await crypto.subtle.generateKey(
    { name: "Ed25519" }, true, ["sign", "verify"],
  )) as CryptoKeyPair;
  const mtlsPem = await spkiPem(mtls.publicKey);
  const signPem = await spkiPem(sign.publicKey);

  return runInDurableObject(stub, async (auth) => {
    const a = auth as unknown as AuthLike;
    if (opts.unbind) {
      const e = { ...a.env };
      delete e.CT_LOG;
      a.env = e;
    }
    if (opts.envPatch) {
      const e = { ...a.env };
      for (const [k, v] of Object.entries(opts.envPatch)) {
        if (v === undefined) delete e[k];
        else e[k] = v;
      }
      a.env = e;
    }
    if (opts.before) {
      await a.getAuthorityState(); // init: the schema exists before `before` touches it
      await opts.before(a);
    }
    const t0 = Date.now();
    const pair = await a.mintBridgeCertPair({
      subject: SUBJECT,
      identity: `wimse://notme.bot/principal/${name}`,
      mtlsPublicKeyPem: mtlsPem,
      signingPublicKeyPem: signPem,
      scopes: ["bridgeCert"],
      authMethod: "gha-oidc",
    });
    const elapsed = Date.now() - t0;
    // Read AFTER the mint. On a fresh authority the first getCACertificatePem
    // caches its root under the key id read before the key existed (''), so
    // the next call re-issues it — same key, new serial. Read once the key
    // exists, the root is the stable one the mint chained to (notme-7aa6dd).
    const ca = await a.getCACertificatePem();
    const backlog = a.ctx.storage.sql
      .exec("SELECT chain_json, created_at, attempts, logged_at FROM ct_backlog ORDER BY id")
      .toArray() as BacklogRow[];

    // Today's behaviour, for RF5: the same mint function with no pin and no
    // extra extension, which is exactly what the DO called before CT.
    const state = await a.getAuthorityState();
    const row = a.ctx.storage.sql
      .exec("SELECT private_jwk FROM keys WHERE id = 'authority'")
      .toArray()[0] as { private_jwk: string };
    const { ED25519 } = await import("./platform");
    const signingKey = await crypto.subtle.importKey(
      "jwk", JSON.parse(row.private_jwk), ED25519, false, ["sign"],
    );
    const { mintBridgeCertPair } = await import("./cert-authority");
    const today = await mintBridgeCertPair(
      SUBJECT, `wimse://notme.bot/principal/${name}`, mtlsPem, signPem, signingKey,
      { scopes: ["bridgeCert"], epoch: state.epoch, authMethod: "gha-oidc" },
    );

    const health = (await a.getAlarmHealth()).ct;
    return {
      ca,
      health,
      mtls: pair.certificates.mtls,
      signing: pair.certificates.signing,
      today,
      backlog,
      elapsed,
      mtlsPub: mtls.publicKey,
      signPub: sign.publicKey,
    };
  });
}

const oids = (pem: string) => new X509Certificate(pem).extensions.map((e) => e.type);

/** The TLS-encoded SCTs inside an embedded SCT list extension. */
function embeddedScts(pem: string): Uint8Array[] {
  const ext = new X509Certificate(pem).getExtension(CT_SCT_LIST_OID)!;
  const v = new Uint8Array(ext.value);
  // OCTET STRING wrapping the TLS list (short or 1/2-byte long form).
  expect(v[0]).toBe(0x04);
  const n = v[1]! & 0x80 ? v[1]! & 0x7f : 0;
  const list = v.subarray(2 + n);
  expect((list[0]! << 8) | list[1]!).toBe(list.length - 2);
  const out: Uint8Array[] = [];
  for (let at = 2; at < list.length; ) {
    const len = (list[at]! << 8) | list[at + 1]!;
    out.push(list.subarray(at + 2, at + 2 + len));
    at += 2 + len;
  }
  return out;
}

/** An embedded (TLS-encoded) SCT back to the JSON shape a log returns. */
function sctFromTls(sct: Uint8Array): SctResponse {
  expect(sct[0], "SCT v1").toBe(0);
  let ts = 0n;
  for (const b of sct.subarray(33, 41)) ts = (ts << 8n) | BigInt(b);
  const extLen = (sct[41]! << 8) | sct[42]!;
  const b64 = (u: Uint8Array) => btoa(String.fromCharCode(...u));
  return {
    sct_version: 0,
    id: b64(sct.subarray(1, 33)),
    timestamp: Number(ts),
    extensions: b64(sct.subarray(43, 43 + extLen)),
    signature: b64(sct.subarray(43 + extLen)),
  };
}

/** The stub log as the authority pins it. */
async function stubPin(k: { id: string; spki: string }): Promise<LogPin> {
  const pin = await parseLogPin(k.id, k.spki);
  if ("error" in pin) throw new Error(pin.error);
  return pin;
}

/**
 * RFC 6962 §3.2 verification of one embedded SCT against one final cert,
 * through PRODUCTION's verifySct (ct/verify-sct.ts): the precert_entry is
 * the final cert's TBSCertificate with the SCT list removed — which equals
 * the precert's TBS with the poison removed when the pin held — and
 * issuer_key_hash is SHA-256 of the root's SPKI.
 */
async function sctVerifies(
  sct: Uint8Array,
  finalPem: string,
  rootPem: string,
  pin: LogPin,
): Promise<boolean> {
  const tbs = tbsWithout(fromB64(pemBody(finalPem)), CT_SCT_LIST_OID);
  const issuerSpki = spkiOf(fromB64(pemBody(rootPem)));
  return (await verifySct(sctFromTls(sct), { kind: "precert", tbs, issuerSpki }, pin)) === "ok";
}

async function expectWorkingPair(r: Awaited<ReturnType<typeof mint>>) {
  const ca = new X509Certificate(r.ca);
  for (const [pem, pub] of [[r.mtls, r.mtlsPub], [r.signing, r.signPub]] as const) {
    const c = new X509Certificate(pem);
    expect(c.issuer).toBe(ca.subject);
    expect(await c.verify({ publicKey: ca.publicKey })).toBe(true);
    const want = new Uint8Array((await crypto.subtle.exportKey("spki", pub)) as ArrayBuffer);
    expect(new Uint8Array(c.publicKey.rawData)).toEqual(want);
  }
}

/** Neither cert logged; both FINAL chains (not the precerts) backlogged. */
function expectBacklogged(r: Awaited<ReturnType<typeof mint>>) {
  for (const pem of [r.mtls, r.signing]) {
    const c = new X509Certificate(pem);
    expect(c.getExtension(CT_SCT_LIST_OID), "a half-logged pair embedded an SCT").toBeFalsy();
    expect(c.getExtension(CT_POISON_OID), "the final cert kept the poison").toBeFalsy();
  }
  expect(r.backlog).toHaveLength(2);
  const chains = r.backlog.map((b) => JSON.parse(b.chain_json) as string[]);
  expect(chains.map((c) => c[0]).sort()).toEqual([pemBody(r.mtls), pemBody(r.signing)].sort());
  for (const c of chains) expect(c).toEqual([c[0], pemBody(r.ca)]);
  for (const b of r.backlog) {
    expect(b.attempts).toBe(0);
    expect(b.logged_at).toBeNull();
    expect(typeof b.created_at).toBe("number");
  }
}

describe("ct.mint — bridge pairs", () => {
  it("RF5: with CT_LOG absent the mint is today's — no poison, no SCT, no backlog, no calls", async () => {
    await setMode("ok");
    const r = await mint({ unbind: true });
    for (const pem of [r.mtls, r.signing]) {
      expect(oids(pem)).not.toContain(CT_SCT_LIST_OID);
      expect(oids(pem)).not.toContain(CT_POISON_OID);
    }
    expect(oids(r.mtls)).toEqual(oids(r.today.certificates.mtls));
    expect(oids(r.signing)).toEqual(oids(r.today.certificates.signing));
    expect(r.backlog).toEqual([]);
    expect(await received()).toEqual([]);
    await expectWorkingPair(r);
  });

  it("ok: each final cert embeds THIS log's SCT, pinned to the precert it was issued for", async () => {
    const logId = await setMode("ok");
    const r = await mint();
    const got = await received();

    // Both precerts submitted, each as [precert, root], to add-pre-chain.
    expect(got).toHaveLength(2);
    for (const g of got) {
      expect(g.path).toBe("/logs/notme/ct/v1/add-pre-chain");
      expect(g.chain).toHaveLength(2);
      expect(g.chain[1]).toBe(pemBody(r.ca));
    }
    const pres = got.map((g) => new X509Certificate(fromB64(g.chain[0]!)));
    for (const p of pres) {
      expect(p.getExtension(CT_POISON_OID)?.critical).toBe(true);
      expect(p.getExtension(CT_SCT_LIST_OID)).toBeFalsy();
    }

    for (const pem of [r.mtls, r.signing]) {
      const fin = new X509Certificate(pem);
      expect(fin.getExtension(CT_SCT_LIST_OID), "final cert not logged").toBeTruthy();
      expect(fin.getExtension(CT_POISON_OID), "the poison must come OFF").toBeFalsy();
      const pre = pres.find((p) => p.serialNumber === fin.serialNumber);
      expect(pre, "no precert shares this final cert's serial — the pin was dropped").toBeTruthy();
      expect(fin.notBefore.getTime()).toBe(pre!.notBefore.getTime());
      expect(fin.notAfter.getTime()).toBe(pre!.notAfter.getTime());

      const scts = embeddedScts(pem);
      expect(scts).toHaveLength(1);
      expect(scts[0]![0], "SCT version v1").toBe(0);
      expect(btoa(String.fromCharCode(...scts[0]!.subarray(1, 33)))).toBe(logId);
    }
    // Extension set = today's plus exactly the SCT list.
    expect(oids(r.mtls)).toEqual([...oids(r.today.certificates.mtls), CT_SCT_LIST_OID]);
    expect(oids(r.signing)).toEqual([...oids(r.today.certificates.signing), CT_SCT_LIST_OID]);
    expect(r.backlog).toEqual([]);
    await expectWorkingPair(r);
  });

  it("RF2: each cert's SCT verifies against its OWN bytes (and not the other's); §3.2 reconstruction equals the precert the log saw", async () => {
    const stubKey = await control("ok");
    const r = await mint();
    const got = await received();
    const pres = got.map((g) => fromB64(g.chain[0]!));
    for (const pem of [r.mtls, r.signing]) {
      const finDer = fromB64(pemBody(pem));
      const serial = new X509Certificate(finDer).serialNumber;
      const preDer = pres.find((p) => new X509Certificate(p).serialNumber === serial)!;
      expect(preDer).toBeTruthy();
      expect(tbsWithout(finDer, CT_SCT_LIST_OID)).toEqual(tbsWithout(preDer, CT_POISON_OID));
    }
    // The decisive check: each cert's embedded SCT VERIFIES, under the stub
    // log's key, against that cert's own reconstructed bytes — and the OTHER
    // cert's SCT does not. TBS equality above proves the pin; this proves
    // each SCT landed in the certificate it was issued for. A swapped
    // perCertExtensions mapping passes the pin check and fails here.
    const logKey = await stubPin(stubKey);
    const ownSpkiHash = new Uint8Array(await crypto.subtle.digest("SHA-256", fromB64(stubKey.spki)));
    expect(btoa(String.fromCharCode(...ownSpkiHash)), "log id = SHA-256(log SPKI)").toBe(stubKey.id);
    const sctOf = { mtls: embeddedScts(r.mtls)[0]!, signing: embeddedScts(r.signing)[0]! };
    expect(await sctVerifies(sctOf.mtls, r.mtls, r.ca, logKey), "mTLS SCT vs mTLS cert").toBe(true);
    expect(await sctVerifies(sctOf.signing, r.signing, r.ca, logKey), "signing SCT vs signing cert").toBe(true);
    expect(await sctVerifies(sctOf.signing, r.mtls, r.ca, logKey), "signing SCT must NOT verify on mTLS").toBe(false);
    expect(await sctVerifies(sctOf.mtls, r.signing, r.ca, logKey), "mTLS SCT must NOT verify on signing").toBe(false);
  });

  for (const mode of ["fail-signing", "ok-then-fail", "fail-second", "500"] as const) {
    it(`RF1 (${mode}): a half-logged pair is not minted — neither SCT, both backlogged, still a working pair`, async () => {
      await setMode(mode);
      const r = await mint();
      // Both halves were attempted, concurrently, before either failure mattered.
      expect(await received()).toHaveLength(2);
      expectBacklogged(r);
      await expectWorkingPair(r);
      // lastError names the HTTP status, not just "failed".
      expect(r.health.lastError).toMatch(/add-pre-chain failed \(.*cert \d: HTTP 500.*\); chains backlogged/);
    });
  }

  it("RF3: a log that never answers cannot stall the mint — bounded, then backlogged", async () => {
    await setMode("hang");
    const r = await mint();
    // Both submissions run concurrently, so the bound is ONE timeout, not two.
    expect(r.elapsed).toBeLessThan(CT_TIMEOUT_MS + 1500);
    // ...and it really did wait on the log: a fast failure would not prove
    // the bound, only that the stub errored.
    expect(r.elapsed).toBeGreaterThanOrEqual(CT_TIMEOUT_MS - 100);
    expectBacklogged(r);
    await expectWorkingPair(r);
    expect(r.health.lastError).toMatch(/cert 0: timeout.*cert 1: timeout/);
  });
});

// ── Final review I1: an SCT is embedded only if it is from THE pinned log ──

describe("ct.pin — only the pinned log's verified SCT is embedded", () => {
  it("the right log: embedded, verifying under the pin; health clean", async () => {
    const stubKey = await control("ok");
    const r = await mint();
    for (const pem of [r.mtls, r.signing]) {
      expect(new X509Certificate(pem).getExtension(CT_SCT_LIST_OID)).toBeTruthy();
      expect(await sctVerifies(embeddedScts(pem)[0]!, pem, r.ca, await stubPin(stubKey))).toBe(true);
    }
    expect(r.backlog).toEqual([]);
    expect(r.health.configError).toBeNull();
    expect(r.health.lastError).toBe("");
    expect(r.health.unloggable.count).toBe(0);
  });

  for (const [mode, why] of [["wrong-id", "wrong log"], ["bad-sig", "bad signature"]] as const) {
    it(`${mode}: a well-formed SCT the pin refuses is not embedded — both backlogged, lastError "${why}"`, async () => {
      await setMode(mode);
      const r = await mint();
      expect(await received()).toHaveLength(2);
      expectBacklogged(r);
      await expectWorkingPair(r);
      expect(r.health.lastError).toContain(`cert 0: ${why}`);
      expect(r.health.lastError).toContain(`cert 1: ${why}`);
      expect(r.health.backlog).toBe(2);
    });
  }

  const OTHER_ID = btoa(String.fromCharCode(...new Uint8Array(32).fill(9)));
  for (const [label, patch, reason] of [
    ["CT_LOG_KEY missing", { CT_LOG_KEY: undefined }, /CT_LOG_KEY missing/],
    ["CT_LOG_ID missing", { CT_LOG_ID: undefined }, /CT_LOG_ID missing/],
    ["CT_LOG_ID is not SHA-256(CT_LOG_KEY)", { CT_LOG_ID: OTHER_ID }, /CT_LOG_ID is not SHA-256\(CT_LOG_KEY\)/],
    ["CT_LOG_KEY not a P-256 key", { CT_LOG_KEY: btoa("not a key") }, /CT_LOG_KEY is not a P-256 SPKI/],
  ] as const) {
    it(`${label} while bound: nothing submitted, minted unlogged, counted in health`, async () => {
      await setMode("ok");
      const r = await mint({ envPatch: patch });
      expect(await received(), "an unpinned authority must not submit").toEqual([]);
      for (const pem of [r.mtls, r.signing]) {
        expect(oids(pem)).not.toContain(CT_SCT_LIST_OID);
        expect(oids(pem)).not.toContain(CT_POISON_OID);
      }
      expect(r.backlog).toEqual([]);
      await expectWorkingPair(r);
      expect(r.health.unloggable.count).toBe(1);
      expect(r.health.unloggable.reason).toMatch(/^config: /);
      expect(r.health.unloggable.reason).toMatch(reason);
      expect(r.health.configError).toMatch(reason);
    });
  }
});

describe("ct.health — failures that used to reach only console.error", () => {
  it("a failed backlog INSERT is counted as unloggable, and the mint still succeeds", async () => {
    await setMode("500");
    const r = await mint({
      before: (a) => {
        a.ctx.storage.sql.exec(
          "CREATE TRIGGER ct_backlog_refuse BEFORE INSERT ON ct_backlog BEGIN SELECT RAISE(ABORT, 'forced insert failure'); END",
        );
      },
    });
    await expectWorkingPair(r);
    expect(r.backlog).toEqual([]);
    expect(r.health.unloggable.count).toBe(1);
    expect(r.health.unloggable.reason).toMatch(/^backlog write failed: .*forced insert failure/);
    expect(r.health.embedFailed.count).toBe(0);
  });
});

// ── Task 3: tiers (Issuing CA certificates) ────────────────────────────────

type TierAuthLike = AuthLike & {
  mintIssuingCa(p: {
    subject: string;
    identity: string;
    publicKeyPem: string;
    scopes: string[];
    authMethod: string;
  }): Promise<{ certificate: string }>;
};

/** Mint a tier through the DO's public method on a fresh authority. */
async function mintTier(opts: { unbind?: boolean } = {}) {
  const name = `ct-tier-${++seq}-${crypto.randomUUID()}`;
  const stub = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(name));
  const { ED25519 } = await import("./platform");
  const tierKeys = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
  const tierPem = await spkiPem(tierKeys.publicKey);
  const identity = `wimse://notme.bot/principal/${name}`;

  return runInDurableObject(stub, async (auth) => {
    const a = auth as unknown as TierAuthLike;
    if (opts.unbind) {
      const e = { ...a.env };
      delete e.CT_LOG;
      a.env = e;
    }
    const t0 = Date.now();
    const tier = await a.mintIssuingCa({
      subject: name,
      identity,
      publicKeyPem: tierPem,
      scopes: ["bridgeCert"],
      authMethod: "passkey",
    });
    const elapsed = Date.now() - t0;
    const ca = await a.getCACertificatePem(); // after the mint — see mint()
    const backlog = a.ctx.storage.sql
      .exec("SELECT chain_json, created_at, attempts, logged_at FROM ct_backlog ORDER BY id")
      .toArray() as BacklogRow[];
    const state = await a.getAuthorityState();
    return { ca, tier: tier.certificate, backlog, elapsed, tierKeys, epoch: state.epoch };
  });
}

type TierRun = Awaited<ReturnType<typeof mintTier>>;

/** The tier still works as a CA: root → tier → task, by the real chain verifier. */
async function expectTierIssues(r: TierRun) {
  const { mintTaskCertPair } = await import("./cert-authority");
  const { verifyCertChain } = await import("./auth/verify-chain");
  const { ED25519 } = await import("./platform");
  const mtls = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
  )) as CryptoKeyPair;
  const sign = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
  const task = await mintTaskCertPair(
    r.tier, r.tierKeys.privateKey, await spkiPem(mtls.publicKey), await spkiPem(sign.publicKey),
    { task: "t", goalHash: "a".repeat(64), scopes: ["bridgeCert"], epoch: r.epoch },
  );
  const v = await verifyCertChain(task.certificates.mtls, [r.tier], r.ca, r.epoch);
  expect(v.depth).toBe(1);
  const c = new X509Certificate(r.tier);
  expect(c.issuer).toBe(new X509Certificate(r.ca).subject);
}

describe("ct.mint — tiers", () => {
  it("absent: no binding → no poison, no SCT, no backlog row, no log call", async () => {
    await setMode("ok");
    const r = await mintTier({ unbind: true });
    expect(oids(r.tier)).not.toContain(CT_SCT_LIST_OID);
    expect(oids(r.tier)).not.toContain(CT_POISON_OID);
    expect(r.backlog).toEqual([]);
    expect(await received()).toEqual([]);
    await expectTierIssues(r);
  });

  it("ok: the tier embeds an SCT that VERIFIES against its own bytes; no poison; no backlog", async () => {
    const stubKey = await control("ok");
    const r = await mintTier();
    const got = await received();
    expect(got).toHaveLength(1);
    expect(got[0]!.path).toBe("/logs/notme/ct/v1/add-pre-chain");
    expect(got[0]!.chain).toEqual([got[0]!.chain[0], pemBody(r.ca)]);

    const fin = new X509Certificate(r.tier);
    expect(fin.getExtension(CT_SCT_LIST_OID), "tier not logged").toBeTruthy();
    expect(fin.getExtension(CT_POISON_OID), "the poison must come OFF").toBeFalsy();
    const pre = new X509Certificate(fromB64(got[0]!.chain[0]!));
    expect(pre.getExtension(CT_POISON_OID)?.critical).toBe(true);
    expect(fin.serialNumber, "pin dropped: final serial differs from the precert's").toBe(pre.serialNumber);
    expect(tbsWithout(fromB64(pemBody(r.tier)), CT_SCT_LIST_OID)).toEqual(
      tbsWithout(fromB64(got[0]!.chain[0]!), CT_POISON_OID),
    );

    const logKey = await stubPin(stubKey);
    const scts = embeddedScts(r.tier);
    expect(scts).toHaveLength(1);
    expect(await sctVerifies(scts[0]!, r.tier, r.ca, logKey), "tier SCT vs tier bytes").toBe(true);
    expect(r.backlog).toEqual([]);
    await expectTierIssues(r);
  });

  for (const mode of ["500", "hang"] as const) {
    it(`${mode}: the tier is minted without an SCT and ONE final chain is backlogged`, async () => {
      await setMode(mode);
      const r = await mintTier();
      const c = new X509Certificate(r.tier);
      expect(c.getExtension(CT_SCT_LIST_OID)).toBeFalsy();
      expect(c.getExtension(CT_POISON_OID)).toBeFalsy();
      expect(r.backlog).toHaveLength(1);
      expect(JSON.parse(r.backlog[0]!.chain_json)).toEqual([pemBody(r.tier), pemBody(r.ca)]);
      expect(r.backlog[0]!.attempts).toBe(0);
      expect(r.backlog[0]!.logged_at).toBeNull();
      if (mode === "hang") {
        expect(r.elapsed).toBeGreaterThanOrEqual(CT_TIMEOUT_MS - 100);
        expect(r.elapsed).toBeLessThan(CT_TIMEOUT_MS + 1500);
      }
      await expectTierIssues(r);
    });
  }
});

// ── Collect and renew, end to end through the routes ───────────────────────

describe("ct.mint — tiers via collect and renew", () => {
  it("both the collected tier and the renewed tier are logged, each verifying against its own bytes", async () => {
    const { default: worker } = await import("../worker");
    const { createSessionCookie } = await import("./auth/session");
    const { tierEnrolmentBinding, deviceCodeHash, tierRenewalBindingV2 } = await import(
      "./auth/tier-enrolment-binding"
    );
    const { ED25519 } = await import("./platform");
    const ORIGIN = "http://localhost:8788";
    const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
      (worker.fetch as (r: Request, e: unknown) => Promise<Response>)(
        new Request(`${ORIGIN}${path}`, {
          method: "POST",
          headers: { "content-type": "application/json", ...headers },
          body: JSON.stringify(body),
        }),
        { ...env, SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN },
      );
    const b64u = (b: Uint8Array) =>
      btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const authority = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));

    const stubKey = await control("ok");
    const logKey = await stubPin(stubKey);
    const kp = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
    const spki = new Uint8Array((await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer);
    const pem = await spkiPem(kp.publicKey);

    const pid = `ct-renew-${crypto.randomUUID()}`;
    const scopes = ["bridgeCert", "certMint"];
    await (authority as unknown as { createPrincipalWithCapabilities(p: string, s: string[]): Promise<void> })
      .createPrincipalWithCapabilities(pid, scopes);
    const cookie = await createSessionCookie(
      { principalId: pid, scopes, authMethod: "passkey" },
      await (authority as unknown as { getSessionSecret(): Promise<string> }).getSessionSecret(),
    );

    const start = (await (await post("/cert/issuing-ca/device", { public_key: pem })).json()) as {
      device_code: string;
      user_code: string;
    };
    const ap = await post("/cert/issuing-ca/device/approve", { user_code: start.user_code }, { cookie });
    expect(ap.status, await ap.clone().text()).toBe(200);
    const proof = b64u(new Uint8Array(await crypto.subtle.sign(
      ED25519, kp.privateKey, tierEnrolmentBinding(spki, await deviceCodeHash(start.device_code)),
    )));
    const tok = await post("/cert/issuing-ca/device/token", { device_code: start.device_code, proof });
    expect(tok.status, await tok.clone().text()).toBe(200);
    const collected = (await tok.json()) as { certificate: string; generation: number };

    const iat = Math.floor(Date.now() / 1000);
    const rproof = b64u(new Uint8Array(await crypto.subtle.sign(
      ED25519, kp.privateKey, tierRenewalBindingV2(spki, iat, collected.generation),
    )));
    const rn = await post("/cert/issuing-ca/renew", {
      public_key: pem, iat, generation: collected.generation, proof: rproof,
    });
    expect(rn.status, await rn.clone().text()).toBe(200);
    const renewed = (await rn.json()) as { certificate: string };

    const root = await (authority as unknown as { getCACertificatePem(): Promise<string> }).getCACertificatePem();
    for (const [label, tier] of [["collected", collected.certificate], ["renewed", renewed.certificate]] as const) {
      const c = new X509Certificate(tier);
      expect(c.getExtension(CT_SCT_LIST_OID), `${label} tier not logged`).toBeTruthy();
      expect(c.getExtension(CT_POISON_OID)).toBeFalsy();
      const scts = embeddedScts(tier);
      expect(await sctVerifies(scts[0]!, tier, root, logKey), `${label} SCT vs own bytes`).toBe(true);
    }
    expect(collected.certificate).not.toBe(renewed.certificate);
  });
});

// ── Task 4: drain the backlog from the refresh alarm; report CT health ──────

type DrainAuth = {
  env: Record<string, unknown>;
  alarm(): Promise<void>;
  getCACertificatePem(): Promise<string>;
  getAlarmHealth(): Promise<{
    failureCount: number;
    totalFires: number;
    ct: CtHealthView;
  }>;
  mintBridgeCertPair(p: {
    subject: string;
    identity: string;
    mtlsPublicKeyPem: string;
    signingPublicKeyPem: string;
    scopes: string[];
    authMethod: string;
  }): Promise<unknown>;
  ctx: { storage: { sql: { exec(q: string, ...b: unknown[]): { toArray(): unknown[] } } } };
};

/**
 * A fresh authority holding `n` backlog rows whose chains are REAL (the stub
 * signs real SCTs and parses the leaf, so placeholder bytes would not do).
 * They come from a genuine mint against a 500-ing log, then are cloned.
 */
async function withBacklog<T>(
  n: number,
  body: (a: DrainAuth) => Promise<T>,
  opts: { unbind?: boolean; envPatch?: Record<string, string | undefined> } = {},
): Promise<T> {
  const name = `ct-drain-${++seq}-${crypto.randomUUID()}`;
  const stub = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(name));
  const mtls = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
  )) as CryptoKeyPair;
  const sign = (await crypto.subtle.generateKey(
    { name: "Ed25519" }, true, ["sign", "verify"],
  )) as CryptoKeyPair;
  await setMode("500");
  return runInDurableObject(stub, async (auth) => {
    const a = auth as unknown as DrainAuth;
    await a.mintBridgeCertPair({
      subject: SUBJECT,
      identity: `wimse://notme.bot/principal/${name}`,
      mtlsPublicKeyPem: await spkiPem(mtls.publicKey),
      signingPublicKeyPem: await spkiPem(sign.publicKey),
      scopes: ["bridgeCert"],
      authMethod: "gha-oidc",
    });
    const sql = a.ctx.storage.sql;
    const seed = sql.exec("SELECT chain_json FROM ct_backlog ORDER BY id").toArray() as Array<{
      chain_json: string;
    }>;
    expect(seed.length).toBe(2); // the failed mint backlogged both certs
    sql.exec("DELETE FROM ct_backlog");
    const base = Math.floor(Date.now() / 1000) - 1000;
    for (let i = 0; i < n; i++) {
      // created_at ascends with i, so row i is the i-th oldest.
      sql.exec(
        "INSERT INTO ct_backlog (chain_json, created_at) VALUES (?, ?)",
        seed[i % 2]!.chain_json,
        base + i,
      );
    }
    await setMode("ok");
    if (opts.unbind) {
      const e = { ...a.env };
      delete e.CT_LOG;
      a.env = e;
    }
    if (opts.envPatch) {
      const e = { ...a.env };
      for (const [k, v] of Object.entries(opts.envPatch)) {
        if (v === undefined) delete e[k];
        else e[k] = v;
      }
      a.env = e;
    }
    return body(a);
  });
}

const rowsOf = (a: DrainAuth) =>
  a.ctx.storage.sql
    .exec("SELECT id, attempts, logged_at FROM ct_backlog ORDER BY created_at, id")
    .toArray() as Array<{ id: number; attempts: number; logged_at: number | null }>;

describe("ct.drain — the refresh alarm empties the backlog", () => {
  it("25 rows, log ok: one fire logs 20 (the OLDEST 20), the next logs the last 5", async () => {
    await withBacklog(25, async (a) => {
      await a.alarm();
      let rows = rowsOf(a);
      expect(rows.filter((r) => r.logged_at !== null).length).toBe(20);
      expect(rows.slice(0, 20).every((r) => r.logged_at !== null)).toBe(true);
      expect(rows.slice(20).every((r) => r.logged_at === null && r.attempts === 0)).toBe(true);
      expect((await a.getAlarmHealth()).ct.backlog).toBe(5);

      await a.alarm();
      rows = rowsOf(a);
      expect(rows.every((r) => r.logged_at !== null)).toBe(true);
      const h = await a.getAlarmHealth();
      expect(h.ct.backlog).toBe(0);
      expect(h.ct.oldestUnloggedAgeS).toBeNull();
      expect(h.failureCount).toBe(0);
    });
    // 25 rows, 2 fires: exactly 25 add-chain submissions reached the log.
    const adds = (await received()).filter((r) => r.path.endsWith("/add-chain"));
    expect(adds.length).toBe(25);
  });

  it("log 500: attempts increment, rows at 24 are skipped and counted in gaveUp, lastError is set", async () => {
    await withBacklog(3, async (a) => {
      const sql = a.ctx.storage.sql;
      // Row 3 (newest) is already at the cap and was tried a minute ago; it
      // must not be submitted again (its slow retry is 24 h out).
      sql.exec(
        "UPDATE ct_backlog SET attempts = 24, last_attempt_at = ? WHERE id = (SELECT MAX(id) FROM ct_backlog)",
        Math.floor(Date.now() / 1000) - 60,
      );
      await setMode("500");
      await a.alarm();
      const rows = rowsOf(a);
      expect(rows.map((r) => r.attempts)).toEqual([1, 1, 24]);
      expect(rows.every((r) => r.logged_at === null)).toBe(true);
      const h = await a.getAlarmHealth();
      expect(h.ct.backlog).toBe(2);
      expect(h.ct.gaveUp).toBe(1);
      expect(h.ct.lastError).toMatch(/add-chain failed for backlog row \d+: HTTP 500/);
      expect(h.ct.lastErrorAt).toBeGreaterThan(0);
      expect(typeof h.ct.oldestUnloggedAgeS).toBe("number");
      expect(h.ct.oldestUnloggedAgeS!).toBeGreaterThanOrEqual(900);
      expect(h.failureCount).toBe(0); // a log outage is not an alarm failure
      // 2 rows submitted, the capped one was not.
      const adds = (await received()).filter((r) => r.path.endsWith("/add-chain"));
      expect(adds.length).toBe(2);

      // Climb to the cap: a row at 23 gets one last try and then gives up.
      sql.exec("UPDATE ct_backlog SET attempts = 23 WHERE attempts = 1");
      await a.alarm();
      const h2 = await a.getAlarmHealth();
      expect(h2.ct.backlog).toBe(0);
      expect(h2.ct.gaveUp).toBe(3);
    });
  });

  it("a corrupt row is a failed attempt; the other rows still drain and the alarm is unharmed", async () => {
    await withBacklog(3, async (a) => {
      a.ctx.storage.sql.exec(
        "INSERT INTO ct_backlog (chain_json, created_at) VALUES ('{not json', 1)",
      );
      await a.alarm();
      const rows = rowsOf(a);
      expect(rows[0]!.attempts).toBe(1); // oldest: the corrupt one
      expect(rows[0]!.logged_at).toBeNull();
      expect(rows.slice(1).every((r) => r.logged_at !== null)).toBe(true);
      const h = await a.getAlarmHealth();
      expect(h.failureCount).toBe(0);
      expect(h.ct.lastError).toMatch(/backlog row/);
    });
  });

  it("a drain that throws outright (backlog table gone) is not an alarm failure and does not throw", async () => {
    await withBacklog(2, async (a) => {
      a.ctx.storage.sql.exec("DROP TABLE ct_backlog");
      await expect(a.alarm()).resolves.toBeUndefined();
      a.ctx.storage.sql.exec(
        "CREATE TABLE ct_backlog (id INTEGER PRIMARY KEY, chain_json TEXT NOT NULL, created_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, logged_at INTEGER)",
      );
      const h = await a.getAlarmHealth();
      expect(h.failureCount).toBe(0);
      expect(h.totalFires).toBeGreaterThanOrEqual(1);
      expect(h.ct.lastError).toMatch(/^drain:/);
    });
  });

  for (const [mode, why] of [["wrong-id", "wrong log"], ["bad-sig", "bad signature"]] as const) {
    it(`I1 ${mode}: an add-chain answer the pin refuses does not mark the row logged`, async () => {
      await withBacklog(2, async (a) => {
        await setMode(mode);
        await a.alarm();
        const rows = rowsOf(a);
        expect(rows.every((r) => r.logged_at === null && r.attempts === 1)).toBe(true);
        const h = await a.getAlarmHealth();
        expect(h.ct.backlog).toBe(2);
        expect(h.ct.lastError).toMatch(new RegExp(`add-chain failed for backlog row \\d+: ${why}`));
      });
      expect((await received()).filter((r) => r.path.endsWith("/add-chain")).length).toBe(2);
    });
  }

  it("I1: the drain submits nothing while CT_LOG_KEY is missing; rows untouched, reason recorded", async () => {
    await withBacklog(2, async (a) => {
      await a.alarm();
      expect(rowsOf(a).every((r) => r.attempts === 0 && r.logged_at === null)).toBe(true);
      const h = await a.getAlarmHealth();
      expect(h.ct.lastError).toMatch(/drain skipped: config: CT_LOG_KEY missing/);
      expect(h.ct.configError).toBe("CT_LOG_KEY missing");
      expect(h.failureCount).toBe(0);
    }, { envPatch: { CT_LOG_KEY: undefined } });
    expect((await received()).filter((r) => r.path.endsWith("/add-chain")).length).toBe(0);
  });

  it("absent binding: the drain does nothing — no log call, rows untouched", async () => {
    await withBacklog(3, async (a) => {
      await a.alarm();
      expect(rowsOf(a).every((r) => r.attempts === 0 && r.logged_at === null)).toBe(true);
    }, { unbind: true });
    expect((await received()).filter((r) => r.path.endsWith("/add-chain")).length).toBe(0);
  });
});

// ── Final review I2: gaveUp rows are retried slowly, not abandoned ─────────

const DAY_S = 24 * 60 * 60;
const nowS = () => Math.floor(Date.now() / 1000);

describe("ct.drain — rows past the attempt cap are retried once per 24 h", () => {
  it("a gaveUp row last tried over 24 h ago is retried and logged; health counts it until then", async () => {
    await withBacklog(1, async (a) => {
      a.ctx.storage.sql.exec(
        "UPDATE ct_backlog SET attempts = 24, last_attempt_at = ?",
        nowS() - DAY_S - 60,
      );
      const before = await a.getAlarmHealth();
      expect(before.ct.gaveUp).toBe(1);
      expect(before.ct.backlog).toBe(0);
      await a.alarm();
      const [row] = rowsOf(a);
      expect(row!.logged_at).not.toBeNull();
      const after = await a.getAlarmHealth();
      expect(after.ct.gaveUp).toBe(0);
    });
    expect((await received()).filter((r) => r.path.endsWith("/add-chain")).length).toBe(1);
  });

  it("a gaveUp row tried within 24 h is not retried; a failed slow retry waits another 24 h", async () => {
    await withBacklog(2, async (a) => {
      const sql = a.ctx.storage.sql;
      const [r1, r2] = rowsOf(a);
      sql.exec("UPDATE ct_backlog SET attempts = 30, last_attempt_at = ? WHERE id = ?", nowS() - DAY_S + 3600, r1!.id);
      sql.exec("UPDATE ct_backlog SET attempts = 30, last_attempt_at = ? WHERE id = ?", nowS() - DAY_S - 60, r2!.id);
      await setMode("500");
      await a.alarm();
      // Only the eligible row was submitted; it failed and is stamped now.
      expect((await received()).filter((r) => r.path.endsWith("/add-chain")).length).toBe(1);
      let rows = rowsOf(a);
      expect(rows.map((r) => r.attempts)).toEqual([30, 31]);
      expect(rows.every((r) => r.logged_at === null)).toBe(true);
      expect((await a.getAlarmHealth()).ct.gaveUp).toBe(2);
      // Next fire: neither is due.
      await setMode("ok");
      await a.alarm();
      expect((await received()).filter((r) => r.path.endsWith("/add-chain")).length).toBe(0);
      rows = rowsOf(a);
      expect(rows.every((r) => r.logged_at === null)).toBe(true);
    });
  });

  it("normal rows come first: 20 normal rows fill a fire ahead of an OLDER due gaveUp row", async () => {
    await withBacklog(21, async (a) => {
      const oldest = rowsOf(a)[0]!;
      a.ctx.storage.sql.exec(
        "UPDATE ct_backlog SET attempts = 24, last_attempt_at = ? WHERE id = ?",
        nowS() - DAY_S - 60,
        oldest.id,
      );
      await a.alarm();
      let rows = rowsOf(a);
      expect(rows[0]!.logged_at, "the gaveUp row waited for the normal rows").toBeNull();
      expect(rows.slice(1).every((r) => r.logged_at !== null)).toBe(true);
      await a.alarm();
      rows = rowsOf(a);
      expect(rows[0]!.logged_at, "and was logged on the next fire").not.toBeNull();
    });
  });

  it("an old ct_backlog (no last_attempt_at) is migrated in place, and the drain's index is created", async () => {
    const stub = env.SIGNING_AUTHORITY.get(
      env.SIGNING_AUTHORITY.idFromName(`ct-migrate-${crypto.randomUUID()}`),
    );
    await runInDurableObject(stub, async (auth) => {
      const a = auth as unknown as DrainAuth;
      const sql = a.ctx.storage.sql;
      // The pre-I2 shape, with a row in it, before the authority initialises.
      sql.exec(
        "CREATE TABLE ct_backlog (id INTEGER PRIMARY KEY, chain_json TEXT NOT NULL, created_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, logged_at INTEGER)",
      );
      sql.exec("INSERT INTO ct_backlog (chain_json, created_at, attempts) VALUES ('[]', 1, 24)");
      const h = await a.getAlarmHealth();
      expect(h.ct.gaveUp).toBe(1);
      const cols = (sql.exec("PRAGMA table_info(ct_backlog)").toArray() as Array<{ name: string }>).map(
        (c) => c.name,
      );
      expect(cols).toContain("last_attempt_at");
      expect(sql.exec("SELECT last_attempt_at FROM ct_backlog").toArray()).toEqual([{ last_attempt_at: null }]);
      const idx = sql
        .exec("SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'ct_backlog_drain'")
        .toArray() as Array<{ sql: string }>;
      expect(idx).toHaveLength(1);
      expect(idx[0]!.sql).toMatch(/\(logged_at, attempts, created_at\)/);
    });
  });
});

describe("ct.health — what the operator sees", () => {
  it("unloggable counts a mint whose root could not be read, and the mint is unchanged", async () => {
    const name = `ct-unloggable-${++seq}-${crypto.randomUUID()}`;
    const stub = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(name));
    const mtls = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    )) as CryptoKeyPair;
    const sign = (await crypto.subtle.generateKey(
      { name: "Ed25519" }, true, ["sign", "verify"],
    )) as CryptoKeyPair;
    await setMode("ok");
    await runInDurableObject(stub, async (auth) => {
      const a = auth as unknown as DrainAuth;
      const before = await a.getAlarmHealth();
      expect(before.ct.unloggable).toEqual({ count: 0, lastAt: 0, reason: "" });
      a.getCACertificatePem = async () => {
        throw new Error("root unreadable (forced)");
      };
      const pair = (await a.mintBridgeCertPair({
        subject: SUBJECT,
        identity: `wimse://notme.bot/principal/${name}`,
        mtlsPublicKeyPem: await spkiPem(mtls.publicKey),
        signingPublicKeyPem: await spkiPem(sign.publicKey),
        scopes: ["bridgeCert"],
        authMethod: "gha-oidc",
      })) as { certificates: { mtls: string; signing: string } };
      expect(pair.certificates.mtls).toContain("BEGIN CERTIFICATE");
      const h = await a.getAlarmHealth();
      expect(h.ct.unloggable.count).toBe(1);
      expect(h.ct.unloggable.lastAt).toBeGreaterThan(0);
      expect(h.ct.lastError).toMatch(/root unreadable/);
      expect(h.ct.backlog).toBe(0); // no row: nothing to record
    });
  });

  it("a healthy, empty authority reports zeros", async () => {
    await withBacklog(0, async (a) => {
      const h = await a.getAlarmHealth();
      expect(h.ct.backlog).toBe(0);
      expect(h.ct.gaveUp).toBe(0);
      expect(h.ct.oldestUnloggedAgeS).toBeNull();
      expect(h.ct.unloggable.count).toBe(0);
    });
  });
});
