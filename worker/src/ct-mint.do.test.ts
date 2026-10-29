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
import { CT_POISON_OID, CT_SCT_LIST_OID } from "./ct/sct";

const SUBJECT = "repo:agentic-research/notme:ref:refs/heads/main";
const CT_TIMEOUT_MS = 2000;

type Mode = "ok" | "500" | "hang" | "ok-then-fail" | "fail-second" | "fail-signing";
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
  ctx: { storage: { sql: { exec(q: string): { toArray(): unknown[] } } } };
};

const ctLog = (): Fetcher => {
  const f = (env as unknown as { CT_LOG?: Fetcher }).CT_LOG;
  if (!f) throw new Error("CT_LOG is not bound — run under vitest.workers.ct.config.mts");
  return f;
};

async function setMode(mode: Mode): Promise<string> {
  const r = await ctLog().fetch("https://ct-log/__control", {
    method: "POST",
    body: JSON.stringify({ mode }),
  });
  return ((await r.json()) as { id: string }).id;
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
 */
async function mint(opts: { unbind?: boolean } = {}) {
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

    return {
      ca,
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

// ── Minimal DER, enough to perform the RFC 6962 §3.2 reconstruction ────────

interface Tlv {
  tag: number;
  start: number; // first byte of the TLV
  body: number; // first byte of the content
  end: number; // one past the last content byte
}
function tlv(d: Uint8Array, at: number): Tlv {
  const tag = d[at]!;
  let len = d[at + 1]!;
  let body = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + d[at + 2 + i]!;
    body = at + 2 + n;
  }
  return { tag, start: at, body, end: body + len };
}
function children(d: Uint8Array, t: Tlv): Tlv[] {
  const out: Tlv[] = [];
  for (let at = t.body; at < t.end; ) {
    const c = tlv(d, at);
    out.push(c);
    at = c.end;
  }
  return out;
}
function encode(tag: number, content: Uint8Array): Uint8Array {
  const n = content.length;
  const len =
    n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : n < 0x10000 ? [0x82, n >> 8, n & 0xff] : null;
  if (!len) throw new Error("test DER encoder: content too long");
  const out = new Uint8Array(1 + len.length + n);
  out[0] = tag;
  out.set(len, 1);
  out.set(content, 1 + len.length);
  return out;
}
function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}
function oidString(content: Uint8Array): string {
  const arcs = [Math.floor(content[0]! / 40), content[0]! % 40];
  let v = 0;
  for (const b of content.subarray(1)) {
    v = v * 128 + (b & 0x7f);
    if (!(b & 0x80)) {
      arcs.push(v);
      v = 0;
    }
  }
  return arcs.join(".");
}

/** The TBSCertificate of `certDer` with the extension `drop` removed. */
function tbsWithout(certDer: Uint8Array, drop: string): Uint8Array {
  const cert = tlv(certDer, 0);
  const tbs = children(certDer, cert)[0]!;
  const fields = children(certDer, tbs);
  const extsField = fields.find((f) => f.tag === 0xa3);
  if (!extsField) throw new Error("certificate has no extensions");
  const seq = children(certDer, extsField)[0]!;
  const exts = children(certDer, seq);
  const kept = exts.filter((e) => {
    const oid = children(certDer, e)[0]!;
    return oidString(certDer.subarray(oid.body, oid.end)) !== drop;
  });
  if (kept.length !== exts.length - 1) {
    throw new Error(`expected exactly one ${drop} extension`);
  }
  const newExts = encode(
    0xa3,
    encode(0x30, concat(kept.map((e) => certDer.subarray(e.start, e.end)))),
  );
  return encode(
    0x30,
    concat([
      ...fields.filter((f) => f.tag !== 0xa3).map((f) => certDer.subarray(f.start, f.end)),
      newExts,
    ]),
  );
}

/** The TLS-encoded SCTs inside an embedded SCT list extension. */
function embeddedScts(pem: string): Uint8Array[] {
  const ext = new X509Certificate(pem).getExtension(CT_SCT_LIST_OID)!;
  const v = new Uint8Array(ext.value);
  const inner = tlv(v, 0); // OCTET STRING wrapping the TLS list
  expect(inner.tag).toBe(0x04);
  const list = v.subarray(inner.body, inner.end);
  expect((list[0]! << 8) | list[1]!).toBe(list.length - 2);
  const out: Uint8Array[] = [];
  for (let at = 2; at < list.length; ) {
    const n = (list[at]! << 8) | list[at + 1]!;
    out.push(list.subarray(at + 2, at + 2 + n));
    at += 2 + n;
  }
  return out;
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

  it("RF2: each SCT signs the final cert's own bytes — §3.2 reconstruction equals the precert the log saw", async () => {
    await setMode("ok");
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
  });

  for (const mode of ["fail-signing", "ok-then-fail", "fail-second", "500"] as const) {
    it(`RF1 (${mode}): a half-logged pair is not minted — neither SCT, both backlogged, still a working pair`, async () => {
      await setMode(mode);
      const r = await mint();
      // Both halves were attempted, concurrently, before either failure mattered.
      expect(await received()).toHaveLength(2);
      expectBacklogged(r);
      await expectWorkingPair(r);
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
  });
});
