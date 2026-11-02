import { describe, expect, it } from "vitest";
import * as x509 from "@peculiar/x509";
import { OID_CRITERIA, OID_SCOPES, derTlv, derUtf8String } from "../cert-authority";
import { CERT_ELIGIBLE_SCOPES } from "../auth/passkey-cert-scopes";
import {
  CRITERIA,
  checkCriteria,
  criteriaId,
  encodeCriteria,
  parseCriteriaId,
  readCriteria,
} from "../criteria";

const OID_CONFINEMENT = "1.3.6.1.4.1.99999.1.7";
const T0 = new Date("2026-11-02T12:00:00Z");

const keys = (await crypto.subtle.generateKey({ name: "Ed25519" } as any, true, ["sign", "verify"])) as CryptoKeyPair;

const scopesDer = (scopes: string[]) => derTlv(0x30, new Uint8Array(scopes.flatMap((s) => [...derUtf8String(s)])));
const elem = (name: string, version: number[]) =>
  derTlv(0x30, new Uint8Array([...derUtf8String(name), ...derTlv(0x02, new Uint8Array(version))]));
const seq = (...parts: Uint8Array[]) => derTlv(0x30, new Uint8Array(parts.flatMap((p) => [...p])));

interface Spec {
  spanS?: number;
  criteria?: Uint8Array | { name: string; version: number }[];
  scopes?: string[];
  confinement?: boolean;
}

async function mk(spec: Spec = {}) {
  const exts: x509.Extension[] = [];
  if (spec.criteria) {
    const der = spec.criteria instanceof Uint8Array ? spec.criteria : encodeCriteria(spec.criteria);
    exts.push(new x509.Extension(OID_CRITERIA, false, der));
  }
  if (spec.scopes) exts.push(new x509.Extension(OID_SCOPES, false, scopesDer(spec.scopes)));
  if (spec.confinement) exts.push(new x509.Extension(OID_CONFINEMENT, false, new Uint8Array([0x04, 0x01, 0x00])));
  return x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: "CN=test",
    notBefore: T0,
    notAfter: new Date(T0.getTime() + (spec.spanS ?? 300) * 1000),
    signingAlgorithm: { name: "Ed25519" } as any,
    keys: keys as any,
    extensions: exts,
  });
}

const AS = { name: "agent-session", version: 1 };
const LLO = { name: "llo-run", version: 1 };
const DEP = { name: "deploy", version: 1 };

describe("encode / read", () => {
  it("round-trips one element with the expected DER shape", async () => {
    const der = encodeCriteria([AS]);
    expect(der[0]).toBe(0x30);
    expect(der[2]).toBe(0x30);
    expect(der[4]).toBe(0x0c);
    expect(der[3]).toBe(2 + "agent-session".length + 3);
    const r = readCriteria(await mk({ criteria: [AS] }));
    expect(r).toEqual({ present: true, ok: true, list: [AS] });
  });

  it("round-trips three elements", async () => {
    const list = [AS, LLO, DEP];
    expect(readCriteria(await mk({ criteria: list }))).toEqual({ present: true, ok: true, list });
  });

  it("reports absence", async () => {
    expect(readCriteria(await mk())).toEqual({ present: false });
  });

  it("refuses to encode empty or duplicate lists", () => {
    expect(() => encodeCriteria([])).toThrow();
    expect(() => encodeCriteria([AS, AS])).toThrow();
  });

  it("accepts long-form lengths", async () => {
    const e = elem("agent-session", [1]);
    // Re-encode the outer SEQUENCE and inner element with long-form (0x81) lengths.
    const inner = new Uint8Array([0x30, 0x81, e.length - 2, ...e.subarray(2)]);
    const outer = new Uint8Array([0x30, 0x81, inner.length, ...inner]);
    expect(readCriteria(await mk({ criteria: outer }))).toEqual({ present: true, ok: true, list: [AS] });
  });

  it("parses and formats ids", () => {
    expect(criteriaId(AS)).toBe("agent-session/1");
    expect(parseCriteriaId("agent-session/1")).toEqual(AS);
    for (const bad of ["", "agent-session", "/1", "a/", "a/0", "a/-1", "a/1/2", "a/x", "a/01", "a/99999999999"]) {
      expect(parseCriteriaId(bad)).toBeNull();
    }
  });
});

describe("malformed .1.10 never throws and never passes", () => {
  const good = elem("agent-session", [1]);
  const cases: Record<string, Uint8Array> = {
    "zero elements": seq(),
    "wrong outer tag": derTlv(0x31, good),
    "wrong element tag": seq(derTlv(0x31, good.subarray(2))),
    "name not utf8": seq(derTlv(0x30, new Uint8Array([...derTlv(0x04, new Uint8Array([97])), ...derTlv(0x02, new Uint8Array([1]))]))),
    "version not integer": seq(derTlv(0x30, new Uint8Array([...derUtf8String("agent-session"), ...derTlv(0x04, new Uint8Array([1]))]))),
    "trailing bytes in element": seq(derTlv(0x30, new Uint8Array([...derUtf8String("agent-session"), ...derTlv(0x02, new Uint8Array([1])), 0x00]))),
    "trailing bytes after outer": new Uint8Array([...seq(good), 0x00]),
    "negative integer": seq(elem("agent-session", [0xff])),
    "zero integer": seq(elem("agent-session", [0])),
    "oversize integer": seq(elem("agent-session", [1, 0, 0, 0, 0])),
    "empty integer": seq(elem("agent-session", [])),
    "truncated": seq(good).subarray(0, 8),
    "length overruns": new Uint8Array([0x30, 0x20, 0x30, 0x03]),
    "empty value": new Uint8Array([]),
    "indefinite length": new Uint8Array([0x30, 0x80, 0x00, 0x00]),
    "empty name": seq(elem("", [1])),
  };
  for (const [label, der] of Object.entries(cases)) {
    it(label, async () => {
      const leaf = await mk({ criteria: der });
      const r = readCriteria(leaf);
      expect(r.present && !r.ok).toBe(true);
      expect(checkCriteria(null, leaf, { at: T0 })).toEqual({ ok: false, reason: "malformed criteria on leaf" });
    });
  }

  it("malformed on the tier is named as the tier (checked before the leaf)", async () => {
    const tier = await mk({ criteria: seq() });
    const leaf = await mk({ criteria: seq() });
    expect(checkCriteria(tier, leaf, { at: T0 })).toEqual({ ok: false, reason: "malformed criteria on tier" });
  });

  it("two elements on a task", async () => {
    const leaf = await mk({ criteria: [AS, LLO] });
    expect(checkCriteria(await mk({ criteria: [AS, LLO] }), leaf)).toEqual({
      ok: false,
      reason: "a task carries exactly one criteria",
    });
  });

  it("unknown name and version 2 of a known name are refused as unknown", async () => {
    const tier = await mk({ criteria: [{ name: "nope", version: 1 }, { name: "agent-session", version: 2 }] });
    for (const c of [{ name: "nope", version: 1 }, { name: "agent-session", version: 2 }]) {
      const leaf = await mk({ criteria: [c] });
      expect(checkCriteria(tier, leaf)).toEqual({ ok: false, reason: `unknown criteria ${criteriaId(c)}` });
    }
  });
});

describe("checkCriteria rules", () => {
  it("rule 4: legacy, no cutoff", async () => {
    expect(checkCriteria(await mk(), await mk(), { at: T0 })).toEqual({ ok: true, criteria: null, legacy: true });
  });

  it("rule 4: legacy cutoff", async () => {
    const at = new Date("2027-01-01T00:00:00Z");
    expect(checkCriteria(await mk(), await mk(), { at, legacyCutoff: new Date("2026-12-31T00:00:00Z") })).toEqual({
      ok: false,
      reason: "legacy certificate past the operator's cutoff",
    });
    expect(checkCriteria(await mk(), await mk(), { at, legacyCutoff: new Date("2027-06-01T00:00:00Z") })).toEqual({
      ok: true,
      criteria: null,
      legacy: true,
    });
  });

  it("rule 5: task claims criteria its tier does not carry", async () => {
    expect(checkCriteria(await mk(), await mk({ criteria: [AS] }))).toEqual({
      ok: false,
      reason: "task claims criteria its tier does not carry",
    });
  });

  it("rule 6: tier carries criteria, task names none", async () => {
    expect(checkCriteria(await mk({ criteria: [AS] }), await mk())).toEqual({
      ok: false,
      reason: "tier carries criteria; the task names none",
    });
  });

  it("rule 7: unknown criteria", async () => {
    const c = { name: "mystery", version: 3 };
    expect(checkCriteria(await mk({ criteria: [c] }), await mk({ criteria: [c] }))).toEqual({
      ok: false,
      reason: "unknown criteria mystery/3",
    });
  });

  it("rule 8: tier-minted criteria with no tier; authority-minted under a tier", async () => {
    expect(checkCriteria(null, await mk({ criteria: [AS] }))).toEqual({
      ok: false,
      reason: "agent-session/1 is minted by the tier only",
    });
    expect(checkCriteria(await mk({ criteria: [DEP] }), await mk({ criteria: [DEP] }))).toEqual({
      ok: false,
      reason: "deploy/1 is minted by the authority only",
    });
  });

  it("rule 9: not granted by its tier", async () => {
    expect(checkCriteria(await mk({ criteria: [LLO] }), await mk({ criteria: [AS] }))).toEqual({
      ok: false,
      reason: "task criteria agent-session/1 is not granted by its tier",
    });
  });

  it("rule 10: lifetime boundary", async () => {
    const tier = await mk({ criteria: [AS] });
    expect(checkCriteria(tier, await mk({ criteria: [AS], spanS: 300 }))).toEqual({
      ok: true,
      criteria: AS,
      legacy: false,
    });
    expect(checkCriteria(tier, await mk({ criteria: [AS], spanS: 301 }))).toEqual({
      ok: false,
      reason: "agent-session/1 allows at most 300s, this certificate spans 301s",
    });
  });

  it("rule 10: a three-hour deploy certificate is refused", async () => {
    expect(checkCriteria(null, await mk({ criteria: [DEP], spanS: 3 * 3600 }))).toEqual({
      ok: false,
      reason: "deploy/1 allows at most 900s, this certificate spans 10800s",
    });
    expect(checkCriteria(null, await mk({ criteria: [DEP], spanS: 900 }))).toEqual({
      ok: true,
      criteria: DEP,
      legacy: false,
    });
  });

  it("rule 10 ignores the wall clock", async () => {
    const tier = await mk({ criteria: [AS] });
    const r = checkCriteria(tier, await mk({ criteria: [AS] }), { at: new Date("2099-01-01T00:00:00Z") });
    expect(r.ok).toBe(true);
  });

  it("rule 11: scope outside the ceiling", async () => {
    const tier = await mk({ criteria: [AS] });
    expect(checkCriteria(tier, await mk({ criteria: [AS], scopes: ["bridgeCert", "certMint"] }))).toEqual({
      ok: false,
      reason: "agent-session/1 does not allow scope certMint",
    });
    expect(checkCriteria(tier, await mk({ criteria: [AS], scopes: ["bridgeCert", "sign:git"] })).ok).toBe(true);
    expect(checkCriteria(null, await mk({ criteria: [DEP], scopes: ["sign:git"] }))).toEqual({
      ok: false,
      reason: "deploy/1 does not allow scope sign:git",
    });
  });

  it("rule 12: llo-run requires .1.7", async () => {
    const tier = await mk({ criteria: [LLO] });
    expect(checkCriteria(tier, await mk({ criteria: [LLO] }))).toEqual({
      ok: false,
      reason: "llo-run/1 requires the run's confinementDigest (.1.7)",
    });
    expect(checkCriteria(tier, await mk({ criteria: [LLO], confinement: true }))).toEqual({
      ok: true,
      criteria: LLO,
      legacy: false,
    });
  });

  it("a tier may carry several; the task picks one", async () => {
    const tier = await mk({ criteria: [AS, LLO] });
    expect(checkCriteria(tier, await mk({ criteria: [AS] }))).toEqual({ ok: true, criteria: AS, legacy: false });
  });
});

describe("registry", () => {
  it("has exactly the three definitions", () => {
    expect([...CRITERIA.keys()].sort()).toEqual(["agent-session/1", "deploy/1", "llo-run/1"]);
    const as = CRITERIA.get("agent-session/1")!;
    expect(as).toMatchObject({ id: "agent-session/1", mintedBy: "tier", maxLifetimeS: 300, requiresConfinementDigest: false });
    expect(as.scopeCeiling).toBe(CERT_ELIGIBLE_SCOPES);
    const llo = CRITERIA.get("llo-run/1")!;
    expect(llo).toMatchObject({ mintedBy: "tier", maxLifetimeS: 300, requiresConfinementDigest: true });
    expect([...llo.scopeCeiling]).toEqual(["bridgeCert"]);
    const dep = CRITERIA.get("deploy/1")!;
    expect(dep).toMatchObject({ mintedBy: "authority", maxLifetimeS: 900, requiresConfinementDigest: false });
    expect([...dep.scopeCeiling]).toEqual(["bridgeCert"]);
  });

  it("only agent-session/1 is grantable", () => {
    expect([...CRITERIA.values()].filter((d) => d.grantable).map((d) => d.id)).toEqual(["agent-session/1"]);
  });
});
