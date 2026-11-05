/**
 * ct-sct.test.ts — RFC 6962 precertificate and embedded-SCT encoding
 * (notme-1b46a8).
 *
 * These are the two byte formats that stand between a minted certificate and
 * a logged one. Both are easy to get subtly wrong in ways that still parse:
 *
 *  - the poison extension must be CRITICAL, or a verifier treats the
 *    precertificate as an ordinary certificate;
 *  - the SCT list extension value is ITSELF an OCTET STRING (RFC 6962 §3.3
 *    "SignedCertificateTimestampList ::= OCTET STRING"), which X.509 then
 *    wraps in extnValue — so the bytes are double-wrapped, and a single wrap
 *    decodes as a truncated list rather than failing outright.
 *
 * The fixture SCT is a real one, returned by a local azul ct_worker for a
 * real notme chain, so the serialiser is checked against something a log
 * actually emitted rather than against my reading of the RFC.
 */
import { describe, expect, it } from "vitest";
import {
  CT_POISON_OID,
  CT_SCT_LIST_OID,
  ctPoisonExtension,
  sctListExtension,
  serialiseSct,
  type SctResponse,
} from "../ct/sct";

/** Verbatim from a local notme-ct add-chain response. */
const FIXTURE: SctResponse = {
  sct_version: 0,
  id: "0CIlpLhhveuR6klLqq0XS5hMRt4wsduIsX13+q6+tXg=",
  timestamp: 1790371772233,
  extensions: "AAAFAAAAAAA=",
  signature:
    "BAMASDBGAiEAifHdCpTSAkyjnPCd8MMiWFBGYg2ehLnIsjQMNGPWczQCIQDJrbsVz7IyB+G+g0k17TNY11uoVNoaIWd/EqxKGtiLyQ==",
};

const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const fromB64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

describe("ct.poison", () => {
  it("is the RFC 6962 OID, critical, carrying ASN.1 NULL", () => {
    const ext = ctPoisonExtension();
    expect(CT_POISON_OID).toBe("1.3.6.1.4.1.11129.2.4.3");
    expect(ext.type).toBe(CT_POISON_OID);
    // Critical is the whole point: a non-critical poison lets a verifier that
    // does not know the OID accept the precertificate as a real certificate.
    expect(ext.critical).toBe(true);
    expect(new Uint8Array(ext.value)).toEqual(new Uint8Array([0x05, 0x00]));
  });
});

describe("ct.sct.serialise", () => {
  it("lays out version || log id || timestamp || extensions || signature", () => {
    const out = serialiseSct(FIXTURE);
    const id = fromB64(FIXTURE.id);
    const ext = fromB64(FIXTURE.extensions);
    const sig = fromB64(FIXTURE.signature);

    expect(out[0]).toBe(0); // v1
    expect(out.subarray(1, 33)).toEqual(id);
    // uint64 big-endian milliseconds.
    const ts = out.subarray(33, 41).reduce((a, b) => a * 256 + b, 0);
    expect(ts).toBe(FIXTURE.timestamp);
    // uint16 extension length, then the bytes.
    expect((out[41]! << 8) | out[42]!).toBe(ext.length);
    expect(out.subarray(43, 43 + ext.length)).toEqual(ext);
    // The `signature` field is ALREADY the digitally-signed struct — hash
    // alg, signature alg, uint16 length, signature — so it is appended whole.
    // Re-wrapping it is the mistake this asserts against.
    expect(out.subarray(43 + ext.length)).toEqual(sig);
    expect(sig[0]).toBe(4); // SHA-256
    expect(sig[1]).toBe(3); // ECDSA
    expect(out.length).toBe(1 + 32 + 8 + 2 + ext.length + sig.length);
  });

  it("refuses an SCT version it does not understand", () => {
    // v2 changes the structure. Silently serialising it as v1 would produce
    // bytes that embed cleanly and verify nowhere.
    expect(() => serialiseSct({ ...FIXTURE, sct_version: 1 })).toThrow(/version/i);
  });

  it("refuses a log id that is not 32 bytes", () => {
    expect(() => serialiseSct({ ...FIXTURE, id: b64(new Uint8Array(31)) })).toThrow(
      /log id/i,
    );
  });
});

describe("ct.sct.list", () => {
  it("double-wraps: OCTET STRING inside the extension value", () => {
    const ext = sctListExtension([serialiseSct(FIXTURE)]);
    expect(CT_SCT_LIST_OID).toBe("1.3.6.1.4.1.11129.2.4.2");
    expect(ext.type).toBe(CT_SCT_LIST_OID);
    expect(ext.critical).toBe(false); // RFC 6962: MUST NOT be critical

    const value = new Uint8Array(ext.value);
    expect(value[0], "extension value must itself be an OCTET STRING").toBe(0x04);

    // Skip the OCTET STRING header to reach the TLS list.
    const lenByte = value[1]!;
    const headerLen = lenByte < 0x80 ? 2 : 2 + (lenByte & 0x7f);
    const list = value.subarray(headerLen);
    const sct = serialiseSct(FIXTURE);
    // uint16 total list length, then uint16 per-SCT length.
    expect((list[0]! << 8) | list[1]!).toBe(list.length - 2);
    expect((list[2]! << 8) | list[3]!).toBe(sct.length);
    expect(list.subarray(4)).toEqual(sct);
  });

  it("carries several SCTs in order", () => {
    const a = serialiseSct(FIXTURE);
    const b = serialiseSct({ ...FIXTURE, timestamp: FIXTURE.timestamp + 1 });
    const value = new Uint8Array(sctListExtension([a, b]).value);
    const lenByte = value[1]!;
    const list = value.subarray(lenByte < 0x80 ? 2 : 2 + (lenByte & 0x7f));
    expect((list[0]! << 8) | list[1]!).toBe(list.length - 2);
    expect((list[2]! << 8) | list[3]!).toBe(a.length);
    const second = 4 + a.length;
    expect((list[second]! << 8) | list[second + 1]!).toBe(b.length);
    expect(list.subarray(second + 2)).toEqual(b);
  });

  it("refuses an empty list rather than embedding a meaningless extension", () => {
    // An SCT list with no SCTs satisfies the encoding and proves nothing was
    // logged. Emitting it would put a transparency extension on a cert no log
    // ever saw.
    expect(() => sctListExtension([])).toThrow(/empty|at least one/i);
  });
});
