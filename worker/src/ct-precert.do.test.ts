/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * ct-precert.do.test.ts — a precertificate minted by the REAL mint path, with
 * the real CA key (notme-1b46a8).
 *
 * `ct-sct.test.ts` pins the extension bytes in isolation. This pins the thing
 * a log is actually handed: `mintBridgeCertPair` output carrying the poison,
 * signed by this authority, chaining to this authority's root. It also writes
 * the chain out so `add-pre-chain` can be driven against a live log — the
 * step that turns "the encoding looks right" into "a log accepted it".
 */
import { env, runInDurableObject } from "cloudflare:test";
import { X509Certificate } from "@peculiar/x509";
import { describe, expect, it } from "vitest";
import { CT_POISON_OID, CT_SCT_LIST_OID, ctPoisonExtension } from "./ct/sct";

const spkiPem = async (k: CryptoKey) => {
  const s = (await crypto.subtle.exportKey("spki", k)) as ArrayBuffer;
  const b = btoa(String.fromCharCode(...new Uint8Array(s)));
  return `-----BEGIN PUBLIC KEY-----\n${b.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
};

async function mintPair(withPoison: boolean) {
  const stub = env.SIGNING_AUTHORITY.get(
    env.SIGNING_AUTHORITY.idFromName("ct-precert"),
  );
  const mtls = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
  )) as CryptoKeyPair;
  const sign = (await crypto.subtle.generateKey(
    { name: "Ed25519" }, true, ["sign", "verify"],
  )) as CryptoKeyPair;

  return runInDurableObject(stub, async (auth) => {
    const a = auth as unknown as {
      getCACertificatePem(): Promise<string>;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ["#getOrCreateSigningKey"]?: unknown;
    };
    const ca = await a.getCACertificatePem();
    // The DO's mintBridgeCertPair RPC does not forward extraExtensions, so
    // the mint function is called directly with the authority's own key. Same
    // function the route uses; the only addition is the extension.
    const { mintBridgeCertPair } = await import("./cert-authority");
    const inner = auth as unknown as {
      getPublicKeyPem(): Promise<string>;
    };
    await inner.getPublicKeyPem(); // force key load
    // Reach the loaded signing key the same way the DO's own callers do.
    const signingKey = await (
      auth as unknown as { __ctTestSigningKey?: CryptoKey }
    ).__ctTestSigningKey;
    return { ca, signingKey, mtls, sign, withPoison };
  });
}

describe("ct.precert", () => {
  it("the poison and the SCT list are different, non-overlapping extensions", () => {
    // Guards a transposition that would be invisible in a hex dump: the two
    // OIDs differ only in their last arc.
    expect(CT_POISON_OID).not.toBe(CT_SCT_LIST_OID);
    expect(ctPoisonExtension().type).toBe(CT_POISON_OID);
  });

  it("mints a precertificate carrying a CRITICAL poison, chaining to the root", async () => {
    const stub = env.SIGNING_AUTHORITY.get(
      env.SIGNING_AUTHORITY.idFromName("ct-precert"),
    );
    const mtls = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    )) as CryptoKeyPair;
    const sign = (await crypto.subtle.generateKey(
      { name: "Ed25519" }, true, ["sign", "verify"],
    )) as CryptoKeyPair;
    const mtlsPem = await spkiPem(mtls.publicKey);
    const signPem = await spkiPem(sign.publicKey);

    const out = await runInDurableObject(stub, async (auth) => {
      const a = auth as unknown as {
        getCACertificatePem(): Promise<string>;
        getAuthorityState(): Promise<{ epoch: number }>;
        ctx: { storage: { sql: { exec(q: string): { toArray(): unknown[] } } } };
      };
      const ca = await a.getCACertificatePem();
      const state = await a.getAuthorityState();
      // The authority's private key, read from its own storage — the same
      // route delegation-depth.do.test.ts uses, because the key is not
      // returnable over RPC any more (notme-eedc9c).
      const row = a.ctx.storage.sql
        .exec("SELECT private_jwk FROM keys WHERE id = 'authority'")
        .toArray()[0] as { private_jwk: string };
      const { ED25519 } = await import("./platform");
      const signingKey = await crypto.subtle.importKey(
        "jwk", JSON.parse(row.private_jwk), ED25519, false, ["sign"],
      );
      const { mintBridgeCertPair } = await import("./cert-authority");
      const pair = await mintBridgeCertPair(
        "repo:agentic-research/notme:ref:refs/heads/main",
        "wimse://notme.bot/principal/ct-precert",
        mtlsPem,
        signPem,
        signingKey,
        {
          scopes: ["bridgeCert"],
          epoch: state.epoch,
          authMethod: "gha-oidc",
          ttlMs: 300_000,
          extraExtensions: [ctPoisonExtension()],
        },
      );
      return { ca, mtls: pair.certificates.mtls, signing: pair.certificates.signing };
    });

    for (const [which, pem] of [["mtls", out.mtls], ["signing", out.signing]] as const) {
      const cert = new X509Certificate(pem);
      const poison = cert.getExtension(CT_POISON_OID);
      expect(poison, `${which} precert has no poison extension`).toBeTruthy();
      expect(poison!.critical, `${which} poison must be critical`).toBe(true);
      // A precertificate must NOT also carry an SCT list.
      expect(cert.getExtension(CT_SCT_LIST_OID)).toBeFalsy();
      // Still a real notme leaf: same issuer, and it verifies under the root.
      const ca = new X509Certificate(out.ca);
      expect(cert.issuer).toBe(ca.subject);
      expect(await cert.verify({ publicKey: ca.publicKey })).toBe(true);
    }

    // Emit the chain so add-pre-chain can be driven against a live log. Read
    // by ct/scripts/, not asserted here.
    console.log(
      "CT_PRECERT_CHAIN " +
        JSON.stringify({
          chain: [out.mtls, out.ca].map((p) =>
            p.replace(/-----[A-Z ]+-----|\s/g, ""),
          ),
        }),
    );
  });

  it("embeds a REAL SCT into the final certificate and drops the poison", async () => {
    /**
     * The round trip, using an SCT a log actually issued rather than one I
     * constructed: returned by a local azul ct_worker from `add-pre-chain`
     * for a precertificate minted by the case above.
     *
     * A precertificate and its certificate must differ in exactly this: the
     * poison comes off, the SCT list goes on. Asserting both directions is
     * what catches an embed that leaves the poison in place — which would
     * produce a certificate every conforming verifier rejects, for a reason
     * that looks like a CA bug rather than a CT bug.
     */
    const REAL_SCT = {
      sct_version: 0,
      id: "0CIlpLhhveuR6klLqq0XS5hMRt4wsduIsX13+q6+tXg=",
      timestamp: 1790376361057,
      extensions: "AAAFAAAAAAA=",
      signature:
        "BAMARjBEAiBU7wr96bBOVgH1oih6Dsx87OCPwQ6wXq7vco5MQRnJkgIgWv3GFEgfqvkjYIy+336JNCa6QHxTh8Ba12MNcQTTm/w=",
    };
    const { serialiseSct, sctListExtension } = await import("./ct/sct");
    const sctBytes = serialiseSct(REAL_SCT);

    const stub = env.SIGNING_AUTHORITY.get(
      env.SIGNING_AUTHORITY.idFromName("ct-precert"),
    );
    const mtls = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    )) as CryptoKeyPair;
    const sign = (await crypto.subtle.generateKey(
      { name: "Ed25519" }, true, ["sign", "verify"],
    )) as CryptoKeyPair;
    const mtlsPem = await spkiPem(mtls.publicKey);
    const signPem = await spkiPem(sign.publicKey);

    const out = await runInDurableObject(stub, async (auth) => {
      const a = auth as unknown as {
        getCACertificatePem(): Promise<string>;
        getAuthorityState(): Promise<{ epoch: number }>;
        ctx: { storage: { sql: { exec(q: string): { toArray(): unknown[] } } } };
      };
      const ca = await a.getCACertificatePem();
      const state = await a.getAuthorityState();
      const row = a.ctx.storage.sql
        .exec("SELECT private_jwk FROM keys WHERE id = 'authority'")
        .toArray()[0] as { private_jwk: string };
      const { ED25519 } = await import("./platform");
      const signingKey = await crypto.subtle.importKey(
        "jwk", JSON.parse(row.private_jwk), ED25519, false, ["sign"],
      );
      const { mintBridgeCertPair } = await import("./cert-authority");
      const base = {
        scopes: ["bridgeCert"],
        epoch: state.epoch,
        authMethod: "gha-oidc",
        ttlMs: 300_000,
      };
      const pre = await mintBridgeCertPair(
        "repo:agentic-research/notme:ref:refs/heads/main",
        "wimse://notme.bot/principal/ct-embed",
        mtlsPem, signPem, signingKey,
        { ...base, extraExtensions: [ctPoisonExtension()] },
      );
      const final = await mintBridgeCertPair(
        "repo:agentic-research/notme:ref:refs/heads/main",
        "wimse://notme.bot/principal/ct-embed",
        mtlsPem, signPem, signingKey,
        { ...base, extraExtensions: [sctListExtension([sctBytes])] },
      );
      return { ca, pre: pre.certificates.mtls, final: final.certificates.mtls };
    });

    const pre = new X509Certificate(out.pre);
    const final = new X509Certificate(out.final);

    // Exactly one of the two extensions on each.
    expect(pre.getExtension(CT_POISON_OID)).toBeTruthy();
    expect(pre.getExtension(CT_SCT_LIST_OID)).toBeFalsy();
    expect(final.getExtension(CT_POISON_OID), "the poison must come OFF").toBeFalsy();
    expect(final.getExtension(CT_SCT_LIST_OID)).toBeTruthy();

    // The embedded bytes must be the log's, unchanged. Unwrap extnValue, then
    // the inner OCTET STRING, then the TLS list, and compare.
    const ext = final.getExtension(CT_SCT_LIST_OID)!;
    const value = new Uint8Array(ext.value);
    expect(value[0], "inner OCTET STRING missing").toBe(0x04);
    const lenByte = value[1]!;
    const list = value.subarray(lenByte < 0x80 ? 2 : 2 + (lenByte & 0x7f));
    expect((list[0]! << 8) | list[1]!).toBe(list.length - 2);
    expect((list[2]! << 8) | list[3]!).toBe(sctBytes.length);
    expect(list.subarray(4)).toEqual(sctBytes);

    // And it is still a certificate this authority issued.
    const ca = new X509Certificate(out.ca);
    expect(await final.verify({ publicKey: ca.publicKey })).toBe(true);
  });

  it("a PINNED pair differs ONLY in the CT extension — the invariant SCT verification needs", async () => {
    /**
     * This is the requirement the bead's build order does not mention, and it
     * is why embedding cannot be two ordinary mints.
     *
     * RFC 6962 §3.2: the log signs the precertificate's TBSCertificate with
     * the poison REMOVED. A verifier reconstructs those bytes from the final
     * certificate by removing the SCT list. If anything else differs — and a
     * random serial per call is the obvious one — the two reconstructions are
     * different bytes and the SCT verifies nowhere, while every other check
     * passes and the certificate looks logged.
     *
     * So: mint both halves under one pin, strip the CT extension from each,
     * and require what remains to be byte-identical.
     */
    const stub = env.SIGNING_AUTHORITY.get(
      env.SIGNING_AUTHORITY.idFromName("ct-precert"),
    );
    const mtls = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    )) as CryptoKeyPair;
    const sign = (await crypto.subtle.generateKey(
      { name: "Ed25519" }, true, ["sign", "verify"],
    )) as CryptoKeyPair;
    const mtlsPem = await spkiPem(mtls.publicKey);
    const signPem = await spkiPem(sign.publicKey);

    const { serialiseSct, sctListExtension } = await import("./ct/sct");
    const sctBytes = serialiseSct({
      sct_version: 0,
      id: "0CIlpLhhveuR6klLqq0XS5hMRt4wsduIsX13+q6+tXg=",
      timestamp: 1790376361057,
      extensions: "AAAFAAAAAAA=",
      signature:
        "BAMARjBEAiBU7wr96bBOVgH1oih6Dsx87OCPwQ6wXq7vco5MQRnJkgIgWv3GFEgfqvkjYIy+336JNCa6QHxTh8Ba12MNcQTTm/w=",
    });

    const notBefore = new Date();
    const pin = {
      serialMtls: "0a".repeat(16),
      serialSigning: "0b".repeat(16),
      notBefore,
      notAfter: new Date(notBefore.getTime() + 300_000),
    };

    const out = await runInDurableObject(stub, async (auth) => {
      const a = auth as unknown as {
        getAuthorityState(): Promise<{ epoch: number }>;
        ctx: { storage: { sql: { exec(q: string): { toArray(): unknown[] } } } };
      };
      const state = await a.getAuthorityState();
      const row = a.ctx.storage.sql
        .exec("SELECT private_jwk FROM keys WHERE id = 'authority'")
        .toArray()[0] as { private_jwk: string };
      const { ED25519 } = await import("./platform");
      const signingKey = await crypto.subtle.importKey(
        "jwk", JSON.parse(row.private_jwk), ED25519, false, ["sign"],
      );
      const { mintBridgeCertPair } = await import("./cert-authority");
      const base = {
        scopes: ["bridgeCert"],
        epoch: state.epoch,
        authMethod: "gha-oidc",
        pin,
      };
      const pre = await mintBridgeCertPair(
        "repo:agentic-research/notme:ref:refs/heads/main",
        "wimse://notme.bot/principal/ct-pinned",
        mtlsPem, signPem, signingKey,
        { ...base, extraExtensions: [ctPoisonExtension()] },
      );
      const fin = await mintBridgeCertPair(
        "repo:agentic-research/notme:ref:refs/heads/main",
        "wimse://notme.bot/principal/ct-pinned",
        mtlsPem, signPem, signingKey,
        { ...base, extraExtensions: [sctListExtension([sctBytes])] },
      );
      return { pre: pre.certificates.mtls, fin: fin.certificates.mtls };
    });

    const pre = new X509Certificate(out.pre);
    const fin = new X509Certificate(out.fin);

    // The pin held.
    expect(fin.serialNumber).toBe(pre.serialNumber);
    expect(fin.notBefore.getTime()).toBe(pre.notBefore.getTime());
    expect(fin.notAfter.getTime()).toBe(pre.notAfter.getTime());

    // Everything except the CT extension is the same extension set, by OID
    // and by bytes.
    const strip = (c: X509Certificate, drop: string) =>
      c.extensions
        .filter((e) => e.type !== drop)
        .map((e) => `${e.type}:${e.critical}:${btoa(String.fromCharCode(...new Uint8Array(e.value)))}`)
        .sort();
    expect(strip(fin, CT_SCT_LIST_OID)).toEqual(strip(pre, CT_POISON_OID));

    // And the CT extension is the ONLY difference in count, so nothing was
    // silently added alongside it.
    expect(fin.extensions.length).toBe(pre.extensions.length);
  });
});
