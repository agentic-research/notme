/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * ct-full-cycle.do.test.ts — mint, log, embed, and emit for verification
 * (notme-1b46a8).
 *
 * The one flow that can prove embedding works: a PINNED precertificate is
 * submitted to a live log, the SCT that comes back is embedded in the final
 * certificate under the same pin, and the result is written out for an
 * INDEPENDENT verifier (azul's `sct_validator::validate_embedded_scts`) to
 * check. Nothing here verifies the signature itself — deliberately. A
 * verifier I wrote, checking an encoder I wrote, proves that I am consistent.
 *
 * REQUIRES A RUNNING LOG, so it does not run by default. It is gated on
 * CT_LOG_URL rather than skipped silently on connection failure: a test that
 * quietly turns into a no-op when its dependency is absent is the shape that
 * made routes.test.ts worthless for a year (notme-8da0a3).
 *
 *   cd <azul>/crates/ct_worker && DEPLOY_ENV=notme npx wrangler -e notme dev
 *   CT_LOG_URL=http://localhost:8787/logs/notmedev \
 *     pnpm exec vitest run --config vitest.workers.config.mts src/ct-full-cycle
 */
import { env, runInDurableObject } from "cloudflare:test";
import { X509Certificate } from "@peculiar/x509";
import { describe, expect, it } from "vitest";
import { CT_POISON_OID, CT_SCT_LIST_OID, ctPoisonExtension } from "./ct/sct";

const LOG_URL = (env as unknown as Record<string, string | undefined>).CT_LOG_URL;

/**
 * A FIXED TEST KEY. Inlined rather than read from ct/testdata/ because the
 * workers pool's tsconfig carries no node types, so `node:fs` is unavailable
 * here; ct/testdata/local-authority-key.json holds the same key as the
 * provenance record for the committed roots PEM beside it.
 *
 * THIS IS NOT NOTME'S CA. That is trust/notme-root.pem. This key exists only
 * so a locally running log — which compiles its roots in at build time — can
 * be bootstrapped once and stay valid, instead of chasing a new authority
 * root on every run.
 */
const FIXED_KEY = {
  // `alg` is STRIPPED. Node's webcrypto stamps alg:"Ed25519" on an exported
  // Ed25519 JWK; workerd's importKey rejects that with 'JSON Web Key
  // Algorithm parameter "alg" ("Ed25519") does not match requested Ed25519
  // curve'. Keys the DO generates itself carry no alg, which is why this only
  // bites a fixture crossing runtimes.
  private_jwk: {"key_ops": ["sign"], "ext": true, "crv": "Ed25519", "d": "8BerFCZ8MeHvZbIPXxOtEU930wmwDlXiamoKtKv2xxg", "x": "8GeBIdjKGDYyFm0vTihPDwLzE9A2tPquj5QC4pfaf6o", "kty": "OKP"} as JsonWebKey,
  public_spki_b64: "MCowBQYDK2VwAyEA8GeBIdjKGDYyFm0vTihPDwLzE9A2tPquj5QC4pfaf6o=",
};
const pemBody = (p: string) => p.replace(/-----[A-Z ]+-----|\s/g, "");

const spkiPem = async (k: CryptoKey) => {
  const s = (await crypto.subtle.exportKey("spki", k)) as ArrayBuffer;
  const b = btoa(String.fromCharCode(...new Uint8Array(s)));
  return `-----BEGIN PUBLIC KEY-----\n${b.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
};

describe.skipIf(!LOG_URL)("ct.full-cycle", () => {
  it("mints a pinned precert, logs it, embeds the real SCT, and emits the pair", async () => {
    const stub = env.SIGNING_AUTHORITY.get(
      env.SIGNING_AUTHORITY.idFromName("ct-full-cycle"),
    );
    const mtls = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    )) as CryptoKeyPair;
    const sign = (await crypto.subtle.generateKey(
      { name: "Ed25519" }, true, ["sign", "verify"],
    )) as CryptoKeyPair;
    const mtlsPem = await spkiPem(mtls.publicKey);
    const signPem = await spkiPem(sign.publicKey);

    const notBefore = new Date();
    const pin = {
      serialMtls: Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map((b, i) => (i === 0 ? b & 0x7f : b).toString(16).padStart(2, "0"))
        .join(""),
      serialSigning: Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map((b, i) => (i === 0 ? b & 0x7f : b).toString(16).padStart(2, "0"))
        .join(""),
      notBefore,
      notAfter: new Date(notBefore.getTime() + 300_000),
    };

    // ── phase 1: the precertificate ──
    const phase1 = await runInDurableObject(stub, async (auth) => {
      const a = auth as unknown as {
        getCACertificatePem(): Promise<string>;
        getAuthorityState(): Promise<{ epoch: number }>;
        ctx: {
          storage: {
            sql: { exec(q: string, ...args: unknown[]): { toArray(): unknown[] } };
          };
        };
      };
      // PLANT A FIXED KEY before the authority creates one.
      //
      // The workers pool gives every run isolated storage, so the authority
      // would mint a NEW CA each time — and the log compiles its roots in at
      // build time, so it could never be bootstrapped to trust a root that
      // changes every run. Two passes converge only if the key is stable.
      //
      // azul matches a chain to its root pool by the issuer's PUBLIC KEY
      // (x509_util::is_link_valid reads subject_public_key_info), so a
      // regenerated root certificate with the same key still matches the
      // committed PEM even though its serial differs.
      await (auth as unknown as { getSessionSecret(): Promise<string> }).getSessionSecret();
      a.ctx.storage.sql.exec("DELETE FROM keys WHERE id = 'authority'");
      a.ctx.storage.sql.exec(
        "INSERT INTO keys (id, private_jwk, public_spki, key_id) VALUES ('authority', ?, ?, ?)",
        JSON.stringify(FIXED_KEY.private_jwk),
        FIXED_KEY.public_spki_b64,
        "local-authority",
      );
      const ca = await a.getCACertificatePem();
      const state = await a.getAuthorityState();
      const { ED25519 } = await import("./platform");
      const signingKey = await crypto.subtle.importKey(
        "jwk", FIXED_KEY.private_jwk, ED25519, false, ["sign"],
      );
      const { mintBridgeCertPair } = await import("./cert-authority");
      const pre = await mintBridgeCertPair(
        "repo:agentic-research/notme:ref:refs/heads/main",
        "wimse://notme.bot/principal/ct-full-cycle",
        mtlsPem, signPem, signingKey,
        {
          scopes: ["bridgeCert"], epoch: state.epoch, authMethod: "gha-oidc", pin,
          extraExtensions: [ctPoisonExtension()],
        },
      );
      return { ca, pre: pre.certificates.mtls, epoch: state.epoch };
    });

    // Emitted BEFORE the submission, so a first pass against a log that does
    // not yet trust this authority still hands over the root it needs. The
    // log compiles roots in at build time (build.rs), so bootstrapping is
    // necessarily two passes.
    console.log("CT_CA " + pemBody(phase1.ca));

    // ── phase 2: log it ──
    const res = await fetch(`${LOG_URL}/ct/v1/add-pre-chain`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chain: [pemBody(phase1.pre), pemBody(phase1.ca)] }),
    });
    expect(res.status, `log refused the precertificate: ${await res.clone().text()}`).toBe(200);
    const sct = (await res.json()) as {
      sct_version: number; id: string; timestamp: number;
      extensions: string; signature: string;
    };

    // ── phase 3: the final certificate, same pin, SCT instead of poison ──
    const phase3 = await runInDurableObject(stub, async (auth) => {
      const a = auth as unknown as {
        getAuthorityState(): Promise<{ epoch: number }>;
        ctx: {
          storage: {
            sql: { exec(q: string, ...args: unknown[]): { toArray(): unknown[] } };
          };
        };
      };
      const state = await a.getAuthorityState();
      const { ED25519 } = await import("./platform");
      const signingKey = await crypto.subtle.importKey(
        "jwk", FIXED_KEY.private_jwk, ED25519, false, ["sign"],
      );
      const { mintBridgeCertPair } = await import("./cert-authority");
      const { serialiseSct, sctListExtension } = await import("./ct/sct");
      const fin = await mintBridgeCertPair(
        "repo:agentic-research/notme:ref:refs/heads/main",
        "wimse://notme.bot/principal/ct-full-cycle",
        mtlsPem, signPem, signingKey,
        {
          scopes: ["bridgeCert"], epoch: state.epoch, authMethod: "gha-oidc", pin,
          extraExtensions: [sctListExtension([serialiseSct(sct)])],
        },
      );
      return fin.certificates.mtls;
    });

    const pre = new X509Certificate(phase1.pre);
    const fin = new X509Certificate(phase3);

    // The pin held across the log round-trip — the precondition for the SCT
    // meaning anything about this certificate.
    expect(fin.serialNumber).toBe(pre.serialNumber);
    expect(fin.notBefore.getTime()).toBe(pre.notBefore.getTime());
    expect(fin.getExtension(CT_POISON_OID)).toBeFalsy();
    expect(fin.getExtension(CT_SCT_LIST_OID)).toBeTruthy();

    // Emitted for the independent verifier. NOT checked here.
    console.log(
      "CT_CYCLE " +
        JSON.stringify({
          leaf: pemBody(phase3),
          issuer: pemBody(phase1.ca),
          precert: pemBody(phase1.pre),
          sct,
        }),
    );
  });
});
