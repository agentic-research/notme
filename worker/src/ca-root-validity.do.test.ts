/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * ca-root-validity.do.test.ts — the root's validity window belongs to the KEY,
 * not to the moment the root was last issued (notme-0c494f).
 *
 * RFC 5280 path validation checks every certificate in the chain at the
 * verification time, and a signature verifier (cosign, git) uses the SIGNING
 * time. So a root re-issued under the same key with notBefore = now silently
 * un-verifies everything that key signed before the re-issue. Measured in
 * production: the pathlen re-issue (notme-1b1db4) moved the served root's
 * notBefore from 2026-03-31 to 2026-08-28, and signet v0.3.0, signed
 * 2026-08-07 by the same key, stopped verifying against the published anchor.
 *
 * The rule pinned here: the root's notBefore is keys.created_at, the instant
 * the key began signing. Nothing it signed can predate that, so no re-issue
 * under the same key can strand a signature.
 */
import { env, runInDurableObject } from "cloudflare:test";
import {
  BasicConstraintsExtension,
  X509Certificate,
  X509CertificateGenerator,
} from "@peculiar/x509";
import { describe, expect, it } from "vitest";
import { ED25519 } from "./platform";
import type { SigningAuthority } from "./signing-authority";

const KEY_START = "2026-03-31 01:44:33";
const KEY_START_MS = Date.parse("2026-03-31T01:44:33Z");

function pemToSpki(pem: string): Uint8Array {
  const b64 = pem.replace(/-----(BEGIN|END) PUBLIC KEY-----|\s/g, "");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

/**
 * Backdate the authority key to KEY_START and plant a cached root under that
 * same key, as production had after the pathlen re-issue. The key material is
 * read from the DO's own storage, as delegation-depth.do.test.ts does.
 */
async function plantRoot(
  a: SigningAuthority,
  opts: { notBefore: Date; pathLen: number },
): Promise<void> {
  await a.getCACertificatePem(); // force key + schema init
  const sql = a["ctx"].storage.sql;
  sql.exec("UPDATE keys SET created_at = ? WHERE id = 'authority'", KEY_START);
  const keyRow = sql
    .exec("SELECT private_jwk FROM keys WHERE id = 'authority'")
    .toArray()[0] as { private_jwk: string };
  const signingKey = await crypto.subtle.importKey(
    "jwk",
    JSON.parse(keyRow.private_jwk),
    ED25519,
    false,
    ["sign"],
  );
  const verifyKey = await crypto.subtle.importKey(
    "spki",
    pemToSpki(await a.getPublicKeyPem()),
    ED25519,
    true,
    ["verify"],
  );
  const root = await X509CertificateGenerator.createSelfSigned({
    name: "CN=signet-authority,O=notme",
    notBefore: opts.notBefore,
    notAfter: new Date(opts.notBefore.getTime() + 86_400_000 * 3650),
    signingAlgorithm: ED25519,
    keys: { privateKey: signingKey, publicKey: verifyKey },
    serialNumber: "0b",
    extensions: [new BasicConstraintsExtension(true, opts.pathLen, true)],
  });
  const { keyId } = await a.getAuthorityState();
  sql.exec("DELETE FROM ca_cert WHERE id = 'cert'");
  sql.exec(
    "INSERT INTO ca_cert (id, pem, key_id) VALUES ('cert', ?, ?)",
    root.toString("pem"),
    keyId,
  );
}

describe("the root's validity starts when its key did (notme-0c494f)", () => {
  it("a fresh key's root starts at the key's creation", async () => {
    const stub = env.SIGNING_AUTHORITY.get(
      env.SIGNING_AUTHORITY.idFromName("root-validity-fresh"),
    );
    const { pem, createdAt } = await runInDurableObject(stub, async (auth) => {
      const a = auth as SigningAuthority;
      const pem = await a.getCACertificatePem();
      const row = a["ctx"].storage.sql
        .exec("SELECT created_at FROM keys WHERE id = 'authority'")
        .toArray()[0] as { created_at: string };
      return { pem, createdAt: row.created_at };
    });
    const root = new X509Certificate(pem);
    expect(root.notBefore.getTime()).toBe(
      Date.parse(`${createdAt.replace(" ", "T")}Z`),
    );
  });

  it("re-issuing for a stale pathlen keeps the key's notBefore, not now", async () => {
    const stub = env.SIGNING_AUTHORITY.get(
      env.SIGNING_AUTHORITY.idFromName("root-validity-pathlen"),
    );
    const pem = await runInDurableObject(stub, async (auth) => {
      const a = auth as SigningAuthority;
      await plantRoot(a, { notBefore: new Date(KEY_START_MS), pathLen: 0 });
      return a.getCACertificatePem();
    });
    const root = new X509Certificate(pem);
    expect(root.getExtension(BasicConstraintsExtension)?.pathLength).toBe(1);
    expect(root.notBefore.getTime()).toBe(KEY_START_MS);
  });

  it("heals a cached root whose notBefore is later than its key — production's state", async () => {
    const stub = env.SIGNING_AUTHORITY.get(
      env.SIGNING_AUTHORITY.idFromName("root-validity-late"),
    );
    // Right pathlen, wrong window: the pathlen check alone would keep it.
    const late = new Date(Date.parse("2026-08-28T20:17:40Z"));
    const pem = await runInDurableObject(stub, async (auth) => {
      const a = auth as SigningAuthority;
      await plantRoot(a, { notBefore: late, pathLen: 1 });
      return a.getCACertificatePem();
    });
    const root = new X509Certificate(pem);
    expect(root.notBefore.getTime()).toBe(KEY_START_MS);

    // What that buys, in the verifier's own terms: a leaf this key signed
    // between the key's start and the late root (signet v0.3.0, 2026-08-07)
    // falls inside the root's window again.
    const signedAt = Date.parse("2026-08-07T15:51:46Z");
    expect(root.notBefore.getTime()).toBeLessThanOrEqual(signedAt);
    expect(root.notAfter.getTime()).toBeGreaterThan(signedAt);
  });

  it("keeps a cached root that already starts at or before its key", async () => {
    const stub = env.SIGNING_AUTHORITY.get(
      env.SIGNING_AUTHORITY.idFromName("root-validity-keep"),
    );
    const { planted, served } = await runInDurableObject(stub, async (auth) => {
      const a = auth as SigningAuthority;
      await plantRoot(a, { notBefore: new Date(KEY_START_MS), pathLen: 1 });
      const planted = a["ctx"].storage.sql
        .exec("SELECT pem FROM ca_cert WHERE id = 'cert'")
        .toArray()[0] as { pem: string };
      return { planted: planted.pem, served: await a.getCACertificatePem() };
    });
    expect(served).toBe(planted);
  });
});
