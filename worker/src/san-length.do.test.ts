/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * san-length.do.test.ts — the SubjectAltName URI must round-trip at any
 * length a real deployment can produce (notme-193368).
 *
 * cert-authority.ts hand-rolls the SAN with SINGLE-BYTE DER lengths:
 *
 *   sanDer[1] = 2 + sanUri.length;   // SEQUENCE length
 *   sanDer[3] = sanUri.length;       // [6] URI length
 *
 * Past 125 bytes those exceed 0x7f, and a byte with the high bit set is a
 * long-form LENGTH INDICATOR in DER, not a length. So the certificate is not
 * rejected — it is silently MALFORMED, which is worse: it is signed, it looks
 * issued, and it fails somewhere downstream in a parser the operator does not
 * control.
 *
 * This was latent while the identity segment was the constant "passkey"
 * (62 bytes). It is live now: notme-ebc9af made the segment the session's auth
 * method, and both mint paths percent-encode it, so an issuer-qualified
 * method spends roughly three bytes per ':' or '/'. Measured today —
 * "oidc:https://token.actions.githubusercontent.com" reaches 111 of the 125
 * available. A tenant-qualified enterprise issuer clears it outright, and
 * packages/contract's README tells deployers they MAY extend the issuer
 * allowlist.
 *
 * The contract is round-trip: whatever identity is minted must parse back
 * identically. An explicit length error would also be acceptable — silently
 * emitting a broken cert is not.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import * as x509 from "@peculiar/x509";
import type { SigningAuthority } from "./signing-authority";

async function keyPems() {
  const mtls = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const signing = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const pem = async (k: CryptoKey) => {
    const spki = (await crypto.subtle.exportKey("spki", k)) as ArrayBuffer;
    const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
    return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
  };
  return { mtls: await pem(mtls.publicKey), signing: await pem(signing.publicKey) };
}

/** Mint a pair with the given identity and return the parsed signing cert. */
async function mintWithIdentity(name: string, identity: string) {
  const stub = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(name));
  const keys = await keyPems();
  const result = await runInDurableObject(stub, (auth) =>
    (auth as SigningAuthority).mintBridgeCertPair({
      subject: "principal-san-length",
      identity,
      mtlsPublicKeyPem: keys.mtls,
      signingPublicKeyPem: keys.signing,
      scopes: ["bridgeCert"],
      authMethod: "passkey",
      ttlMs: 5 * 60 * 1000,
    }),
  );
  return new x509.X509Certificate((result as any).certificates.signing);
}

/** The SAN URI as a parser sees it. */
function sanUri(cert: x509.X509Certificate): string | undefined {
  const ext = cert.getExtension("2.5.29.17") as any;
  const names = new x509.GeneralNames(ext.value);
  return names.items.find((n: any) => n.type === "url")?.value;
}

describe("SubjectAltName round-trips at realistic identity lengths (notme-193368)", () => {
  it("round-trips a short identity — the case that always worked", async () => {
    const identity = "wimse://notme.bot/passkey/8b1a9953-1c73-4f2e-9a0b-1d2c3e4f5a6b";
    expect(identity.length).toBeLessThan(126);
    expect(sanUri(await mintWithIdentity("san-short", identity))).toBe(identity);
  });

  it("round-trips an identity PAST the 125-byte single-byte ceiling", async () => {
    // A tenant-qualified enterprise issuer, percent-encoded as both mint
    // paths now do. This is the shape a self-hoster reaches by following
    // packages/contract's documented allowlist extension.
    const method = encodeURIComponent(
      "oidc:https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0",
    );
    const identity = `wimse://notme.bot/${method}/8b1a9953-1c73-4f2e-9a0b-1d2c3e4f5a6b`;
    expect(identity.length).toBeGreaterThan(125);
    expect(sanUri(await mintWithIdentity("san-long", identity))).toBe(identity);
  });

  it("round-trips right at the boundary, where off-by-one lives", async () => {
    const base = "wimse://notme.bot/x/";
    for (const target of [125, 126, 127, 128]) {
      const identity = base + "a".repeat(target - base.length);
      expect(identity.length).toBe(target);
      expect(
        sanUri(await mintWithIdentity(`san-b${target}`, identity)),
        `identity of ${target} bytes did not round-trip`,
      ).toBe(identity);
    }
  });
});
