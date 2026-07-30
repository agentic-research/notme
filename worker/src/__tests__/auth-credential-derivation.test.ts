/**
 * auth-credential-derivation.test.ts — notme-6ad276 (red-team:isolation).
 *
 * THE INVARIANT: `heldCerts.identity` and `heldCerts.scopes` are
 * entrypoint-DERIVED, never entrypoint-RECEIVED.
 *
 * `AuthService.authenticate()` used to be one assignment statement —
 * `this.heldCerts = creds` — over a caller-supplied struct containing
 * `identity`, `scopes` and `expiresAt`. Any Worker holding an `AUTH` service
 * binding could therefore name itself any WIMSE principal and grant itself any
 * scope: `proxy()` gates on `scopes.includes("bridgeCert")` and audit-logs
 * `identity`, and both came straight from the caller.
 *
 * The certs are the only trustworthy input in that struct — they are CA-signed
 * and already carry the subject and the granted scopes as custom extensions
 * (cert-authority.ts OID_SUBJECT / OID_SCOPES). So the fix is to read the
 * principal out of the cert instead of believing the caller, which is what
 * these tests pin.
 */

import { describe, expect, it } from "vitest";
import { mintBridgeCertPair } from "../cert-authority";
import { deriveCredentialsFromCerts } from "../auth/derive-credentials";
import { ED25519 } from "../platform";

async function generateCAKeyPair(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey(ED25519, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
}

async function generateLeafKey(algo: "ECDSA" | "Ed25519"): Promise<CryptoKeyPair> {
  const params = algo === "ECDSA" ? { name: "ECDSA", namedCurve: "P-256" } : ED25519;
  return (await crypto.subtle.generateKey(params, true, ["sign", "verify"])) as CryptoKeyPair;
}

async function spkiToPem(key: CryptoKey): Promise<string> {
  const spki = (await crypto.subtle.exportKey("spki", key)) as ArrayBuffer;
  const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
  const lines = b64.match(/.{1,64}/g)!.join("\n");
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`;
}

/** Mint a real CA-signed bridge cert pair for `identity` with `scopes`. */
async function mintPair(
  identity: string,
  scopes: string[],
  ca: CryptoKeyPair,
  ttlMs?: number,
) {
  const mtls = await generateLeafKey("ECDSA");
  const signing = await generateLeafKey("Ed25519");
  const result = await mintBridgeCertPair(
    // Principal name derived from the identity so two different identities
    // never share one — a fixed literal here made the mismatch case
    // unfalsifiable, since both certs then named the same principal.
    `principal-${identity.split("/").pop()}`,
    identity,
    await spkiToPem(mtls.publicKey),
    await spkiToPem(signing.publicKey),
    ca.privateKey,
    { scopes, epoch: 1, authMethod: "test", ttlMs },
  );
  return result.certificates;
}

describe("deriveCredentialsFromCerts", () => {
  it("returns the identity carried in the signing cert, not any caller-supplied string", async () => {
    const ca = await generateCAKeyPair();
    const certs = await mintPair("wimse://notme.bot/test/real-principal", ["bridgeCert"], ca);

    const derived = await deriveCredentialsFromCerts(
      certs.signing,
      certs.mtls,
      await spkiToPem(ca.publicKey),
    );

    // The ONLY source of this string is the cert's SAN URI. Nothing in the
    // call above could have supplied it.
    expect(derived.identity).toBe("wimse://notme.bot/test/real-principal");
  });

  it("distinguishes the SAN identity from the OID_SUBJECT principal name", async () => {
    // These are two different fields carrying two different strings, and
    // reading the wrong one yields a plausible non-empty value rather than an
    // error — which is exactly the mistake this suite caught during the fix.
    const ca = await generateCAKeyPair();
    const certs = await mintPair("wimse://notme.bot/test/real-principal", ["bridgeCert"], ca);

    const derived = await deriveCredentialsFromCerts(
      certs.signing,
      certs.mtls,
      await spkiToPem(ca.publicKey),
    );

    expect(derived.identity).toBe("wimse://notme.bot/test/real-principal");
    expect(derived.principal).toBe("principal-real-principal");
    expect(derived.principal).not.toBe(derived.identity);
  });

  it("returns the scopes carried in the signing cert", async () => {
    const ca = await generateCAKeyPair();
    const certs = await mintPair("wimse://notme.bot/test/scoped", ["bridgeCert", "sign:git"], ca);

    const derived = await deriveCredentialsFromCerts(
      certs.signing,
      certs.mtls,
      await spkiToPem(ca.publicKey),
    );

    expect(derived.scopes).toEqual(["bridgeCert", "sign:git"]);
  });

  it("rejects a cert signed by a different CA", async () => {
    const realCA = await generateCAKeyPair();
    const attackerCA = await generateCAKeyPair();
    // A cert the attacker minted themselves, claiming a privileged identity
    // and every scope they wanted.
    const forged = await mintPair(
      "wimse://notme.bot/gha/agentic-research/cloister",
      ["bridgeCert", "sign:git", "sign:attestation"],
      attackerCA,
    );

    await expect(
      deriveCredentialsFromCerts(
        forged.signing,
        forged.mtls,
        await spkiToPem(realCA.publicKey),
      ),
    ).rejects.toThrow(/signature|CA|trusted/i);
  });

  it("rejects an expired cert", async () => {
    const ca = await generateCAKeyPair();
    // ttl in the past — notAfter is already behind us.
    const certs = await mintPair("wimse://notme.bot/test/stale", ["bridgeCert"], ca, -1000);

    await expect(
      deriveCredentialsFromCerts(
        certs.signing,
        certs.mtls,
        await spkiToPem(ca.publicKey),
      ),
    ).rejects.toThrow(/expired/i);
  });

  it("rejects when the mTLS cert names a different identity than the signing cert", async () => {
    // Both certs are individually CA-signed and valid; they simply belong to
    // two different principals. Accepting this would let a caller pair its own
    // signing cert with someone else's mTLS cert and egress as them.
    const ca = await generateCAKeyPair();
    const a = await mintPair("wimse://notme.bot/test/alice", ["bridgeCert"], ca);
    const b = await mintPair("wimse://notme.bot/test/bob", ["bridgeCert"], ca);

    await expect(
      deriveCredentialsFromCerts(a.signing, b.mtls, await spkiToPem(ca.publicKey)),
    ).rejects.toThrow(/mismatch|identity/i);
  });

  it("derives expiresAt from the cert's notAfter rather than a caller-chosen value", async () => {
    const ca = await generateCAKeyPair();
    const ttlMs = 60_000;
    const before = Math.floor(Date.now() / 1000);
    const certs = await mintPair("wimse://notme.bot/test/ttl", ["bridgeCert"], ca, ttlMs);

    const derived = await deriveCredentialsFromCerts(
      certs.signing,
      certs.mtls,
      await spkiToPem(ca.publicKey),
    );

    // Within the minted window, and nowhere near a caller-chosen far future.
    expect(derived.expiresAt).toBeGreaterThanOrEqual(before);
    expect(derived.expiresAt).toBeLessThanOrEqual(before + ttlMs / 1000 + 2);
  });
});
