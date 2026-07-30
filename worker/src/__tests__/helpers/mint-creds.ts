/**
 * mint-creds.ts — real CA-signed credentials for AuthService tests.
 *
 * `AuthService.authenticate()` derives identity and scopes from the certs it
 * is handed (notme-6ad276), so tests can no longer pass literal strings like
 * `cert:alice` and assert on an identity they supplied themselves. That older
 * fixture only worked while the method believed whatever it was told — which
 * was the bug.
 *
 * These helpers mint genuinely CA-signed cert pairs, so the identity a test
 * asserts on is one it could not have injected. Shared across the isolation
 * and threat-model suites so the three of them cannot drift into testing
 * three different notions of "authenticated".
 */

import { mintBridgeCertPair } from "../../cert-authority";
import { ED25519 } from "../../platform";

/** A CA for a test file. One per suite is plenty; keygen is not free. */
export async function makeCA(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
}

export async function spkiToPem(key: CryptoKey): Promise<string> {
  const spki = (await crypto.subtle.exportKey("spki", key)) as ArrayBuffer;
  const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
  return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
}

export interface MintedCreds {
  mtlsCert: string;
  signingCert: string;
  mtlsKey: CryptoKey;
  signingKey: CryptoKey;
}

/**
 * Mint a CA-signed bridge cert pair and return it in `authenticate()`'s shape.
 *
 * The returned private keys are the COUNTERPARTS of the public keys embedded
 * in the certs. That correspondence matters for `sign()`: hand back an
 * unrelated key and the identity assertions still pass while any signature the
 * test produces is unverifiable against the cert it ships with — a fixture
 * that looks right and proves nothing.
 *
 * Keys are extractable here only because minting needs to export the SPKI.
 * Production keys are non-extractable; nothing in these tests depends on the
 * difference.
 */
export async function mintCreds(
  ca: CryptoKeyPair,
  identity: string,
  scopes: string[] = ["bridgeCert"],
): Promise<MintedCreds> {
  const mtls = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const signing = (await crypto.subtle.generateKey(ED25519, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;

  const result = await mintBridgeCertPair(
    // Principal name tracks the identity so two identities never collide on
    // one principal — a shared literal makes identity-mismatch cases
    // unfalsifiable.
    `principal-${identity.split("/").pop()}`,
    identity,
    await spkiToPem(mtls.publicKey),
    await spkiToPem(signing.publicKey),
    ca.privateKey,
    { scopes, epoch: 1, authMethod: "test" },
  );

  return {
    mtlsCert: result.certificates.mtls,
    signingCert: result.certificates.signing,
    mtlsKey: mtls.privateKey,
    signingKey: signing.privateKey,
  };
}

/**
 * A stub env exposing just the SIGNING_AUTHORITY binding `authenticate()`
 * reaches for the CA public key it verifies against.
 */
export function stubEnv(ca: CryptoKeyPair) {
  return {
    SIGNING_AUTHORITY: {
      idFromName: () => "default",
      get: () => ({
        getPublicKeyPem: async () => spkiToPem(ca.publicKey),
      }),
    },
  };
}
