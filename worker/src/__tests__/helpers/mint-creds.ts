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
  /** CA epoch written into both certs (OID_EPOCH). */
  epoch = 1,
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
    { scopes, epoch, authMethod: "test" },
  );

  return {
    mtlsCert: result.certificates.mtls,
    signingCert: result.certificates.signing,
    mtlsKey: mtls.privateKey,
    signingKey: signing.privateKey,
  };
}

/**
 * The SigningAuthority methods AuthService reaches, faked in memory: the CA
 * public key `authenticate()` verifies against, and the single-use,
 * principal-bound PoP nonce pair (`issuePopNonce` / `consumePopNonce`) its
 * challenge is built on (notme-fbbfbc). The fake keeps the real contract —
 * a nonce is spent once, only for the principal it was issued to.
 */
export function stubAuthority(ca: CryptoKeyPair, extra: Record<string, unknown> = {}) {
  const nonces = new Map<string, string>();
  return {
    getPublicKeyPem: async () => spkiToPem(ca.publicKey),
    issuePopNonce: async (principalId: string) => {
      const nonce = b64u(crypto.getRandomValues(new Uint8Array(32)));
      nonces.set(nonce, principalId);
      return { nonce, expiresIn: 120 };
    },
    consumePopNonce: async (nonce: string, principalId: string) => {
      if (nonces.get(nonce) !== principalId) return false;
      nonces.delete(nonce);
      return true;
    },
    ...extra,
  };
}

/** A stub env exposing just the SIGNING_AUTHORITY binding AuthService reaches. */
export function stubEnv(ca: CryptoKeyPair) {
  const authority = stubAuthority(ca);
  return {
    SIGNING_AUTHORITY: {
      idFromName: () => "default",
      get: () => authority,
    },
  };
}

function b64u(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function pemToDer(pem: string): Uint8Array {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

/** SPKI DER of a cert's public key. */
async function certSpki(certPem: string): Promise<Uint8Array> {
  const { X509Certificate } = await import("@peculiar/x509");
  return new Uint8Array(new X509Certificate(pemToDer(certPem)).publicKey.rawData);
}

/**
 * The proofs `authenticate()` requires: each held private key signs the
 * authenticate binding over `challenge` (notme-fbbfbc). `signWith` lets a
 * test sign with keys OTHER than the certs' — the wrong-key case.
 */
export async function popProofs(
  creds: MintedCreds,
  challenge: string,
  signWith: { mtlsKey: CryptoKey; signingKey: CryptoKey } = creds,
): Promise<{ mtls: string; signing: string }> {
  const { authenticateBinding } = await import("../../auth/cert-pair-binding");
  const binding = await authenticateBinding(await certSpki(creds.mtlsCert), await certSpki(creds.signingCert), challenge);
  const mtls = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signWith.mtlsKey, binding),
  );
  const signing = new Uint8Array(await crypto.subtle.sign(ED25519, signWith.signingKey, binding));
  return { mtls: b64u(mtls), signing: b64u(signing) };
}

/** The identity a cert pair names (its SAN URI). */
export async function identityOf(creds: MintedCreds): Promise<string> {
  const { X509Certificate, SubjectAlternativeNameExtension } = await import("@peculiar/x509");
  const cert = new X509Certificate(pemToDer(creds.signingCert));
  const san = cert.getExtension(SubjectAlternativeNameExtension);
  return san!.names.items.find((n) => n.type === "url")!.value;
}

/**
 * authenticate() as a real caller does it: ask for a challenge, prove both
 * keys over it, present certs + challenge + proofs (+ the keys, in-isolate,
 * so sign() can use them). Returns the AuthSession authenticate() returns
 * (notme-153f03): proxy(), sign() and identity() are its methods.
 */
export async function authenticateWithPop<S>(
  svc: {
    authChallenge(identity: string): Promise<{ challenge: string }>;
    authenticate(creds: any): Promise<S>;
  },
  creds: MintedCreds,
  extra: Record<string, unknown> = {},
): Promise<S> {
  const { challenge } = await svc.authChallenge(await identityOf(creds));
  return svc.authenticate({ ...creds, challenge, proofs: await popProofs(creds, challenge), ...extra });
}
