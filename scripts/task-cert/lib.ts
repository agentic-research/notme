/**
 * Task-certificate client (notme-486e8a): what a MACHINE runs to hold a
 * delegation tier and mint task certificates offline.
 *
 * The flow it implements:
 *   1. enroll — generate a tier keypair HERE; ask the authority for a device
 *      enrolment; a human approves the user code with their passkey; collect
 *      the tier with a proof over the device code.
 *   2. mint  — per task, with no network: a cert pair whose identity is
 *      <tier identity>/<task> and whose .1.9 extension commits to the task id
 *      and a hash of its goal.
 *   3. verify — root → tier → task.
 *
 * Minting uses the AUTHORITY'S OWN code (worker/src/cert-authority.ts), not a
 * client copy, so the offline mint enforces the same rules the authority
 * would: scopes never exceed the tier's, lifetime never outlives it, an
 * expired tier is refused, and the tier key must match the tier cert.
 */
import { X509Certificate, BasicConstraintsExtension } from "@peculiar/x509";
import { mintTaskCertPair } from "../../worker/src/cert-authority";
import { ED25519 } from "../../worker/src/platform";
import { deviceCodeHash, tierEnrolmentBinding } from "../../worker/src/auth/tier-enrolment-binding";

const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const b64url = (b: Uint8Array) => b64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const hex = (b: Uint8Array) => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const pemWrap = (label: string, der: Uint8Array) =>
  `-----BEGIN ${label}-----\n${b64(der).match(/.{1,64}/g)!.join("\n")}\n-----END ${label}-----\n`;
const pemBody = (pem: string) =>
  Uint8Array.from(atob(pem.replace(/-----[A-Z ]+-----|\s/g, "")), (c) => c.charCodeAt(0));

export async function generateTierKey(): Promise<{
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  spki: Uint8Array;
  pem: string;
  fingerprint: string;
}> {
  // Extractable ONLY so it can be written to disk once; it is re-imported
  // non-extractable for every use after that.
  const kp = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = new Uint8Array((await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer);
  const fingerprint = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", spki)));
  return { privateKey: kp.privateKey, publicKey: kp.publicKey, spki, pem: pemWrap("PUBLIC KEY", spki), fingerprint };
}

/** The fingerprint as the approval page shows it — first 64 bits, in fours. */
export function groupFingerprint(fingerprintHex: string): string {
  return fingerprintHex.slice(0, 16).match(/..../g)!.join(" ");
}

export async function exportPrivateKeyPem(key: CryptoKey): Promise<string> {
  return pemWrap("PRIVATE KEY", new Uint8Array((await crypto.subtle.exportKey("pkcs8", key)) as ArrayBuffer));
}

export async function importPrivateKeyPem(pem: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("pkcs8", pemBody(pem), ED25519, false, ["sign"]);
}

/** The collection proof — over the authority's shared binding, byte for byte. */
export async function enrolProof(privateKey: CryptoKey, spki: Uint8Array, deviceCode: string): Promise<string> {
  const input = tierEnrolmentBinding(spki, await deviceCodeHash(deviceCode));
  return b64url(new Uint8Array(await crypto.subtle.sign(ED25519, privateKey, input)));
}

export type EnrolmentStart = {
  device_code: string;
  user_code: string;
  verification_uri: string;
  key_fingerprint: string;
  expires_in: number;
  interval: number;
};

export async function startEnrolment(
  authority: string,
  publicKeyPem: string,
  scopes: string[] | undefined,
  fetchFn: typeof fetch = fetch,
): Promise<EnrolmentStart> {
  const res = await fetchFn(`${authority}/cert/issuing-ca/device`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ public_key: publicKeyPem, ...(scopes ? { scopes } : {}) }),
  });
  const body = (await res.json().catch(() => ({}))) as EnrolmentStart & { error?: string };
  if (!res.ok) throw new Error(`enrolment start refused: ${body.error ?? res.status}`);
  return body;
}

/**
 * Poll until the human approves (RFC 8628 §3.4–3.5). `authorization_pending`
 * and `slow_down` keep polling; anything else is terminal and is thrown with
 * the authority's error name, so a script can tell "denied" from "expired".
 */
export async function pollEnrolment(
  authority: string,
  deviceCode: string,
  proof: string,
  opts: {
    interval: number;
    expiresIn: number;
    fetchFn?: typeof fetch;
    sleep?: (ms: number) => Promise<void>;
  },
): Promise<any> {
  const fetchFn = opts.fetchFn ?? fetch;
  const sleep = opts.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
  let interval = opts.interval;
  const deadline = Date.now() + opts.expiresIn * 1000;
  for (;;) {
    const res = await fetchFn(`${authority}/cert/issuing-ca/device/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ device_code: deviceCode, proof }),
    });
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    if (res.ok) return body;
    if (body.error === "authorization_pending" || body.error === "slow_down") {
      if (body.error === "slow_down") interval += 5;
      if (Date.now() + interval * 1000 > deadline) throw new Error("expired_token");
      await sleep(interval * 1000);
      continue;
    }
    throw new Error(body.error ?? `HTTP ${res.status}`);
  }
}

async function spkiPemOf(key: CryptoKey): Promise<string> {
  return pemWrap("PUBLIC KEY", new Uint8Array((await crypto.subtle.exportKey("spki", key)) as ArrayBuffer));
}

/**
 * Mint a task cert pair OFFLINE under the tier. Generates the task's own
 * keys; the goal is hashed here so the certificate commits to it without
 * carrying the text.
 */
export async function mintTask(
  tierPem: string,
  tierPrivateKey: CryptoKey,
  opts: { task: string; goal: string; epoch: number; scopes?: string[]; ttlMs?: number },
) {
  const mtls = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const signing = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
  const goalHash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(opts.goal))));
  const result = await mintTaskCertPair(
    tierPem,
    tierPrivateKey,
    await spkiPemOf(mtls.publicKey),
    await spkiPemOf(signing.publicKey),
    { task: opts.task, goalHash, scopes: opts.scopes ?? ["bridgeCert"], epoch: opts.epoch, ttlMs: opts.ttlMs },
  );
  return {
    ...result,
    goalHash,
    keys: {
      mtls: pemWrap("PRIVATE KEY", new Uint8Array((await crypto.subtle.exportKey("pkcs8", mtls.privateKey)) as ArrayBuffer)),
      signing: pemWrap("PRIVATE KEY", new Uint8Array((await crypto.subtle.exportKey("pkcs8", signing.privateKey)) as ArrayBuffer)),
    },
  };
}

/**
 * root → tier → task. Signatures checked with the library; validity windows
 * checked HERE, inclusively, because @peculiar/x509's date check is a strict
 * `notBefore < t` and reads a cert as invalid at the instant it was minted.
 */
export async function verifyChain(
  rootPem: string,
  tierPem: string,
  leafPem: string,
  at: Date = new Date(),
): Promise<{ ok: true } | { ok: false; reason: string }> {
  const root = new X509Certificate(rootPem);
  const tier = new X509Certificate(tierPem);
  const leaf = new X509Certificate(leafPem);
  const within = (c: X509Certificate) => c.notBefore.getTime() <= at.getTime() && at.getTime() <= c.notAfter.getTime();

  if (tier.issuer !== root.subject) return { ok: false, reason: "tier was not issued by this root" };
  if (!(await tier.verify({ publicKey: await root.publicKey.export(), signatureOnly: true }))) {
    return { ok: false, reason: "tier signature does not verify under the root" };
  }
  const bc = tier.getExtension(BasicConstraintsExtension);
  if (!bc?.ca || bc.pathLength !== 0) return { ok: false, reason: "tier is not a pathlen=0 CA" };
  if (leaf.issuer !== tier.subject) return { ok: false, reason: "task cert was not issued by this tier" };
  if (!(await leaf.verify({ publicKey: await tier.publicKey.export(), signatureOnly: true }))) {
    return { ok: false, reason: "task cert signature does not verify under the tier" };
  }
  if (leaf.getExtension(BasicConstraintsExtension)?.ca) return { ok: false, reason: "task cert must not be a CA" };
  for (const [c, name] of [[root, "root"], [tier, "tier"], [leaf, "task cert"]] as const) {
    if (!within(c)) return { ok: false, reason: `${name} is not valid at ${at.toISOString()}` };
  }
  return { ok: true };
}
