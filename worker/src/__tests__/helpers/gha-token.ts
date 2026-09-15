/**
 * gha-token.ts — genuinely signed GitHub-shaped OIDC tokens for tests.
 *
 * Real RSA keypair, real RS256 signatures, and a JWKS served to the worker's
 * own `fetch`, so `validateGHAToken` verifies for real rather than against a
 * stubbed verifier. A test that mocks the validator proves the mock works.
 *
 * Extracted from gha-bootstrap.do.test.ts so the threat-model tests can
 * exercise the SAME path production takes — the JTI replay row in particular
 * is meaningless unless a real token is presented twice.
 */
export const GHA_ISSUER = "https://token.actions.githubusercontent.com";

export function b64u(bytes: Uint8Array | string): string {
  const u8 = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
  return btoa(String.fromCharCode(...u8))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export interface GhaSigner {
  /** Mint a signed token; override any claim. */
  token(overrides?: Record<string, unknown>): Promise<string>;
  /** Restore the real global fetch. */
  restore(): void;
}

/**
 * Install a JWKS-serving fetch and return a signer.
 *
 * ONE keypair per call, and callers should install once per FILE:
 * validateGHAToken caches JWKS for an hour at module scope, so a second
 * keypair in the same process is verified against the first one's cached
 * key and fails for a reason that has nothing to do with the test.
 */
export async function installGhaSigner(opts: {
  owner: string;
  repo: string;
  audience: string;
  ref?: string;
}): Promise<GhaSigner> {
  const keys = (await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;

  const jwk = (await crypto.subtle.exportKey("jwk", keys.publicKey)) as JsonWebKey;
  const jwks = JSON.stringify({
    keys: [{ ...jwk, kid: "test-key", alg: "RS256", use: "sig" }],
  });

  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url.startsWith(GHA_ISSUER)) {
      return new Response(jwks, { headers: { "content-type": "application/json" } });
    }
    return realFetch(input as RequestInfo, init);
  }) as typeof fetch;

  const ref = opts.ref ?? "refs/heads/main";
  return {
    async token(overrides: Record<string, unknown> = {}): Promise<string> {
      const now = Math.floor(Date.now() / 1000);
      const header = b64u(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "test-key" }));
      const payload = b64u(
        JSON.stringify({
          iss: GHA_ISSUER,
          aud: opts.audience,
          sub: `repo:${opts.owner}/${opts.repo}:ref:${ref}`,
          exp: now + 300,
          iat: now,
          jti: crypto.randomUUID(),
          repository: `${opts.owner}/${opts.repo}`,
          repository_owner: opts.owner,
          ref,
          sha: "a".repeat(40),
          actor: "test-actor",
          workflow: "test",
          job_workflow_ref: `${opts.owner}/${opts.repo}/.github/workflows/t.yml@${ref}`,
          run_id: "1",
          event_name: "push",
          ...overrides,
        }),
      );
      const sig = new Uint8Array(
        await crypto.subtle.sign(
          "RSASSA-PKCS1-v1_5",
          keys.privateKey,
          new TextEncoder().encode(`${header}.${payload}`),
        ),
      );
      return `${header}.${payload}.${b64u(sig)}`;
    },
    restore() {
      globalThis.fetch = realFetch;
    },
  };
}

/** SPKI PEM for a public key, as the mint routes expect. */
export async function spkiPem(key: CryptoKey): Promise<string> {
  const spki = (await crypto.subtle.exportKey("spki", key)) as ArrayBuffer;
  const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
  return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
}

/** The PoP body /cert/gha requires: spki ‖ spki ‖ SHA-256(token), signed as PRE-IMAGE. */
export async function ghaPopBody(token: string) {
  const mtls = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
  )) as CryptoKeyPair;
  const signing = (await crypto.subtle.generateKey(
    { name: "Ed25519" }, true, ["sign", "verify"],
  )) as CryptoKeyPair;
  const mtlsSpki = (await crypto.subtle.exportKey("spki", mtls.publicKey)) as ArrayBuffer;
  const signingSpki = (await crypto.subtle.exportKey("spki", signing.publicKey)) as ArrayBuffer;
  const tokenHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  const binding = new Uint8Array(mtlsSpki.byteLength + signingSpki.byteLength + 32);
  binding.set(new Uint8Array(mtlsSpki), 0);
  binding.set(new Uint8Array(signingSpki), mtlsSpki.byteLength);
  binding.set(new Uint8Array(tokenHash), mtlsSpki.byteLength + signingSpki.byteLength);
  const sig = (b: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(b)));
  return {
    public_keys: { mtls: await spkiPem(mtls.publicKey), signing: await spkiPem(signing.publicKey) },
    proofs: {
      mtls: sig(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, mtls.privateKey, binding)),
      signing: sig(await crypto.subtle.sign({ name: "Ed25519" }, signing.privateKey, binding)),
    },
  };
}
