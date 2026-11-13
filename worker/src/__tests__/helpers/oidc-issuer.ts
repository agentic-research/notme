/**
 * oidc-issuer.ts — a fake OIDC issuer for the plain suite (notme-3fc74b).
 *
 * A real RSA keypair, real RS256 signatures, and that issuer's JWKS served
 * through a `fetch` stub, so verifyOIDC runs its whole path (trust check,
 * audience, JWKS fetch, key selection, signature) without leaving the process.
 * Same approach as gha-token.ts in the pool suite, for any trusted issuer.
 *
 * A test that used to assert "the error is not the trust error" can now
 * assert the token VERIFIES, and that the verifier asked THIS stub for keys:
 * the positive evidence the check passed, which a network failure can no
 * longer impersonate.
 *
 * ONE keypair per issuer per file: verify-proof.ts caches JWKS per issuer for
 * an hour at module scope, so a second keypair for the same issuer in the
 * same file would be checked against the first one's cached key. `fakeIssuer`
 * therefore memoises by issuer, and `requests` accumulates for the file.
 */
import { b64u } from "./gha-token";

export interface FakeIssuer {
  readonly issuer: string;
  /** Every URL the verifier fetched from this issuer, in order, for the file. */
  readonly requests: string[];
  /** Mint a signed token: iss = this issuer, a 10-minute exp, plus `claims`. */
  token(claims: Record<string, unknown>): Promise<string>;
}

const issuers = new Map<string, Promise<FakeIssuer>>();
let installed = false;

function urlOf(input: RequestInfo | URL): string {
  return typeof input === "string"
    ? input
    : input instanceof URL
      ? input.href
      : input.url;
}

/** Route `fetch` for every fake issuer; anything else goes to the prior fetch (the no-network guard). */
function install(): void {
  if (installed) return;
  installed = true;
  const prior = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = urlOf(input);
    for (const [issuer, pending] of issuers) {
      if (url.startsWith(`${issuer}/`)) {
        const fake = await pending;
        fake.requests.push(url);
        return new Response((fake as FakeIssuer & { jwks: string }).jwks, {
          headers: { "content-type": "application/json" },
        });
      }
    }
    return prior(input as RequestInfo, init);
  }) as typeof fetch;
}

async function create(issuer: string): Promise<FakeIssuer & { jwks: string }> {
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
  const jwk = (await crypto.subtle.exportKey(
    "jwk",
    keys.publicKey,
  )) as JsonWebKey;
  const kid = "fake-issuer-key";
  return {
    issuer,
    requests: [],
    jwks: JSON.stringify({ keys: [{ ...jwk, kid, alg: "RS256", use: "sig" }] }),
    async token(claims) {
      const header = b64u(JSON.stringify({ alg: "RS256", typ: "JWT", kid }));
      const payload = b64u(
        JSON.stringify({
          iss: issuer,
          exp: Math.floor(Date.now() / 1000) + 600,
          ...claims,
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
  };
}

/** The fake for `issuer` (an origin, no trailing slash), created and routed on first use. */
export function fakeIssuer(issuer: string): Promise<FakeIssuer> {
  install();
  let pending = issuers.get(issuer);
  if (!pending) {
    pending = create(issuer);
    issuers.set(issuer, pending);
  }
  return pending;
}
