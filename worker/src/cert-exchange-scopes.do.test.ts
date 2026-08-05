/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * cert-exchange-scopes.do.test.ts — POST /cert must not mint what
 * /cert/passkey forbids (notme-18dfd0).
 *
 * auth/passkey-cert-scopes.ts states the rule and gives the reason:
 * certMint is "a delegation the human never agreed to at the touch prompt",
 * and authorityManage in a long-lived exportable credential "removes the
 * 'human present at a browser' property that made granting it acceptable".
 * /cert/passkey enforces it via CERT_ELIGIBLE_SCOPES.
 *
 * /cert applies no such filter — it intersects the request against the
 * SESSION's own scopes — so the same admin session yields a cert carrying
 * both, one route over. Inert inside this repo (AuthService.proxy checks only
 * bridgeCert) but not outside it: gen/go/verify parses oidScopes into
 * Identity.Scopes for downstream authorization.
 *
 * The rule belongs to the ARTIFACT, not the route. A certificate is
 * long-lived, exportable and usable off-origin however it was obtained.
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../worker";
import { createSessionCookie } from "./auth/session";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };

function b64u(b: Uint8Array): string {
  return btoa(String.fromCharCode(...b))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function pem(spki: ArrayBuffer): string {
  const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
  return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
}

async function adminSession(scopes: string[]): Promise<string> {
  const stub = env.SIGNING_AUTHORITY.get(
    env.SIGNING_AUTHORITY.idFromName("default"),
  );
  const secret = await stub.getSessionSecret();
  return createSessionCookie(
    { principalId: "principal-cert-scope-test", scopes, authMethod: "passkey" },
    secret,
  );
}

/**
 * A PoP request for /cert. NOTE the binding differs from /cert/passkey: this
 * route hashes mtls_spki ‖ signing_spki with NO session term.
 */
async function mintRequest() {
  const mtls = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const signing = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;

  const mtlsSpki = (await crypto.subtle.exportKey(
    "spki",
    mtls.publicKey,
  )) as ArrayBuffer;
  const signingSpki = (await crypto.subtle.exportKey(
    "spki",
    signing.publicKey,
  )) as ArrayBuffer;

  const input = new Uint8Array(mtlsSpki.byteLength + signingSpki.byteLength);
  input.set(new Uint8Array(mtlsSpki), 0);
  input.set(new Uint8Array(signingSpki), mtlsSpki.byteLength);
  const binding = await crypto.subtle.digest("SHA-256", input);

  return {
    public_keys: { mtls: pem(mtlsSpki), signing: pem(signingSpki) },
    proofs: {
      mtls: b64u(
        new Uint8Array(
          await crypto.subtle.sign(
            { name: "ECDSA", hash: "SHA-256" },
            mtls.privateKey,
            binding,
          ),
        ),
      ),
      signing: b64u(
        new Uint8Array(
          await crypto.subtle.sign(
            { name: "Ed25519" },
            signing.privateKey,
            binding,
          ),
        ),
      ),
    },
  };
}

function postCert(body: unknown, cookie: string) {
  return worker.fetch(
    new Request(`${ORIGIN}/cert`, {
      method: "POST",
      headers: { cookie, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
    { ...env, ...LOCAL_ENV },
  );
}

describe("POST /cert honours CERT_ELIGIBLE_SCOPES (notme-18dfd0)", () => {
  it("refuses to put certMint or authorityManage in a minted cert", async () => {
    const cookie = await adminSession([
      "bridgeCert",
      "certMint",
      "authorityManage",
    ]);
    const res = await postCert(
      {
        proof: { type: "session" },
        scopes: ["certMint", "authorityManage"],
        ...(await mintRequest()),
      },
      cookie,
    );

    if (res.status === 200) {
      const body = (await res.json()) as { scopes: string[] };
      expect(body.scopes).not.toContain("certMint");
      expect(body.scopes).not.toContain("authorityManage");
    } else {
      // Refusing outright is also acceptable — what must not happen is a
      // 200 carrying the forbidden scopes.
      expect(res.status).toBe(403);
    }
  });

  it("still mints bridgeCert for an admin session — the filter narrows, it does not block", async () => {
    const cookie = await adminSession([
      "bridgeCert",
      "certMint",
      "authorityManage",
    ]);
    const res = await postCert(
      {
        proof: { type: "session" },
        scopes: ["bridgeCert", "certMint"],
        ...(await mintRequest()),
      },
      cookie,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { scopes: string[] };
    expect(body.scopes).toEqual(["bridgeCert"]);
  });

  it("agrees with /cert/passkey for the same session — the rule is the artifact's, not the route's", async () => {
    const cookie = await adminSession([
      "bridgeCert",
      "certMint",
      "authorityManage",
    ]);
    const viaCert = await postCert(
      {
        proof: { type: "session" },
        scopes: ["bridgeCert", "certMint", "authorityManage"],
        ...(await mintRequest()),
      },
      cookie,
    );
    expect(viaCert.status).toBe(200);
    const body = (await viaCert.json()) as { scopes: string[] };
    // /cert/passkey yields exactly ["bridgeCert"] for this session
    // (passkey-cert.do.test.ts pins it). Two routes, one artifact, one answer.
    expect(body.scopes).toEqual(["bridgeCert"]);
  });
});
