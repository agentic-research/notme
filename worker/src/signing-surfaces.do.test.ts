/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * signing-surfaces.do.test.ts — enforce the mechanical parts of ADR-016.
 *
 * ADR-016 exists because the same refusal happened twice and lived nowhere
 * reusable, so the second request arrived written the same way as the first.
 * A normative doc fixes that only if someone reads it. This makes the parts
 * that CAN be checked fail the build instead.
 *
 * What is checked here: no signing surface is reachable as a fetch route, and
 * every signing entrypoint returns a discriminated result rather than
 * throwing. What is NOT checkable mechanically — closed-vs-open format,
 * derive-don't-receive — stays prose in the ADR, and this file says so rather
 * than implying the coverage is total.
 */

import { describe, expect, it } from "vitest";
import worker, { JwtSigner, ReceiptSigner } from "../worker";
import { env } from "cloudflare:test";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };

/**
 * Paths that must NOT sign anything over HTTP (ADR-016 rule 1).
 *
 * `/internal/` is not a private namespace — `/internal/ca-bundle` is
 * registered before host enforcement and answers from the public internet.
 * Anything that signs must be an RPC method with no URL at all.
 */
const MUST_NOT_SIGN_OVER_HTTP = [
  "/internal/sign-receipt",
  "/internal/sign-jwt",
  "/internal/sign",
  "/internal/sign-blob",
];

describe("ADR-016 rule 1 — no signing surface is a fetch route", () => {
  for (const path of MUST_NOT_SIGN_OVER_HTTP) {
    it(`${path} does not sign over HTTP`, async () => {
      const res = await worker.fetch(
        new Request(`${ORIGIN}${path}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ anything: true }),
        }),
        { ...env, ...LOCAL_ENV },
      );

      // A 2xx here means something signed, or is about to. Anything else is
      // fine — 404 for a refused path, 404 from the asset handler for one
      // that was never added.
      expect(
        res.status,
        `${path} answered ${res.status}. If a signing route was added here, ` +
          `move it to a WorkerEntrypoint RPC method — /internal/ is publicly ` +
          `routable. See docs/design/016-signing-surfaces.md rule 1.`,
      ).not.toBeLessThan(300);
    });
  }

  it("the refused paths point somewhere, rather than 404ing blankly", async () => {
    // Rule 1 says refuse explicitly so a caller built against an older spec
    // learns where the surface went instead of hitting the asset handler.
    for (const path of ["/internal/sign-receipt", "/internal/sign-jwt"]) {
      const res = await worker.fetch(
        new Request(`${ORIGIN}${path}`, { method: "POST" }),
        { ...env, ...LOCAL_ENV },
      );
      const body = await res.text();
      expect(body, `${path} should name its replacement`).toMatch(
        /RPC method|entrypoint|016-signing-surfaces|ADR-01[45]/i,
      );
    }
  });
});

describe("ADR-016 rule 5 — signing entrypoints return a union, not a throw", () => {
  // A rejection across RPC surfaces as an uncaught exception in the callee and
  // stringifies the error, leaving a caller nothing but message text to branch
  // on. Every signing method must answer with {ok:false, code} instead.
  it("ReceiptSigner.signReceipt returns ok:false on garbage", async () => {
    const stub = new ReceiptSigner({} as any, env as any);
    const res = await stub.signReceipt(new Uint8Array([0xde, 0xad]));
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(typeof res.code).toBe("string");
    expect(res.code.length).toBeGreaterThan(0);
  });

  it("JwtSigner.signJwt returns ok:false for a non-delegated issuer", async () => {
    const stub = new JwtSigner(
      {} as any,
      {
        ...env,
        DELEGATED_JWT_ISSUERS: "https://allowed.example",
      } as any,
    );
    const res = await stub.signJwt({
      issuer: "https://auth.notme.bot", // the impersonation the allowlist exists to stop
      headerB64: "e30",
      payloadB64: "e30",
    });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.code).toBe("ISSUER_NOT_DELEGATED");
  });
});

describe("ADR-016 rule 2 — signing entrypoints are separate classes", () => {
  it("ReceiptSigner and JwtSigner are distinct entrypoints", () => {
    // Not methods bolted onto AuthService: a binding to one must not confer
    // the other, nor AuthService's proxy/sign/authenticate.
    expect(ReceiptSigner).not.toBe(JwtSigner);
    expect(ReceiptSigner.name).toBe("ReceiptSigner");
    expect(JwtSigner.name).toBe("JwtSigner");
  });
});
