/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * pre-do-limits.do.test.ts — an unauthenticated request that is going to be
 * refused must be refused BEFORE it costs the SigningAuthority anything
 * (notme-ed6114).
 *
 * There is one SigningAuthority, and it serialises issuance. Every RPC to it
 * is billed and queues behind honest mints, so "refused, but only after a DO
 * call" is still a flood that reaches the singleton. Each test counts the
 * RPCs made on the stub rather than inferring them from a status code: a 429
 * says the limiter refused, not that it refused first.
 */
import { env } from "cloudflare:test";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import worker from "../worker";
import { createSessionCookie } from "./auth/session";
import { type GhaSigner, installGhaSigner } from "./__tests__/helpers/gha-token";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN, GHA_ALLOWED_OWNERS: "agentic-research" };

/**
 * The SIGNING_AUTHORITY namespace, with every RPC on every stub it hands out
 * recorded by method name. Getting a stub is not an RPC; calling a method on
 * one is, so that is what is counted.
 */
function spiedAuthority() {
  const calls: string[] = [];
  const ns = env.SIGNING_AUTHORITY;
  const binding = {
    idFromName: (name: string) => ns.idFromName(name),
    get: (id: DurableObjectId) => {
      const stub = ns.get(id);
      return new Proxy(stub, {
        get(target, prop) {
          const value = Reflect.get(target, prop);
          if (typeof prop !== "string" || prop === "then" || typeof value !== "function") return value;
          return (...args: unknown[]) => {
            calls.push(prop);
            // Called through the stub, not via .apply: on an RPC stub `apply` is
            // itself looked up as a remote method.
            return (target as unknown as Record<string, (...a: unknown[]) => unknown>)[prop]!(...args);
          };
        },
      });
    },
  };
  return { calls, binding };
}

/** A stand-in for a rate-limit binding, which has no test constructor. */
function limiter(allow: (key: string) => boolean) {
  const keys: string[] = [];
  return {
    keys,
    binding: {
      limit: async ({ key }: { key: string }) => {
        keys.push(key);
        return { success: allow(key) };
      },
    },
  };
}

const call = (req: Request, extra: Record<string, unknown>) =>
  worker.fetch(req, { ...env, ...LOCAL_ENV, ...extra } as never);

describe("POST /token is limited before any SigningAuthority RPC", () => {
  const tokenReq = (headers: Record<string, string>, body: string) =>
    new Request(`${ORIGIN}/token`, {
      method: "POST",
      headers: { DPoP: "placeholder.validated.after-the-limiter", "cf-connecting-ip": "198.51.100.7", ...headers },
      body,
    });
  const sessionReq = (cookie: string) =>
    tokenReq(
      { "content-type": "application/json", cookie },
      JSON.stringify({ audience: "https://notme.bot" }),
    );

  it("a limited request carrying a forged session cookie makes no RPC at all", async () => {
    // The flood shape: any value in notme_session used to buy a
    // getSessionSecret() before the limiter could run, because the limiter
    // keyed on a principal only the DO's secret can establish.
    const spy = spiedAuthority();
    const rl = limiter(() => false);
    const res = await call(sessionReq("notme_session=forged.value"), {
      SIGNING_AUTHORITY: spy.binding,
      TOKEN_LIMITER: rl.binding,
    });
    expect(res.status).toBe(429);
    expect(spy.calls).toEqual([]);
  });

  it("a principal over its budget is refused before its live scopes are read", async () => {
    const stub = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
    const cookie = await createSessionCookie(
      { principalId: "over-budget", scopes: ["bridgeCert"], authMethod: "passkey" },
      await stub.getSessionSecret(),
    );
    const spy = spiedAuthority();
    const rl = limiter((key) => !key.startsWith("token:"));
    const res = await call(sessionReq(cookie), { SIGNING_AUTHORITY: spy.binding, TOKEN_LIMITER: rl.binding });
    expect(res.status).toBe(429);
    // The secret is needed to learn WHO is asking; nothing after that is.
    expect(spy.calls).toEqual(["getSessionSecret"]);
    expect(rl.keys).toContain("token:over-budget");
  });

  describe("token exchange", () => {
    let signer: GhaSigner;
    beforeAll(async () => {
      signer = await installGhaSigner({ owner: "agentic-research", repo: "pre-do-limits", audience: "notme.bot" });
    });
    afterAll(() => signer.restore());

    it("a limited exchange makes no RPC: the GitHub subject is known without the DO", async () => {
      const spy = spiedAuthority();
      const rl = limiter(() => false);
      const form = new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        subject_token: await signer.token(),
        subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
        audience: "https://rosary.bot",
      });
      const res = await call(tokenReq({ "content-type": "application/x-www-form-urlencoded" }, form.toString()), {
        SIGNING_AUTHORITY: spy.binding,
        TOKEN_LIMITER: rl.binding,
      });
      expect(res.status).toBe(429);
      expect(spy.calls).toEqual([]);
    });
  });
});
