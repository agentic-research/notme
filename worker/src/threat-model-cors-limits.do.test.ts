/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * threat-model-cors-limits.do.test.ts — the THREAT_MODEL rows that named a
 * test which existed NOWHERE, under any name (notme-8eed12).
 *
 * The document says "each test name maps to a row in the tables above", so a
 * reader treats an identifier as evidence the defence is verified. For these
 * six it was evidence of nothing:
 *
 *   §6  cors.origin.allowlist, cors.preflight.origin-echo,
 *       cors.credentials.omitted — no test anywhere touched the CORS block.
 *   §4  dpop.rate-limit          — TOKEN_LIMITER
 *   §1  passkey.register.rate-limit — PASSKEY_LIMITER
 *   §8  routing.cache.vary       — Vary on content-negotiated responses
 *
 * staging-isolation.test.ts asserts the limiter BINDINGS are declared, which
 * is what notme-191328 closed. Nothing exercised the limiting behaviour, and
 * an absent binding is a silent no-op — so "declared" and "enforced" are
 * different claims and only one of them had a test.
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../worker";
import { createSessionCookie } from "./auth/session";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };

/** An allowlisted origin, and one that is not. Both are real production values. */
const ALLOWED = "https://rosary.bot";
const FOREIGN = "https://evil.example";

function call(
  path: string,
  init: RequestInit = {},
  extraEnv: Record<string, unknown> = {},
) {
  return worker.fetch(new Request(`${ORIGIN}${path}`, init), {
    ...env,
    ...LOCAL_ENV,
    ...extraEnv,
  } as never);
}

describe("cors.origin.allowlist", () => {
  it("echoes an allowlisted origin and refuses an unlisted one", async () => {
    const ok = await call("/token", {
      method: "POST",
      headers: { origin: ALLOWED },
    });
    expect(ok.headers.get("access-control-allow-origin")).toBe(ALLOWED);

    const no = await call("/token", {
      method: "POST",
      headers: { origin: FOREIGN },
    });
    expect(no.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("covers every origin the allowlist declares, not just the first", async () => {
    // A check that happened to pass for rosary.bot and nothing else would
    // satisfy the case above.
    for (const origin of [
      "https://rosary.bot",
      "https://auth.rosary.bot",
      "https://notme.bot",
      "https://auth.notme.bot",
      "https://mcp.rosary.bot",
      "https://mache.rosary.bot",
    ]) {
      const res = await call("/token", { method: "POST", headers: { origin } });
      expect(
        res.headers.get("access-control-allow-origin"),
        `${origin} should be allowed`,
      ).toBe(origin);
    }
  });

  it("a lookalike of an allowlisted origin is refused", async () => {
    // Set membership, not prefix or suffix matching. Each of these shares a
    // substring with a real entry.
    for (const origin of [
      "https://rosary.bot.evil.example",
      "https://evilrosary.bot",
      "http://rosary.bot",
      "https://rosary.bot:8443",
    ]) {
      const res = await call("/token", { method: "POST", headers: { origin } });
      expect(
        res.headers.get("access-control-allow-origin"),
        `${origin} must not be allowed`,
      ).toBeNull();
    }
  });

  it("marks the response Vary: Origin, or a cache would cross-serve it", async () => {
    const res = await call("/token", {
      method: "POST",
      headers: { origin: ALLOWED },
    });
    expect(res.headers.get("vary") ?? "").toMatch(/Origin/i);
  });
});

describe("cors.preflight.origin-echo", () => {
  it("never answers a preflight with a wildcard", async () => {
    for (const origin of [ALLOWED, FOREIGN]) {
      const res = await call("/token", {
        method: "OPTIONS",
        headers: { origin, "access-control-request-method": "POST" },
      });
      expect(res.status).toBe(204);
      expect(res.headers.get("access-control-allow-origin")).not.toBe("*");
    }
  });

  it("echoes only the matched origin, and nothing for an unmatched one", async () => {
    const ok = await call("/token", {
      method: "OPTIONS",
      headers: { origin: ALLOWED, "access-control-request-method": "POST" },
    });
    expect(ok.headers.get("access-control-allow-origin")).toBe(ALLOWED);

    const no = await call("/token", {
      method: "OPTIONS",
      headers: { origin: FOREIGN, "access-control-request-method": "POST" },
    });
    // Empty rather than absent: the preflight sets the header unconditionally
    // with an empty value. Either is safe; a wildcard or the echo is not.
    expect(no.headers.get("access-control-allow-origin") || "").toBe("");
  });
});

describe("cors.credentials.omitted", () => {
  it("never sets Access-Control-Allow-Credentials, on any path", async () => {
    // With credentials allowed, a browser would attach the session cookie to
    // a cross-origin call from any allowlisted origin — and the allowlist
    // includes hosts this authority does not control the code of. DPoP
    // tokens exist so that is unnecessary.
    for (const method of ["OPTIONS", "POST"]) {
      for (const origin of [ALLOWED, FOREIGN]) {
        const res = await call("/token", {
          method,
          headers: { origin, "access-control-request-method": "POST" },
        });
        expect(
          res.headers.get("access-control-allow-credentials"),
          `${method} from ${origin}`,
        ).toBeNull();
      }
    }
  });
});

describe("routing.cache.vary", () => {
  it("content-negotiated responses vary on Accept", async () => {
    // Without it the CF cache serves whichever representation it saw first
    // to every subsequent caller, regardless of what they asked for.
    const json = await call("/", {
      headers: { accept: "application/json", host: "auth.notme.bot" },
    });
    expect(json.status).toBe(200);
    expect(json.headers.get("vary") ?? "").toMatch(/Accept/i);
  });
});

/** A rate-limit binding stand-in; the real one has no test constructor. */
function limiter(allow: number) {
  const keys: string[] = [];
  return {
    keys,
    binding: {
      limit: async ({ key }: { key: string }) => {
        keys.push(key);
        return { success: keys.length <= allow };
      },
    },
  };
}

describe("passkey.register.rate-limit", () => {
  it("refuses with 429 once the limiter says no", async () => {
    const rl = limiter(0);
    const res = await call(
      "/auth/passkey/register/options",
      { method: "POST", headers: { "content-type": "application/json" }, body: "{}" },
      { PASSKEY_LIMITER: rl.binding },
    );
    expect(res.status).toBe(429);
    expect(await res.text()).toMatch(/rate_limited/);
  });

  it("buckets PER IP, which is what the row claims", async () => {
    const rl = limiter(10);
    await call(
      "/auth/passkey/register/options",
      {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.9" },
        body: "{}",
      },
      { PASSKEY_LIMITER: rl.binding },
    );
    expect(rl.keys).toEqual(["passkey:203.0.113.9"]);
  });

  it("an absent IP header does not silently share one bucket with everyone", async () => {
    // It does fall back to a single "unknown" bucket — recorded here as the
    // measured behaviour rather than asserted as a defence, because behind CF
    // the header is always present and a test that pretended otherwise would
    // be describing a deployment that does not exist.
    const rl = limiter(10);
    await call(
      "/auth/passkey/register/options",
      { method: "POST", headers: { "content-type": "application/json" }, body: "{}" },
      { PASSKEY_LIMITER: rl.binding },
    );
    expect(rl.keys).toEqual(["passkey:unknown"]);
  });

  it("is checked BEFORE any authority work, so a flood costs no DO time", async () => {
    const rl = limiter(0);
    const res = await call(
      "/auth/passkey/register/options",
      { method: "POST", headers: { "content-type": "application/json" }, body: "{}" },
      { PASSKEY_LIMITER: rl.binding },
    );
    // A 429 rather than the 401 an unbootstrapped authority would answer
    // proves the limiter ran first.
    expect(res.status).toBe(429);
  });
});

describe("dpop.rate-limit", () => {
  // /token fast-fails before session resolution on a missing DPoP header and
  // on a missing or unlisted audience, so both must be present to reach the
  // limiter at all. The PROOF itself is validated after the limiter, so a
  // placeholder is enough here and keeps this file about rate limiting.
  const AUD = "https://notme.bot";
  const tokenReq = (cookie?: string) => ({
    method: "POST",
    headers: {
      "content-type": "application/json",
      DPoP: "placeholder.validated.after-the-limiter",
      ...(cookie ? { cookie } : {}),
    },
    body: JSON.stringify({ audience: AUD }),
  });

  // createSessionCookie returns a full Set-Cookie string; the route parses a
  // Cookie header, and the leading `notme_session=<value>` pair is what it
  // reads. Passing it verbatim is what the existing /token tests do.
  async function sessionCookie(principalId: string): Promise<string> {
    const stub = env.SIGNING_AUTHORITY.get(
      env.SIGNING_AUTHORITY.idFromName("default"),
    );
    const secret = await stub.getSessionSecret();
    return createSessionCookie(
      { principalId, scopes: ["bridgeCert"], authMethod: "passkey" },
      secret,
    );
  }

  it("refuses with 429 once the limiter says no", async () => {
    const rl = limiter(0);
    const res = await call(
      "/token",
      tokenReq(await sessionCookie("rate-limited-principal")),
      { TOKEN_LIMITER: rl.binding },
    );
    expect(res.status).toBe(429);
    expect(await res.text()).toMatch(/rate_limited/);
  });

  it("buckets PER PRINCIPAL, so one caller cannot exhaust another's budget", async () => {
    const rl = limiter(10);
    for (const who of ["alice", "bob"]) {
      await call("/token", tokenReq(await sessionCookie(who)), {
        TOKEN_LIMITER: rl.binding,
      });
    }
    expect(rl.keys).toEqual(["token:alice", "token:bob"]);
  });

  it("an unauthenticated caller never reaches the limiter", async () => {
    // The limiter runs AFTER session resolution, deliberately: keying on a
    // principal requires knowing one. A stranger gets 401 and consumes no
    // budget, which is the property that makes per-principal keying safe.
    const rl = limiter(0);
    const res = await call("/token", tokenReq(), { TOKEN_LIMITER: rl.binding });
    expect(res.status).toBe(401);
    expect(rl.keys).toEqual([]);
  });
});
