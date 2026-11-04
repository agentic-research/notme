/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * auth-method-boundary.do.test.ts — a session whose authMethod does not parse
 * is not a session, on every route that reads one (notme-32003c).
 *
 * "A cert's authMethod is DERIVED, never asserted" used to rest on a
 * hand-written guard in each mint route — /cert/passkey, POST /cert, and the
 * tier approval — that agreed only by inspection, and a new route inherited
 * none of them. The check now lives in verifySessionCookie: a payload whose
 * authMethod does not parse is refused there, so every route sees the same
 * "invalid session" it sees for a forged cookie, and no route can reach a
 * mint with an unchecked method.
 *
 * The cookies here are validly SIGNED. That is the case the boundary exists
 * for: an issuer inside this authority that forgot to set the field.
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../worker";
import { createSessionCookie } from "./auth/session";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };

/** A signed session cookie with NO authMethod, backed by real grants. */
async function sessionWithoutAuthMethod(scopes: string[]): Promise<string> {
  const stub = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
  const principalId = `principal-auth-method-boundary-${crypto.randomUUID()}`;
  await stub.createPrincipalWithCapabilities(principalId, scopes);
  const secret = await stub.getSessionSecret();
  const header = await createSessionCookie({ principalId, scopes } as any, secret);
  return header.split(";")[0]!;
}

const post = (path: string, cookie: string, body: unknown) =>
  worker.fetch(
    new Request(`${ORIGIN}${path}`, {
      method: "POST",
      headers: { cookie, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
    { ...env, ...LOCAL_ENV },
  );

describe("a session with no authMethod is refused at the boundary", () => {
  it("POST /cert (session proof)", async () => {
    const cookie = await sessionWithoutAuthMethod(["bridgeCert"]);
    const res = await post("/cert", cookie, { proof: { type: "session" } });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid session" });
  });

  it("POST /cert/passkey", async () => {
    const cookie = await sessionWithoutAuthMethod(["bridgeCert"]);
    const res = await post("/cert/passkey", cookie, {
      nonce: "n",
      public_keys: { mtls: "m", signing: "s" },
      proofs: { mtls: "m", signing: "s" },
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid_session" });
  });

  it("POST /cert/issuing-ca/device/approve", async () => {
    const cookie = await sessionWithoutAuthMethod(["bridgeCert", "certMint"]);
    const res = await post("/cert/issuing-ca/device/approve", cookie, { user_code: "BCDF-GHJK" });
    expect(res.status).toBe(401);
    expect(((await res.json()) as { error: string }).error).toBe("invalid_session");
  });
});
