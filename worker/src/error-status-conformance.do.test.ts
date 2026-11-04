/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * error-status-conformance.do.test.ts — every route @notme/contract's
 * ERROR_STATUS names answers the status the contract says (notme-778cbf).
 *
 * contract-package.test.ts pins the TABLE (OIDC_PROOF_REJECTED is 403, ...),
 * which only proves the table equals itself. Nothing drove a route and
 * compared, so `/auth/oidc/login` answered 401 for a refused proof for as
 * long as the contract said 403, and a client keying on the contract
 * misread the refusal. This file is the missing half: each row sends the
 * failure the contract names to the route it names, and compares the
 * route's status with `ERROR_STATUS[key]`.
 */
import { ERROR_STATUS } from "@notme/contract";
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../worker";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = {
  SITE_URL: ORIGIN,
  SIGNET_AUTHORITY_URL: ORIGIN,
  GHA_ALLOWED_OWNERS: "example",
  GHA_CERT_AUDIENCE: "notme.bot",
};

const call = (path: string, init: RequestInit) =>
  worker.fetch(new Request(`${ORIGIN}${path}`, init), { ...env, ...LOCAL_ENV } as never);

const postJson = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  call(path, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });

type Row = {
  key: keyof typeof ERROR_STATUS;
  route: string;
  send: () => Promise<Response>;
};

// One row per (route, failure class) the contract documents. A garbage JWT
// is refused by every verifier before anything is read or spent, so each
// row reaches exactly the refusal it names.
const ROWS: Row[] = [
  {
    key: "OIDC_PROOF_REJECTED",
    route: "POST /join (oidc proof)",
    send: () =>
      postJson("/join", { token: crypto.randomUUID(), proof: { type: "oidc", token: "not.a.jwt" } }),
  },
  {
    key: "OIDC_LOGIN_REJECTED",
    route: "POST /auth/oidc/login",
    send: () => postJson("/auth/oidc/login", { token: "not.a.jwt" }),
  },
  {
    key: "GHA_TOKEN_INVALID",
    route: "POST /cert/gha",
    send: () => postJson("/cert/gha", {}, { authorization: "Bearer not.a.jwt" }),
  },
  {
    key: "RESET_NOT_PERMITTED",
    route: "POST /auth/passkey/reset",
    send: () => postJson("/auth/passkey/reset", { bootstrapCode: "not-the-code" }),
  },
  {
    key: "SESSION_REQUIRED",
    route: "POST /admin/revoke-epoch (no session)",
    send: () => call("/admin/revoke-epoch", { method: "POST" }),
  },
];

describe("ERROR_STATUS conformance — the routes answer what the contract says (notme-778cbf)", () => {
  for (const row of ROWS) {
    it(`${row.route} answers ERROR_STATUS.${row.key}`, async () => {
      const res = await row.send();
      expect(res.status, `${row.route}: ${await res.clone().text()}`).toBe(ERROR_STATUS[row.key]);
    });
  }
});
