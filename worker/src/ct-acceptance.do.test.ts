/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * ct-acceptance.do.test.ts — the falsifiable end-to-end acceptance for
 * issuance logging (notme-1b46a8, Task 6), against a REAL azul log.
 *
 * Runs ONLY under vitest.workers.ct-live.config.mts, where CT_LOG is a proxy
 * to the azul ct_worker at CT_LOG_URL. Nothing here is a stub: the SCTs come
 * from the log's own key, the outage is a refused TCP connection, and the
 * drain's add-chain lands in the log's own tree.
 *
 * Three steps, all through the real route /cert/gha with a genuinely signed
 * GitHub OIDC token (stubbed JWKS, as the other /cert/gha suites do):
 *
 *   1. log up    → both certs carry an embedded SCT whose log id is THIS
 *                  log's, and nothing is backlogged;
 *   2. log down  → the mint still succeeds, unlogged, and BOTH final chains
 *                  are backlogged;
 *   3. log back  → one alarm fire drains the backlog: every row is marked
 *                  logged and health reports an empty backlog.
 *
 * What this file cannot see it hands on. Each step prints a `CT_ACCEPT`
 * line; ct/scripts/acceptance.sh turns them into PEMs and asks azul's OWN
 * code whether (1) the embedded SCTs verify (sct_validator), and (3) the
 * drained certificates are in the log's signed tree (integration_tests'
 * checkpoint + Merkle inclusion). A verifier written here would only prove
 * the encoder agrees with its author.
 *
 * Skipped when CT_LOG_URL is unset — loudly, with the command to run — not
 * silently turned into a pass (notme-8da0a3).
 */
import {
  env,
  runDurableObjectAlarm,
  runInDurableObject,
} from "cloudflare:test";
import { X509Certificate } from "@peculiar/x509";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import worker from "../worker";
import {
  type GhaSigner,
  ghaPopBody,
  installGhaSigner,
} from "./__tests__/helpers/gha-token";
import { CT_POISON_OID, CT_SCT_LIST_OID } from "./ct/sct";

const E = env as unknown as {
  CT_LOG_URL?: string;
  CT_LOG_PATH?: string;
  CT_LOG?: Fetcher;
};
const LOG_URL = E.CT_LOG_URL;
const READY = !!(LOG_URL && E.CT_LOG);
if (!READY) {
  console.warn(
    "ct.acceptance SKIPPED: no local log configured. Start one (ct/README.md, " +
      '"End-to-end acceptance") and run ct/scripts/acceptance.sh, or set ' +
      "CT_LOG_URL=http://localhost:8787/logs/notmedev with " +
      "--config vitest.workers.ct-live.config.mts.",
  );
}

const ORIGIN = "http://localhost:8788";
const OWNER = "agentic-research";
const REPO = "notme";
const AUDIENCE = "notme.bot";
const BASE_ENV = {
  SITE_URL: ORIGIN,
  SIGNET_AUTHORITY_URL: ORIGIN,
  GHA_ALLOWED_OWNERS: OWNER,
  GHA_CERT_AUDIENCE: AUDIENCE,
};

/**
 * The FIXED test authority key — the same one ct-full-cycle plants, whose
 * root is ct/testdata/roots.local-authority.pem. The log compiles its roots
 * in at build time, so the authority must sign with a key that root names.
 * THIS IS NOT NOTME'S CA (that is trust/notme-root.pem).
 */
const FIXED_KEY = {
  private_jwk: {
    key_ops: ["sign"],
    ext: true,
    crv: "Ed25519",
    d: "8BerFCZ8MeHvZbIPXxOtEU930wmwDlXiamoKtKv2xxg",
    x: "8GeBIdjKGDYyFm0vTihPDwLzE9A2tPquj5QC4pfaf6o",
    kty: "OKP",
  } as JsonWebKey,
  public_spki_b64:
    "MCowBQYDK2VwAyEA8GeBIdjKGDYyFm0vTihPDwLzE9A2tPquj5QC4pfaf6o=",
};

type Auth = {
  getSessionSecret(): Promise<string>;
  getCACertificatePem(): Promise<string>;
  getAlarmHealth(): Promise<{
    failureCount: number;
    ct: {
      backlog: number;
      gaveUp: number;
      lastError: string;
      unloggable: { count: number };
    };
  }>;
  ctx: {
    storage: {
      sql: { exec(q: string, ...b: unknown[]): { toArray(): unknown[] } };
    };
  };
};
type Row = {
  id: number;
  chain_json: string;
  attempts: number;
  logged_at: number | null;
};

const pemBody = (p: string) => p.replace(/-----[A-Z ]+-----|\s/g, "");
const authority = () =>
  env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
const inAuthority = <T>(f: (a: Auth) => Promise<T> | T) =>
  runInDurableObject(authority(), async (a) => f(a as unknown as Auth));
const backlog = () =>
  inAuthority(
    (a) =>
      a.ctx.storage.sql
        .exec(
          "SELECT id, chain_json, attempts, logged_at FROM ct_backlog ORDER BY id",
        )
        .toArray() as Row[],
  );

/** The proxy's switch: up = the real log, down = a port nothing listens on. */
async function logUp(up: boolean) {
  const r = await E.CT_LOG!.fetch("https://ct-log/__control", {
    method: "POST",
    body: JSON.stringify({ up }),
  });
  expect(((await r.json()) as { up: boolean }).up).toBe(up);
}

/** Log ids of every SCT embedded in a certificate (RFC 6962 §3.3 list). */
function embeddedLogIds(pem: string): string[] {
  const ext = new X509Certificate(pem).getExtension(CT_SCT_LIST_OID);
  if (!ext) return [];
  const v = new Uint8Array(ext.value);
  // OCTET STRING (short or long form length) wrapping the TLS list.
  expect(v[0]).toBe(0x04);
  let at = 2;
  if (v[1]! & 0x80) at = 2 + (v[1]! & 0x7f);
  const list = v.subarray(at);
  expect((list[0]! << 8) | list[1]!).toBe(list.length - 2);
  const ids: string[] = [];
  for (let i = 2; i < list.length; ) {
    const n = (list[i]! << 8) | list[i + 1]!;
    const sct = list.subarray(i + 2, i + 2 + n);
    expect(sct[0], "SCT v1").toBe(0);
    ids.push(btoa(String.fromCharCode(...sct.subarray(1, 33))));
    i += 2 + n;
  }
  return ids;
}

let signer: GhaSigner;
async function certGha(): Promise<{ status: number; body: any }> {
  const token = await signer.token();
  const res = await worker.fetch(
    new Request(`${ORIGIN}/cert/gha`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(await ghaPopBody(token)),
    }),
    { ...env, ...BASE_ENV } as never,
  );
  return { status: res.status, body: await res.json() };
}

const emit = (step: string, data: unknown) =>
  console.log(`CT_ACCEPT ${JSON.stringify({ step, ...(data as object) })}`);

describe.skipIf(!READY)(
  READY
    ? "ct.acceptance — a real azul log"
    : "ct.acceptance — SKIPPED: no local log (set CT_LOG_URL; see ct/README.md)",
  () => {
    beforeAll(async () => {
      signer = await installGhaSigner({
        owner: OWNER,
        repo: REPO,
        audience: AUDIENCE,
      });
    });
    afterAll(() => signer?.restore());

    it("logs a real /cert/gha pair, backlogs through an outage, and drains when the log returns", async () => {
      // ── setup: the fixed test authority key, planted before any key exists ──
      const issuer = await inAuthority(async (a) => {
        await a.getSessionSecret(); // creates the schema
        a.ctx.storage.sql.exec("DELETE FROM keys WHERE id = 'authority'");
        a.ctx.storage.sql.exec(
          "INSERT INTO keys (id, private_jwk, public_spki, key_id) VALUES ('authority', ?, ?, ?)",
          JSON.stringify(FIXED_KEY.private_jwk),
          FIXED_KEY.public_spki_b64,
          "local-authority",
        );
        return a.getCACertificatePem();
      });
      // Same KEY as the root the log compiled in: azul matches a chain to a root
      // by issuer name + signature, so a re-generated root cert still chains.
      const issuerSpki = new Uint8Array(
        new X509Certificate(issuer).publicKey.rawData,
      );
      expect(
        btoa(String.fromCharCode(...issuerSpki)),
        "the authority signs with the fixed key",
      ).toBe(FIXED_KEY.public_spki_b64);

      await logUp(true);
      const metaRes = await E.CT_LOG!.fetch(
        `https://ct-log${E.CT_LOG_PATH}/metadata.json`,
      );
      expect(metaRes.status, "the log serves metadata.json").toBe(200);
      const meta = (await metaRes.json()) as { log_id: string; key: string };
      emit("log", {
        log_id: meta.log_id,
        key: meta.key,
        issuer: pemBody(issuer),
      });

      // ── step 1: log up → a real pair with this log's embedded SCTs ──
      const one = await certGha();
      expect(one.status, `step 1: /cert/gha ${JSON.stringify(one.body)}`).toBe(
        200,
      );
      const pair1 = one.body.certificates as { mtls: string; signing: string };
      for (const [name, pem] of Object.entries(pair1)) {
        const c = new X509Certificate(pem);
        expect(
          c.getExtension(CT_POISON_OID),
          `step 1: ${name} carries no poison`,
        ).toBeFalsy();
        expect(
          embeddedLogIds(pem),
          `step 1: ${name} embeds exactly one SCT, from THIS log`,
        ).toEqual([meta.log_id]);
      }
      expect(
        (await backlog()).length,
        "step 1: a logged mint backlogs nothing",
      ).toBe(0);
      emit("1", { mtls: pemBody(pair1.mtls), signing: pemBody(pair1.signing) });

      // ── step 2: log down → minted unlogged, both final chains backlogged ──
      await logUp(false);
      const two = await certGha();
      expect(
        two.status,
        `step 2: /cert/gha must not fail on the log's account`,
      ).toBe(200);
      const pair2 = two.body.certificates as { mtls: string; signing: string };
      for (const [name, pem] of Object.entries(pair2)) {
        const c = new X509Certificate(pem);
        expect(
          c.getExtension(CT_POISON_OID),
          `step 2: ${name} carries no poison`,
        ).toBeFalsy();
        expect(
          c.getExtension(CT_SCT_LIST_OID),
          `step 2: ${name} carries no SCT`,
        ).toBeFalsy();
      }
      const rows2 = await backlog();
      expect(
        rows2.map((r) => JSON.parse(r.chain_json)[0]),
        "step 2: both final certs are backlogged",
      ).toEqual([pemBody(pair2.mtls), pemBody(pair2.signing)]);
      expect(rows2.every((r) => r.logged_at === null)).toBe(true);
      const h2 = await inAuthority((a) => a.getAlarmHealth());
      expect(h2.ct.backlog, "step 2: health shows the backlog").toBe(2);
      emit("2", { mtls: pemBody(pair2.mtls), signing: pemBody(pair2.signing) });

      // ── step 3: log back → the alarm drains the backlog into the log ──
      await logUp(true);
      expect(
        await runDurableObjectAlarm(authority()),
        "step 3: an alarm was scheduled",
      ).toBe(true);
      const rows3 = await backlog();
      expect(
        rows3.map((r) => ({
          id: r.id,
          logged: r.logged_at !== null,
          attempts: r.attempts,
        })),
        "step 3: every backlog row is logged on the first fire",
      ).toEqual(rows2.map((r) => ({ id: r.id, logged: true, attempts: 0 })));
      const h3 = await inAuthority((a) => a.getAlarmHealth());
      expect(h3.ct.backlog, "step 3: health shows an empty backlog").toBe(0);
      expect(h3.ct.gaveUp).toBe(0);
      expect(
        h3.failureCount,
        "step 3: the drain did not trip the alarm breaker",
      ).toBe(0);
      emit("3", { drained: rows3.map((r) => JSON.parse(r.chain_json)[0]) });
    });
  },
);
