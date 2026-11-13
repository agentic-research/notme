import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { transformSync } from "esbuild";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { configDefaults, defineConfig } from "vitest/config";
import { readPinnedAsset } from "../scripts/fetch-llo-wasm";

// scripts/task-cert/lib.ts (repo root) is imported by fork-acceptance.do.test.ts
// and resolves its deps from the repo root, where @peculiar/x509 is not hoisted.
export const x509Dir = dirname(createRequire(import.meta.url).resolve("@peculiar/x509/package.json"));

// Separate pool config for real-Durable-Object tests (*.do.test.ts). The
// default vitest.config.ts runs the plain-vitest suite (src/__tests__/**);
// this one boots workerd via vitest-pool-workers so tests can exercise a real
// SigningAuthority instance + its SQLite storage through runInDurableObject.
// Kept split so the fast unit suite never pays the workerd boot cost.
//
// Bindings are declared inline via miniflare options rather than loading
// wrangler.toml on purpose: wrangler.toml carries a [[vpc_services]] VPC_AUTH
// binding that forces miniflare to open a REMOTE connection (→ api.cloudflare.com
// for account context), which needs CF creds and can't run in CI. The DO
// rotation-grace test touches only SigningAuthority's own crypto + DO SQLite —
// no worker bindings — so we declare just that one DO and nothing else. This
// keeps the test hermetic and CI-gateable.
//
// pool-workers v4 API (0.18.x): the pool is a Vite plugin, `cloudflareTest`,
// taking what used to be `test.poolOptions.workers` as its argument — not the
// old `defineWorkersProject` from the removed `/config` subpath.
// Exported so vitest.workers.ct.config.mts boots the SAME worker with the same
// bindings plus CT_LOG, instead of a hand-copied second set that can drift.
export const baseMiniflare = {
  // Keep in sync with wrangler.toml `compatibility_date` (line 5) — the
  // isolate must behave identically to production for the code under
  // test. Not imported from wrangler.toml on purpose: this config declares
  // bindings inline precisely to avoid loading wrangler.toml (see above),
  // so the date is duplicated here. If you bump it there, bump it here.
  // The ceiling is the pinned workerd's own date (workerd 1.20261019.x, via
  // wrangler 4.151.3 and vitest-plugin 1.4.6, supports up to 2026-10-19): a
  // later date could not be exercised by this gate, so bumping past it waits
  // for a toolchain bump (notme-05324c, notme-430ad1). No compatibilityFlags:
  // the date enables nodejs_compat, as in production.
  compatibilityDate: "2026-10-19",
  bindings: {
    // The operator-set admin-recovery secret (notme-4838ae). Bound here
    // so the recovery path can be exercised at all — it is the ONLY way
    // back into an authority whose last admin credential is lost, and an
    // untested recovery path is the thing that bricked it.
    BOOTSTRAP_CODE: "r".repeat(40),
    // The attested first-boot identity (notme-addef9). A var, not a
    // secret — it is an identity, and the DO reads it from its OWN env
    // rather than from the request, so a caller cannot name itself the
    // subject permitted to bootstrap.
    BOOTSTRAP_GHA_SUBJECT: "repo:agentic-research/notme:ref:refs/heads/main",
    // The owner allowlist the DO's own mintBridgeCert gha-oidc path reads
    // (security review F7): the DO env is THIS binding set, not the
    // LOCAL_ENV a route test spreads into worker.fetch.
    GHA_ALLOWED_OWNERS: "agentic-research",
    // Renewal binding v3 handed out (notme-c9fc8c, review M1): the suites
    // test the state AFTER the release is promoted and the var turned on.
    // Production and e2e default it off (wrangler.toml.example,
    // wrangler.e2e.toml); tier-generation.do.test.ts covers off.
    RENEWAL_BINDING_V3: "on",
    // The one host AuthSession.proxy() may reach in this pool, so
    // auth-binding-session.do.test.ts can drive proxy() over a real binding
    // (notme-153f03). A reserved `.test` name: the suite stubs fetch, and the
    // no-network guard refuses it if anything forgets to.
    PROXY_ALLOWED_DESTINATIONS: "proxy-dest.notme.test",
    // The Rekor off switch (notme-8befcc). Every suite here that revokes an
    // epoch must send nothing, so submission is off in this pool, and the
    // no-network guard would fail any suite that sent anyway. The suites that
    // submit run under vitest.workers.rekor.config.mts, which drops this and
    // points REKOR_URL at a stubbed host.
    REKOR_SUBMIT: "off",
    // Forwarded from the shell so ct-full-cycle.do.test.ts can be
    // pointed at a locally running transparency log. `env` in this pool
    // is the MINIFLARE binding set, not process.env, so a bare shell
    // variable never reaches the Worker — which is why that test
    // silently skipped rather than running (notme-1b46a8).
    ...(process.env.CT_LOG_URL
      ? { CT_LOG_URL: process.env.CT_LOG_URL }
      : {}),
  },
  durableObjects: {
    // SQLite-backed per wrangler.toml migration v2 (new_sqlite_classes).
    SIGNING_AUTHORITY: {
      className: "SigningAuthority",
      useSQLite: true,
    },
    // Classic (KV-storage) DO per wrangler.toml migration v1
    // (new_classes, NOT new_sqlite_classes). Used by revocation.do.test.ts.
    REVOCATION: {
      className: "RevocationAuthority",
      useSQLite: false,
    },
  },
  // KV binding the checkRevocation() tests write bundle:current into.
  kvNamespaces: ["CA_BUNDLE_CACHE"],
  // The per-principal session limiter (notme-a34dad), at the PRODUCTION rate
  // in wrangler.toml.example, so the suites exercise the number that ships:
  // session-cookie-amplification.do.test.ts measures a real dashboard minute
  // and a hammering session against it. The other limiters stay unbound
  // here (each suite injects a stand-in), as before.
  ratelimits: {
    SESSION_LIMITER: { namespace_id: "1004", simple: { limit: 60, period: 60 as const } },
    PRINCIPAL_LIMITER: { namespace_id: "1005", simple: { limit: 300, period: 60 as const } },
  },
};

/**
 * Suites that need a CT_LOG binding run under vitest.workers.ct.config.mts and
 * are EXCLUDED here, so every suite in this config provably mints with no log
 * bound — the "no binding, no change" guarantee is what they exercise.
 */
export const CT_BOUND_SUITES = ["src/ct-mint.do.test.ts"];

/**
 * The end-to-end acceptance against a REAL log runs only under
 * vitest.workers.ct-live.config.mts (CT_LOG proxied to CT_LOG_URL), and is
 * excluded here and from the stub-log config: with CT_LOG_URL set but no
 * CT_LOG bound it could only fail.
 */
export const CT_LIVE_SUITES = ["src/ct-acceptance.do.test.ts"];

/**
 * Suites that revoke with Rekor submission ON (notme-8befcc) run under
 * vitest.workers.rekor.config.mts and are excluded here, where REKOR_SUBMIT is
 * off.
 */
export const REKOR_SUITES = ["src/rekor-revocation.do.test.ts"];

/**
 * Loads the Worker's module graph before a file's tests start, so the first
 * test to reach a dynamically imported module does not pay the cold transform
 * inside its own timeout. Under load that cold start pushed the first mint-path
 * test of eight files past 5 s at once (notme-070a8f). See the file for the
 * measurement; the timeout is NOT raised.
 */
export const WARM_SETUP_FILES = ["./src/__tests__/setup/warm-worker-modules.ts"];

/**
 * The Durable Object suite is hermetic, like the plain one (notme-73202e): a
 * fetch to any non-loopback host is refused and fails the test that made it,
 * naming the URL. The SAME module the plain suite loads, installed in the
 * pool's isolate. First after the Reflect polyfill (which wraps no fetch),
 * so everything loaded after it (the warm-up, and any fixture that wraps
 * fetch, such as helpers/gha-token.ts and helpers/oidc-issuer.ts) wraps the
 * guard and falls through to it. The tests
 * serve their own hosts; nothing here reaches production.
 *
 * Not applied to vitest.workers.ct-live.config.mts: that suite exists to talk
 * to a real transparency log, from the proxy worker, by design.
 */
export const NO_NETWORK_SETUP_FILES = ["./src/__tests__/setup/no-network.ts"];

/**
 * The Reflect polyfill @peculiar/x509 3.x requires, loaded before anything
 * imports x509 (notme-3ee3b0). FIRST in every pool's setupFiles, ahead of the
 * no-network guard: the warm-up imports x509, and a test file reaches it
 * without going through worker.ts, whose first import is the same.
 */
export const REFLECT_SETUP_FILES = ["./src/__tests__/setup/reflect-metadata.ts"];

/**
 * LLO's released leyline_sign.wasm, running in workerd, for
 * llo-cert-path.do.test.ts (notme-bc4cd2).
 *
 * Three facts force this shape, each observed on this toolchain:
 *   - workerd refuses WebAssembly.compile(bytes): "Wasm code generation
 *     disallowed by embedder". wasm has to arrive as a CompiledWasm MODULE;
 *   - a modules-format worker takes no wasm BINDING (workerd refuses to start);
 *   - the pool runs test files through vite, which cannot import a `.wasm`
 *     (with or without `?module`) as a module.
 * So the wasm lives in a small AUXILIARY worker, which miniflare loads
 * without vite, and the test reaches it over an RPC service binding
 * (env.LLO_SIGN). Its marshalling is the SAME llo-sign.ts the plain pool
 * uses, transpiled here; the bytes are read through readPinnedAsset, so what
 * workerd compiles is exactly what matched wasm/llo-release.json.
 */
const lloSignTs = join(dirname(fileURLToPath(import.meta.url)), "src/__tests__/helpers/llo-sign.ts");
export const lloSignWorker = {
  name: "llo-sign",
  compatibilityDate: "2026-10-19",
  modules: [
    {
      type: "ESModule" as const,
      path: "entry.mjs",
      contents: [
        'import { WorkerEntrypoint } from "cloudflare:workers";',
        'import wasm from "./leyline_sign.wasm";',
        'import { lloSignFrom } from "./llo-sign.mjs";',
        "const llo = lloSignFrom(wasm);",
        "export class LloSign extends WorkerEntrypoint {",
        "  verifyCertPath(leaf, intermediates, anchor, profile) { return llo.verifyCertPath(leaf, intermediates, anchor, profile); }",
        "}",
        "export default { fetch() { return new Response(null, { status: 404 }); } };",
      ].join("\n"),
    },
    {
      type: "ESModule" as const,
      path: "llo-sign.mjs",
      contents: transformSync(readFileSync(lloSignTs, "utf-8"), { loader: "ts", format: "esm" }).code,
    },
    { type: "CompiledWasm" as const, path: "leyline_sign.wasm", contents: readPinnedAsset("leyline_sign.wasm") },
  ],
};

export default defineConfig({
  resolve: { alias: { "@peculiar/x509": x509Dir } },
  plugins: [
    cloudflareTest({
      main: "./worker.ts",
      miniflare: {
        ...baseMiniflare,
        serviceBindings: { LLO_SIGN: { name: "llo-sign", entrypoint: "LloSign" } },
        workers: [lloSignWorker],
      },
    }),
  ],
  test: {
    include: ["src/**/*.do.test.ts"],
    setupFiles: [...REFLECT_SETUP_FILES, ...NO_NETWORK_SETUP_FILES, ...WARM_SETUP_FILES],
    exclude: [...configDefaults.exclude, ...CT_BOUND_SUITES, ...CT_LIVE_SUITES, ...REKOR_SUITES],
  },
});
