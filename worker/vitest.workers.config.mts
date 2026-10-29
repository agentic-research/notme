import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { createRequire } from "node:module";
import { dirname } from "node:path";
import { configDefaults, defineConfig } from "vitest/config";

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
  // Keep in sync with wrangler.toml `compatibility_date` (line 4) — the
  // isolate must behave identically to production for the code under
  // test. Not imported from wrangler.toml on purpose: this config declares
  // bindings inline precisely to avoid loading wrangler.toml (see above),
  // so the date is duplicated here. If you bump it there, bump it here.
  compatibilityDate: "2026-03-01",
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
};

/**
 * Suites that need a CT_LOG binding run under vitest.workers.ct.config.mts and
 * are EXCLUDED here, so every suite in this config provably mints with no log
 * bound — the "no binding, no change" guarantee is what they exercise.
 */
export const CT_BOUND_SUITES = ["src/ct-mint.do.test.ts"];

export default defineConfig({
  resolve: { alias: { "@peculiar/x509": x509Dir } },
  plugins: [cloudflareTest({ main: "./worker.ts", miniflare: baseMiniflare })],
  test: {
    include: ["src/**/*.do.test.ts"],
    exclude: [...configDefaults.exclude, ...CT_BOUND_SUITES],
  },
});
