import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

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
export default defineConfig({
  plugins: [
    cloudflareTest({
      main: "./worker.ts",
      miniflare: {
        // Match wrangler.toml's compatibility_date so the isolate behaves
        // identically to production for the code under test.
        compatibilityDate: "2026-03-01",
        durableObjects: {
          // SQLite-backed per wrangler.toml migration v2 (new_sqlite_classes).
          SIGNING_AUTHORITY: {
            className: "SigningAuthority",
            useSQLite: true,
          },
        },
      },
    }),
  ],
  test: {
    include: ["src/**/*.do.test.ts"],
  },
});
