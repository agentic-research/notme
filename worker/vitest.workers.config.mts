import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

// Separate pool config for real-Durable-Object tests (*.do.test.ts). The
// default vitest.config.ts runs the plain-vitest suite (src/__tests__/**);
// this one boots workerd via vitest-pool-workers so tests can exercise a real
// SigningAuthority instance + its SQLite storage through runInDurableObject.
// Kept split so the fast unit suite never pays the workerd boot cost.
//
// pool-workers v4 API (0.18.x): the pool is a Vite plugin, `cloudflareTest`,
// taking what used to be `test.poolOptions.workers` as its argument — not the
// old `defineWorkersProject` from the removed `/config` subpath.
export default defineConfig({
  plugins: [
    cloudflareTest({
      main: "./worker.ts",
      wrangler: { configPath: "./wrangler.toml" },
    }),
  ],
  test: {
    include: ["src/**/*.do.test.ts"],
  },
});
