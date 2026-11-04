import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";
import { baseMiniflare, NO_NETWORK_SETUP_FILES, REFLECT_SETUP_FILES, REKOR_SUITES, WARM_SETUP_FILES, x509Dir } from "./vitest.workers.config.mts";

// Pool config for the suites that revoke WITH Rekor submission on
// (notme-8befcc). Separate from vitest.workers.config.mts for the reason the
// CT config is: that config sets REKOR_SUBMIT=off, so every other suite that
// pulls revokeEpoch() provably sends nothing — the off switch is a fact there,
// not a per-test toggle.
//
// Here submission is on (REKOR_SUBMIT unset, the production default) and
// REKOR_URL names a reserved `.test` host. Nothing serves it: the suite stubs
// global fetch for that host (the DO shares the test's isolate, so its fetch
// is the stub), and anything else still falls through to the no-network
// guard, which refuses it and fails the test.
const { REKOR_SUBMIT: _off, ...bindings } = baseMiniflare.bindings as Record<string, string>;

export default defineConfig({
  resolve: { alias: { "@peculiar/x509": x509Dir } },
  plugins: [
    cloudflareTest({
      main: "./worker.ts",
      miniflare: {
        ...baseMiniflare,
        bindings: { ...bindings, REKOR_URL: "https://rekor.notme.test" },
      },
    }),
  ],
  test: {
    include: REKOR_SUITES,
    setupFiles: [...REFLECT_SETUP_FILES, ...NO_NETWORK_SETUP_FILES, ...WARM_SETUP_FILES],
  },
});
