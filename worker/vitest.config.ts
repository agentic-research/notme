import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: [
      "src/__tests__/**/*.test.ts",
      // Pull in the shared-SDK tests at gen/ts/__tests__ and the vault
      // tests so they're all under the same CI signal as the worker
      // tests. Earlier these test files existed but no test runner pointed
      // at them — landing changes to gen/ts/dpop.ts or vault/src/*
      // didn't fail anything until a downstream worker import broke.
      // The vault tests use pure-function patterns with injected storage
      // (no DO bindings) per their own header comments, so they run in
      // the standard vitest pool alongside the worker's.
      "../gen/ts/__tests__/**/*.test.ts",
      "../vault/src/__tests__/**/*.test.ts",
    ],
  },
});
