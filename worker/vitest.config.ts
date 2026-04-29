import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: [
      "src/__tests__/**/*.test.ts",
      // Pull in the shared-SDK tests at gen/ts/__tests__ so they're under
      // the same CI signal as the worker tests. Earlier the SDK tests
      // existed but no test runner pointed at them — landing changes to
      // gen/ts/dpop.ts didn't fail anything until a downstream worker
      // import broke.
      "../gen/ts/__tests__/**/*.test.ts",
    ],
  },
});
