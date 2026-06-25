import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: [
      "src/__tests__/**/*.test.ts",
      // Pull in the shared-SDK tests at gen/ts/__tests__ so they're under
      // the same CI signal as the worker tests. Earlier these test files
      // existed but no test runner pointed at them — landing changes to
      // gen/ts/dpop.ts didn't fail anything until a downstream worker
      // import broke.
      // (The vault tests used to be pulled in here too; vault was retired
      // from notme — see docs/design/012-vault-retirement.md — and is now
      // owned + tested in cloister.)
      "../gen/ts/__tests__/**/*.test.ts",
    ],
  },
});
