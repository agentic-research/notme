import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: [
      "src/__tests__/**/*.test.ts",
      // Pull in the shared-SDK tests at packages/dpop so they're under the
      // same CI signal as the worker tests. Earlier these test files existed
      // but no test runner pointed at them — landing changes to the DPoP SDK
      // didn't fail anything until a downstream worker import broke.
      // This path MUST track wherever the SDK's tests live: the notme-18450e
      // move (gen/ts/__tests__ → packages/dpop/__tests__) silently dropped 67
      // tests from this signal until the glob was repointed, which is the very
      // failure the paragraph above is describing.
      // (The vault tests used to be pulled in here too; vault was retired
      // from notme — see docs/design/012-vault-retirement.md — and is now
      // owned + tested in cloister.)
      "../packages/dpop/__tests__/**/*.test.ts",
    ],
  },
});
