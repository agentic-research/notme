
# Final fix wave report

- I1: scripts/task-cert/lib.ts adds `resolveLegacyCutoff(flag, env)`: flag "" is an error, flag wins over env, only env treats empty as unset. cli.ts `args()` now accepts `--flag=value` (other flags unchanged); verify uses the helper and checks the cutoff before `--cert`. Tests (worker/src/__tests__/task-cert-client.test.ts, "the legacy cutoff never silently turns off"): flag parsed/wins over env, bare/empty flag error, empty env unset, CLI subprocess: `=` form, bare, empty, and invalid exit 2/not 2.
  RED (old src): ⎯⎯⎯⎯⎯⎯⎯ Failed Tests 4 ⎯⎯⎯⎯⎯⎯⎯  FAIL  src/__tests__/task-cert-client.test.ts > the legacy cutoff never silently turns off (flag vs env) > a flag value parses; the flag wins over the env var TypeError: resolveLegacyCutoff is not a function  FAIL  src/__tests__/task-cert-client.test.ts > the legacy cutoff never silently turns off (flag vs env) > a bare or empty flag is an error, never the env var or no cutoff TypeError: resolveLegacyCutoff is not a function  FAIL  src/__tests__/task-cert-client.test.ts > the legacy cutoff never silently turns off (flag vs env) > only the env var keeps empty-means-unset TypeError: resolveLegacyCutoff is not a function  FAIL  src/__tests__/task-cert-client.test.ts > the legacy cutoff never silently turns off (flag vs env) > the CLI parses --legacy-cutoff=DATE like --legacy-cutoff DATE, and a bare flag exits 2 AssertionError: expected 1 to be 2 // Object.is equality       Tests  4 failed | 78 passed (82) 
  GREEN: `pnpm exec vitest run src/__tests__/task-cert-client.test.ts` -> Tests 82 passed (82).
  Smoke: `pnpm exec tsx scripts/task-cert/cli.ts verify --legacy-cutoff` -> "--legacy-cutoff needs a value", exit 2.
- I2: README criteria paragraph upgrade note; docs/REMAINING-WORK.md Stage 1 step 8 deploy note. No CHANGELOG/release-notes file exists in the repo.
- M1: cli.ts header usage states --ttl-min above 5 is refused (300 s).
- M2: README names bridgeCert, sign:git, sign:attestation (CERT_ELIGIBLE_SCOPES).
- M3: REMAINING-WORK names b06b8ea, b0e9fd8, ad1ada8, 2a5dd9b, d9f863e plus the fix commit.
- Gates: `task worker:check` exit 0; `task docs:check` exit 0.
