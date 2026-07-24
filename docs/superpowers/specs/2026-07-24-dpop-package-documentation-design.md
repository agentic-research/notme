# DPoP Package Documentation Design

Date: 2026-07-24
Bead: `notme-1c93bc`

## Goal

Make `@agentic-research/dpop` understandable from its npm page and useful as a
self-contained installed package. Documentation must describe the 0.3 API
accurately and travel in the published tarball.

## Documentation layers

### npm landing page

`packages/dpop/README.md` remains the npm-rendered entry point. It will provide:

- installation and runtime requirements;
- a minimal, copy-pasteable `verifyDPoPToken` example;
- the required `audience` and `ath` behavior;
- the independent 60-second access-token tolerance and proof-freshness rules;
- the atomic `checkAndRecordJti` contract, including a warning against
  read-then-write and per-process replay stores;
- stable `DPoPVerificationError.code` handling;
- links to the package-local guides;
- a concise 0.2-to-0.3 breaking-change summary.

The README should help a consumer reach a safe first integration without
requiring a documentation site.

### Package-local guides

Renderer-neutral MDX files will live under `packages/dpop/docs/`:

- `verification.mdx` — complete verifier inputs, URL/method behavior, token
  binding, and Bearer versus DPoP paths;
- `replay-protection.mdx` — atomic ledger semantics, safe storage properties,
  ordering, retention, and deployment examples;
- `errors.mdx` — stable error-code handling and operational classification;
- `migration-0.3.mdx` — changes from 0.2.0 and a consumer checklist.

The pages may use Markdown plus MDX-compatible frontmatter, but will not import
components from a particular documentation framework. A future site can ingest
them without changing the package source of truth.

## Published package contract

`packages/dpop/package.json` will include both `README.md` and `docs` in
`files`. The release gate will pack the package and inspect the tarball rather
than assuming npm includes repository files.

The package-content check must prove:

1. `README.md` is present;
2. all four MDX guides are present;
3. the built entry point and declaration file are present;
4. current API terms such as `checkAndRecordJti` appear;
5. removed or unsafe 0.2 guidance is absent.

This check belongs in the Taskfile-based 0.3 release pipeline tracked by
`notme-0d34d1`.

## Scope boundaries

- No documentation-site framework or hosted deployment in this change.
- No duplicate API reference generated from TypeScript declarations.
- No consumer-repository documentation edits; their 0.3 upgrade beads own
  integration-specific examples.
- No Socket policy dependency: Socket adoption remains independently tracked.

## Verification

- Build the package with TypeScript.
- Run the verifier suite.
- Pack into a temporary directory.
- Inspect the archive file list and documentation content.
- Perform a built-ESM import smoke test from the packed artifact.

The final packed artifact, not the source tree alone, is the release truth.
