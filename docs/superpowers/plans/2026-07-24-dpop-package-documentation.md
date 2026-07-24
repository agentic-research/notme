# DPoP Package Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a useful npm landing README and renderer-neutral package-local MDX guides, with an automated check proving the documentation and built SDK are present in the packed artifact.

**Architecture:** `packages/dpop/README.md` is the concise npm entry point. Four focused files under `packages/dpop/docs/` hold deeper material without depending on a site framework. A Node standard-library smoke script packs the real package, inspects and extracts the tarball, validates documentation terminology, and imports the built ESM entry point.

**Tech Stack:** Markdown, MDX-compatible Markdown with YAML frontmatter, Node.js standard library, pnpm pack, system tar, TypeScript.

## Global Constraints

- Keep the package at zero runtime dependencies.
- Keep MDX renderer-neutral: no framework component imports.
- Describe the 0.3 API: required `audience` and `ath`, `checkAndRecordJti`, normalized `htu`, case-sensitive methods, stable error codes, 60-second token tolerance, and an independent ±60-second proof window.
- Do not add a hosted documentation framework.
- Treat the packed npm tarball as the release truth.

---

### Task 1: Define the packed-artifact documentation contract

**Files:**
- Create: `packages/dpop/scripts/check-package.mjs`
- Modify: `packages/dpop/package.json`

**Interfaces:**
- Consumes: `pnpm pack` output from `packages/dpop`.
- Produces: package script `test:package` that exits zero only when the packed artifact contains the required docs/build and current API language.

- [ ] **Step 1: Write the failing package smoke check**

Create `packages/dpop/scripts/check-package.mjs` using only Node built-ins. It must:

```js
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const packageDir = dirname(dirname(fileURLToPath(import.meta.url)));
const destination = mkdtempSync(join(tmpdir(), "notme-dpop-pack-"));

try {
  const packedName = execFileSync(
    "pnpm",
    ["pack", "--pack-destination", destination],
    { cwd: packageDir, encoding: "utf8" },
  ).trim().split("\n").at(-1);
  const archive = join(destination, packedName);
  const listing = execFileSync("tar", ["-tzf", archive], {
    encoding: "utf8",
  });
  const required = [
    "package/README.md",
    "package/docs/verification.mdx",
    "package/docs/replay-protection.mdx",
    "package/docs/errors.mdx",
    "package/docs/migration-0.3.mdx",
    "package/dist/index.js",
    "package/dist/index.d.ts",
  ];
  for (const path of required) {
    if (!listing.split("\n").includes(path)) {
      throw new Error(`packed package missing ${path}`);
    }
  }

  execFileSync("tar", ["-xzf", archive, "-C", destination]);
  const readme = readFileSync(
    join(destination, "package", "README.md"),
    "utf8",
  );
  for (const term of [
    "checkAndRecordJti",
    "DPoPVerificationError",
    "migration-0.3.mdx",
  ]) {
    if (!readme.includes(term)) {
      throw new Error(`packed README missing current API term: ${term}`);
    }
  }
  for (const stale of [
    "seenJti:",
    "Pass []",
    "clockTolerance defaults to 0",
  ]) {
    if (readme.includes(stale)) {
      throw new Error(`packed README contains stale 0.2 guidance: ${stale}`);
    }
  }

  const sdk = await import(
    pathToFileURL(join(destination, "package", "dist", "index.js")).href
  );
  for (const name of [
    "verifyDPoPToken",
    "verifyAccessToken",
    "DPoPVerificationError",
  ]) {
    if (typeof sdk[name] !== "function") {
      throw new Error(`packed ESM entry point missing ${name}`);
    }
  }
} finally {
  rmSync(destination, { recursive: true, force: true });
}
```

Add the test entry point to `packages/dpop/package.json`:

```json
"test:package": "node ./scripts/check-package.mjs"
```

- [ ] **Step 2: Run the smoke check to verify it fails**

Run:

```bash
pnpm --filter @agentic-research/dpop test:package
```

Expected: FAIL with `packed package missing package/docs/verification.mdx`.

- [ ] **Step 3: Commit the red contract**

```bash
git add packages/dpop/scripts/check-package.mjs packages/dpop/package.json
git commit -m "[notme-1c93bc] test(dpop): define package documentation contract"
```

### Task 2: Build the npm README and package-local MDX guides

**Files:**
- Modify: `packages/dpop/README.md`
- Modify: `packages/dpop/package.json`
- Create: `packages/dpop/docs/verification.mdx`
- Create: `packages/dpop/docs/replay-protection.mdx`
- Create: `packages/dpop/docs/errors.mdx`
- Create: `packages/dpop/docs/migration-0.3.mdx`

**Interfaces:**
- Consumes: current exports from `packages/dpop/src/index.ts`.
- Produces: npm-rendered quick start plus four framework-neutral MDX guides included by the package `files` whitelist.

- [ ] **Step 1: Expand the npm landing README**

Organize `README.md` in this order:

1. package purpose and zero-dependency/runtime statement;
2. install commands for npm and pnpm;
3. safe `verifyDPoPToken` quick start;
4. an atomic replay-ledger contract warning;
5. stable error handling:

```ts
try {
  const claims = await verifyDPoPToken(options);
} catch (error) {
  if (error instanceof DPoPVerificationError) {
    console.error(error.code, error.message);
  }
  throw error;
}
```

6. `verifyAccessToken` guidance for unbound redirect tokens only;
7. links to all four `docs/*.mdx` guides;
8. a short 0.3 breaking-change list.

The quick start must pass the full `request.url`, preserve `request.method`
case, require `audience`, and use `checkAndRecordJti`.

- [ ] **Step 2: Add the focused MDX guides**

Every guide starts with framework-neutral frontmatter:

```mdx
---
title: Verification
description: Verify notme access tokens and DPoP proofs safely.
---
```

Required contents:

- `verification.mdx`: full option behavior, exact-token `ath`, URL
  normalization, method case, token/proof clock windows, Bearer downgrade
  prevention, and verified claim shape.
- `replay-protection.mdx`: atomic check-and-record semantics; invalid proofs
  never consume; SQL uniqueness example; durable/shared storage requirement;
  retention of at least the proof-validity window; warning against KV
  read-then-write and per-isolate sets.
- `errors.mdx`: `DPoPVerificationError`, grouped `VerifyErrorCode` families,
  HTTP/operational mapping guidance, and warning not to match message text.
- `migration-0.3.mdx`: rename `seenJti` to `checkAndRecordJti`; mandatory
  `ath`; mandatory non-empty audience; default token tolerance 60 with explicit
  zero available; normalized `htu`; case-sensitive `htm`; strict alg/key and
  public-JWK checks; stable errors; fixture/consumer checklist.

- [ ] **Step 3: Include MDX in the npm whitelist**

Change `packages/dpop/package.json`:

```json
"files": [
  "dist",
  "src",
  "README.md",
  "docs"
]
```

- [ ] **Step 4: Run the package smoke check to verify it passes**

Run:

```bash
pnpm --filter @agentic-research/dpop test:package
```

Expected: PASS with no output after the package build/pack logs.

- [ ] **Step 5: Run package and repository verification**

Run:

```bash
pnpm --dir worker exec vitest run ../packages/dpop/__tests__/dpop-verifier.test.ts
pnpm --filter @agentic-research/dpop build
task worker:check
git diff --check
```

Expected: 65 package tests pass, TypeScript build passes, all worker and
real-Durable-Object tests pass, and the diff check is clean.

- [ ] **Step 6: Commit the documentation implementation**

```bash
git add packages/dpop/README.md packages/dpop/package.json packages/dpop/docs
git commit -m "[notme-1c93bc] docs(dpop): ship npm and MDX usage guides"
```

### Task 3: Reconcile the release contract

**Files:**
- Modify: `.beads/beads.jsonl`

**Interfaces:**
- Consumes: green package smoke and repository verification results.
- Produces: release bead `notme-0d34d1` explicitly runs `test:package` and
  records the documentation artifact as a release requirement.

- [ ] **Step 1: Comment verification evidence on both beads**

Add the exact package archive file list and test results to
`notme-1c93bc`. Add a release note to `notme-0d34d1` that
`pnpm --filter @agentic-research/dpop test:package` is a mandatory prepublish
gate.

- [ ] **Step 2: Close the documentation bead**

Close `notme-1c93bc` only after both implementation commits and all checks pass.

- [ ] **Step 3: Export and commit the tracked bead projection**

```bash
rsry bead export --jsonl --status all -o .beads/beads.jsonl
git add .beads/beads.jsonl
git commit -m "[notme-1c93bc] chore(beads): close package documentation"
```
