#!/usr/bin/env npx tsx
// check-sha-pins.ts — verify every external `uses:` in any workflow
// is pinned to a 40-char commit SHA.
//
// Companion to the doc-check.ts pattern: small TS scripts run from
// Taskfile against the local tree. No external GHA action dependency.
//
// Why not regex? Because we already learned that regex-on-YAML lies
// silently (PR #13 commit history: `\s` GNU-extension portability bug
// → false-positive "all pass" was the *exact* silent-failure mode the
// check existed to prevent). YAML parsing via the `yaml` npm package
// is the correct primitive; the AST walks the structure honestly.
//
// Trust surface: the `yaml` npm package (universally vetted, transitive
// dep of many things in this tree) + ~50 LOC of our own logic, audited
// here.
//
// Usage:
//   npx tsx scripts/check-sha-pins.ts [path-to-workflows-dir]
//   task pin:check
//
// Exit codes:
//   0 — all external uses: lines are SHA-pinned
//   1 — one or more violations found (printed with file:line)
//   2 — malformed input (workflow file unreadable, YAML parse error)

import { readFileSync, readdirSync, statSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { parse } from "yaml";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const SHA_RE = /^[a-f0-9]{40}$/;

interface Violation {
  file: string;
  uses: string;
  context: string; // job name or "job-level uses"
}

function isLocalRef(uses: string): boolean {
  // Local references: `./.github/workflows/...` or `./action-path`.
  // Don't need SHA-pinning — they resolve within the same commit.
  return uses.startsWith("./");
}

function isSHAPinned(uses: string): boolean {
  const at = uses.lastIndexOf("@");
  if (at === -1) return false;
  const ref = uses.slice(at + 1);
  return SHA_RE.test(ref);
}

function checkWorkflow(file: string): Violation[] {
  const violations: Violation[] = [];
  let doc: unknown;
  try {
    doc = parse(readFileSync(file, "utf8"));
  } catch (err) {
    console.error(`error: failed to parse ${file}: ${(err as Error).message}`);
    process.exit(2);
  }
  if (!doc || typeof doc !== "object") return violations;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const jobs = (doc as any).jobs ?? {};
  for (const [jobName, job] of Object.entries<unknown>(jobs)) {
    if (!job || typeof job !== "object") continue;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const j = job as any;

    // Reusable workflow at job level: `jobs.<name>.uses`
    if (typeof j.uses === "string" && !isLocalRef(j.uses) && !isSHAPinned(j.uses)) {
      violations.push({ file, uses: j.uses, context: `jobs.${jobName}.uses (reusable workflow)` });
    }

    // Step-level uses: `jobs.<name>.steps[].uses`
    const steps = Array.isArray(j.steps) ? j.steps : [];
    for (const [i, step] of steps.entries()) {
      if (!step || typeof step !== "object") continue;
      const uses = (step as { uses?: string }).uses;
      if (typeof uses !== "string") continue;
      if (isLocalRef(uses)) continue;
      if (!isSHAPinned(uses)) {
        violations.push({ file, uses, context: `jobs.${jobName}.steps[${i}].uses` });
      }
    }
  }
  return violations;
}

function findWorkflowFiles(dir: string): string[] {
  const out: string[] = [];
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return out;
  }
  for (const name of entries) {
    const full = join(dir, name);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isFile() && (name.endsWith(".yml") || name.endsWith(".yaml"))) {
      out.push(full);
    }
  }
  return out;
}

const workflowsDir = process.argv[2] ?? join(ROOT, ".github", "workflows");
const files = findWorkflowFiles(workflowsDir);
if (files.length === 0) {
  console.error(`error: no workflow files found in ${workflowsDir}`);
  process.exit(2);
}

const allViolations: Violation[] = [];
for (const file of files) {
  allViolations.push(...checkWorkflow(file));
}

if (allViolations.length === 0) {
  console.log(`pin:check — all ${files.length} workflow file(s) clean.`);
  process.exit(0);
}

console.error(`pin:check — ${allViolations.length} non-SHA-pinned uses: line(s):\n`);
for (const v of allViolations) {
  console.error(`  ${v.file}`);
  console.error(`    ${v.context}`);
  console.error(`    uses: ${v.uses}`);
  console.error("");
}
console.error("Every external action ref MUST be pinned to a 40-char commit SHA.");
console.error("Branch refs and tag refs are forbidden (Trivy/Aqua precedent).");
console.error("Resolve a tag to its commit SHA (handles annotated + lightweight):");
console.error("  gh api repos/<org>/<repo>/commits/<tag> --jq '.sha'");
process.exit(1);
