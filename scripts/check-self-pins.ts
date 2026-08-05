#!/usr/bin/env npx tsx
// check-self-pins.ts — a SHA pin on our OWN action must serve the code this
// repository actually has.
//
// check-sha-pins.ts proves every `uses:` is pinned to a 40-char SHA. That is
// the right rule for a THIRD-PARTY action, where the threat is someone moving
// a tag underneath us. It says nothing about whether the pin is CURRENT, and
// for a self-reference that is the only thing that matters: we control the
// repo, so the pin buys no security — it only decides which version of our own
// code runs.
//
// It drifted. gha-identity.yml pinned e57c9ad while `action/` had moved on
// through three merged PRs, and the pin's own comment claimed it was "the
// current shipping state" (notme-28959a). Nothing checked, so the claim
// outlived its truth. The concrete cost: a security rebuild of
// action/dist/index.js does not reach notme's own CI until someone remembers
// to bump this by hand.
//
// WHY THE SELF-PIN EXISTS AT ALL, so nobody "fixes" it by deleting it:
// gha-identity.yml is a REUSABLE workflow invoked by other repositories. A
// local `uses: ./action` would resolve against the CALLER's checkout, which
// has no action/ directory. The absolute SHA reference is required. The
// answer is not to unpin — it is to make drift loud.
//
// WHAT IS COMPARED, and why it is trees rather than commits: a commit that
// touches action/ alongside unrelated files would make a recency check fire
// with nothing to fix. The question is whether the pinned commit SERVES
// DIFFERENT CODE, which is exactly a tree comparison.
//
// COMPARED AGAINST THE DEFAULT BRANCH, not HEAD, and that is deliberate. A PR
// that changes action/ cannot pin to a commit that does not exist yet, so a
// self-pin necessarily lags by one merge. Checking against origin/main lets
// that PR pass and fires on the NEXT one — which is the moment the bump is
// both possible and required.
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { parse } from "yaml";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const WORKFLOWS = join(ROOT, ".github", "workflows");
const SELF = "agentic-research/notme";
const BASE = process.env.SELF_PIN_BASE ?? "origin/main";

function git(...args: string[]): string {
  return execFileSync("git", args, { cwd: ROOT, encoding: "utf8" }).trim();
}

/** Every `uses:` string in a workflow, wherever it appears. */
function usesIn(node: unknown, out: string[] = []): string[] {
  if (Array.isArray(node)) {
    for (const n of node) usesIn(n, out);
  } else if (node && typeof node === "object") {
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      if (k === "uses" && typeof v === "string") out.push(v);
      else usesIn(v, out);
    }
  }
  return out;
}

const failures: string[] = [];
let checked = 0;

for (const file of readdirSync(WORKFLOWS).filter((f) => /\.ya?ml$/.test(f))) {
  const doc = parse(readFileSync(join(WORKFLOWS, file), "utf8"));
  for (const ref of usesIn(doc)) {
    if (!ref.startsWith(`${SELF}/`)) continue; // third-party: not our problem here
    const [path, sha] = ref.slice(`${SELF}/`.length).split("@");
    if (!path || !sha || !/^[0-9a-f]{40}$/.test(sha)) continue; // check-sha-pins.ts owns that
    // `.github/workflows/x.yml@sha` self-references are the workflow itself;
    // only directory references (action/) serve code we can compare.
    if (path.startsWith(".github/")) continue;
    checked++;

    let pinned: string;
    try {
      pinned = git("rev-parse", `${sha}:${path}`);
    } catch {
      failures.push(
        `${file}: pinned commit ${sha.slice(0, 8)} is not available locally — ` +
          `the checkout needs full history (fetch-depth: 0) for this check.`,
      );
      continue;
    }
    const current = git("rev-parse", `${BASE}:${path}`);
    if (pinned === current) continue;

    const shouldBe = git("log", "-1", "--format=%H", BASE, "--", path);
    failures.push(
      `${file}: pins ${SELF}/${path}@${sha.slice(0, 8)}, which serves a DIFFERENT ` +
        `${path}/ than ${BASE}.\n` +
        `    pinned tree  ${pinned}\n` +
        `    ${BASE} tree ${current}\n` +
        `    Bump the pin to ${shouldBe} (newest ${BASE} commit touching ${path}/).\n` +
        `    A self-pin serving stale code means fixes to ${path}/ — including ` +
        `security rebuilds — never reach this workflow.`,
    );
  }
}

if (failures.length > 0) {
  console.error("self-pin check FAILED:\n");
  for (const f of failures) console.error(`  ✗ ${f}\n`);
  process.exit(1);
}
console.log(
  `self-pin check — ${checked} self-reference(s) serve the same code as ${BASE}.`,
);
