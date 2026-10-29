/**
 * threat-model-index.test.ts — THREAT_MODEL.md says "each test name maps to a
 * row in the tables above". This makes that an assertion instead of a claim
 * (notme-8eed12).
 *
 * It was not true. Of 73 identifiers, 45 appeared nowhere in the repo except
 * THREAT_MODEL.md itself — 17 of them for a `vault/` subsystem retired to
 * cloister in ADR-012, and the rest split between label drift (the defence
 * IS tested, under another name) and rows that asserted a verified defence
 * where none existed. A reader cannot tell those apart from the document, so
 * every identifier read as evidence and some of it was nothing.
 *
 * Fixing the 45 instances without this test would leave the next one to be
 * found by another audit. The document's contract is mechanical, so it is
 * checked mechanically.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = fileURLToPath(new URL("../../", import.meta.url));
const doc = readFileSync(join(root, "THREAT_MODEL.md"), "utf8");

/**
 * Identifiers are backticked dotted tokens in a table's final column.
 * File paths are excluded by extension — `worker.ts` is a dotted backticked
 * token too, and counting it would make this fail on prose.
 */
const NOT_AN_ID = /\.(ts|tsx|js|mjs|md|json|toml|yml|yaml|pem|bot|html|capnp|go|sh)$/;
const identifiers = [
  ...new Set(
    doc
      .split("\n")
      // Table rows only, and only their FINAL cell — the test column. Reading
      // every backtick in the document picks up prose like
      // `window.location.href` and turns this check into noise.
      .filter((line) => line.trimStart().startsWith("|") && line.trimEnd().endsWith("|"))
      .map((line) => line.trim().slice(1, -1).split("|").at(-1) ?? "")
      .flatMap((cell) => [...cell.matchAll(/`([a-z0-9][a-z0-9.\-]*\.[a-z0-9][a-z0-9.\-]*)`/g)])
      .map((m) => m[1]!)
      .filter((id) => !NOT_AN_ID.test(id)),
  ),
].sort();

/** Every test source in the repo, concatenated once. */
function testSources(dir: string, acc: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry === "dist" || entry === ".wrangler") continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) testSources(full, acc);
    else if (/\.(test|spec)\.ts$/.test(entry)) acc.push(readFileSync(full, "utf8"));
  }
  return acc;
}
// worker/src AND packages/ — THREAT_MODEL's index lists
// packages/dpop/__tests__/dpop-verifier.test.ts, which is a real file in a
// sibling workspace, not a ghost.
const repoRoot = join(root, "..");
const suite = [
  ...testSources(join(root, "src")),
  ...testSources(join(repoRoot, "packages")),
].join("\n");

describe("threat-model.index", () => {
  it("finds the identifiers at all", () => {
    // Guards the extractor: a table reformat that broke the regex would make
    // every assertion below vacuously true over an empty list.
    expect(identifiers.length).toBeGreaterThan(40);
    expect(identifiers).toContain("cert-gha.jti.replay");
    expect(identifiers).toContain("routing.blocked-paths");
  });

  it("every identifier THREAT_MODEL names exists as a test name", () => {
    // The document's own sentence, executable. A row may legitimately have
    // no test — say so in the column ("n/a — ..."), do not name one.
    const missing = identifiers.filter((id) => !suite.includes(id));
    expect(
      missing,
      `THREAT_MODEL.md names ${missing.length} test identifier(s) that no test ` +
        `declares. Either write the test, rename an existing one to carry the ` +
        `identifier, or replace the column with "n/a — <reason>":\n  ` +
        missing.join("\n  "),
    ).toEqual([]);
  });

  it("names no test file the repo does not contain", () => {
    // The test-categories block lists files. `vault/src/__tests__/` was
    // listed with five of them for a subsystem deleted in ADR-012.
    const listed = [...doc.matchAll(/^\s{2}([a-z0-9][\w.-]*\.test\.ts)/gm)].map(
      (m) => m[1]!,
    );
    expect(listed.length).toBeGreaterThan(5);
    const present = new Set<string>();
    const walk = (dir: string) => {
      for (const entry of readdirSync(dir)) {
        if (entry === "node_modules" || entry === "dist" || entry === ".wrangler") continue;
        const full = join(dir, entry);
        if (statSync(full).isDirectory()) walk(full);
        else if (entry.endsWith(".test.ts")) present.add(entry);
      }
    };
    walk(join(root, "src"));
    walk(join(repoRoot, "packages"));
    const ghosts = listed.filter((f) => !present.has(f));
    expect(ghosts, `listed but absent: ${ghosts.join(", ")}`).toEqual([]);
  });

  it("does not describe the retired vault as a live surface", () => {
    // ADR-012 deleted vault/ — cloister owns it. §9 carried 17 threat rows
    // and 5 test files for it.
    expect(doc).not.toMatch(/`vault-(adversarial|security|encryption|worker)\./);
    expect(doc).toMatch(/RETIRED, not a notme surface/);
  });
});
