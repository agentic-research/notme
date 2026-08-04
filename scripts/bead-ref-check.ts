/**
 * bead-ref-check.ts — every `notme-xxxxxx` cited in source or docs must
 * resolve to a real bead.
 *
 * WHY THIS EXISTS: a bead ID in a comment reads as a citation. It says "the
 * reasoning for this lives somewhere durable, go look." When the ID resolves
 * to nothing, the comment is worse than if it had said nothing at all — a
 * reader either wastes time looking or, more likely, takes the claim on trust
 * *because* it looks sourced.
 *
 * Found by cloister, who hit the same class in their own repo and observed
 * that nothing checks it. They were right, and notme had one: `notme-9c2b41`
 * in packages/dpop/src/index.ts, attached to a comment documenting a
 * security-relevant gap — and `src/` ships in the npm tarball, so a published
 * package carried a pointer to a bead that never existed.
 *
 * This is the same shape as the two doc-vs-code drifts caught earlier in this
 * repo (a threat-model row claiming a mitigation the code did not implement, a
 * README describing behaviour that was never added). The common factor is a
 * claim that looks authoritative and that nothing executes. Rails beat
 * re-reading, because re-reading only works when someone happens to re-read.
 *
 * SOURCE OF TRUTH: `.beads/beads.jsonl`, the committed export. Deliberately
 * NOT the `bd` CLI — this must run identically for anyone with a checkout,
 * with no tool to install and no divergence between a developer's machine and
 * CI. A check that only some people can run is not a rail.
 *
 * WARNS rather than FAILS, and that is a real limitation stated rather than
 * hidden. The export can lag the store, so a miss means EITHER a bad citation
 * OR a stale export and this cannot tell which. Failing on an ambiguous signal
 * teaches people to ignore the check, which costs more than the rot it catches.
 * It becomes a hard gate the moment the export is reliably current — that is a
 * one-line change here and a process fix elsewhere.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

const SEARCH_DIRS = ["worker", "docs", "scripts", "packages", "action", ".github"];
const EXTS = [".ts", ".tsx", ".md", ".yml", ".yaml"];
const SKIP_DIRS = new Set(["node_modules", "dist", "coverage", ".git", "_agent_log"]);

/** `notme-` followed by exactly six lowercase hex characters. */
const BEAD_RE = /\bnotme-[0-9a-f]{6}\b/g;

interface Citation {
  id: string;
  file: string;
  line: number;
}

function walk(dir: string, out: string[]): void {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) walk(full, out);
    else if (EXTS.some((e) => entry.endsWith(e))) out.push(full);
  }
}

function collectCitations(): Citation[] {
  const files: string[] = [];
  for (const d of SEARCH_DIRS) walk(join(ROOT, d), files);

  const cites: Citation[] = [];
  for (const file of files) {
    // The bead store itself is full of IDs by definition; checking it would
    // be circular.
    if (file.includes("/.beads/")) continue;
    // And this file, which names a historical dangling ID while explaining
    // what it is for — narrative about a bad citation is not a bad citation.
    if (file.endsWith("scripts/bead-ref-check.ts")) continue;
    const lines = readFileSync(file, "utf8").split("\n");
    lines.forEach((text, i) => {
      for (const m of text.matchAll(BEAD_RE)) {
        cites.push({ id: m[0], file: relative(ROOT, file), line: i + 1 });
      }
    });
  }
  return cites;
}

/**
 * The committed export — the only source available to every checkout without
 * installing anything.
 */
function exportedBeadIds(): Set<string> {
  try {
    const raw = readFileSync(join(ROOT, ".beads", "beads.jsonl"), "utf8");
    const ids = new Set<string>();
    for (const line of raw.split("\n")) {
      if (!line.trim()) continue;
      try {
        const id = JSON.parse(line).id;
        if (id) ids.add(id);
      } catch {
        /* skip malformed line */
      }
    }
    return ids;
  } catch {
    return new Set();
  }
}

function main(): void {
  const cites = collectCitations();
  {
    const exported = exportedBeadIds();
    const suspect = cites.filter((c) => !exported.has(c.id));
    const unique = new Set(cites.map((c) => c.id));
    if (suspect.length === 0) {
      console.log(
        `\x1b[32mPASS\x1b[0m ${unique.size} bead citations resolve against the committed export.`,
      );
      return;
    }
    console.log(
      `\x1b[33mWARN\x1b[0m ${suspect.length} bead citation(s) absent from .beads/beads.jsonl.`,
    );
    for (const c of new Map(suspect.map((c) => [c.id, c])).values()) {
      console.log(`  ${c.file}:${c.line} → ${c.id}`);
    }
    console.log(
      "  Either the citation is wrong or the export is stale. Fix the ID, or\n" +
        "  delete the pointer and keep the substance — do not substitute a\n" +
        "  plausible-looking ID, which is the same rot with better camouflage.",
    );
  }
}

main();
