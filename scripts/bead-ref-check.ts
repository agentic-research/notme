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
 * TWO MODES, deliberately:
 *
 *   - `bd` available → checks the LIVE store and FAILS on a dangling ID. The
 *     signal is unambiguous, so the gate is real.
 *   - `bd` absent → falls back to `.beads/beads.jsonl` and WARNS. That export
 *     is demonstrably incomplete, so a miss there means either a bad citation
 *     or a stale export and cannot distinguish them. Failing CI on an
 *     ambiguous signal trains people to ignore the check, which costs more
 *     than the rot it catches.
 *
 * CI currently has no `bd`, so today this is advisory there and a real gate
 * locally. That is a known limit, not an oversight — say so rather than
 * letting a green check imply a guarantee it is not making.
 */

import { execFileSync } from "node:child_process";
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
 * Fallback: the committed export. NOT authoritative — it is demonstrably
 * incomplete (153 ids while beads that provably exist in the store are absent
 * from it), so a miss here means EITHER a bad citation OR a stale export and
 * we cannot tell which. Hence warn, never fail, on this path.
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

function knownBeadIds(): Set<string> | null {
  try {
    // `bd list` against the live Dolt store. NOT .beads/beads.jsonl — that is
    // an export and lags, which would flag freshly-filed beads as dangling.
    const out = execFileSync("bd", ["list", "--all", "--json"], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 30_000,
    });
    const parsed = JSON.parse(out);
    const rows = Array.isArray(parsed) ? parsed : (parsed.issues ?? parsed.beads ?? []);
    const ids = new Set<string>(rows.map((r: any) => r.id).filter(Boolean));
    return ids.size > 0 ? ids : null;
  } catch {
    return null;
  }
}

function main(): void {
  const cites = collectCitations();
  const known = knownBeadIds();

  if (!known) {
    // No `bd` — fall back to the committed export, and WARN rather than fail.
    //
    // This split is the whole design. The export is incomplete, so a miss
    // against it is ambiguous: bad citation, or stale export. Failing CI on an
    // ambiguous signal trains people to ignore the check, which costs more
    // than the rot it catches. Where the store IS available the signal is
    // unambiguous and we fail properly.
    const exported = exportedBeadIds();
    const suspect = cites.filter((c) => !exported.has(c.id));
    const unique = new Set(cites.map((c) => c.id));
    if (suspect.length === 0) {
      console.log(
        `\x1b[32mPASS\x1b[0m ${unique.size} bead citations resolve against the committed export (\`bd\` unavailable — advisory).`,
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
      "  Either the citation is wrong or the export is stale — the export is\n" +
        "  known incomplete, so this cannot distinguish them. Install `bd` for a\n" +
        "  real check against the live store.",
    );
    return;
  }

  const dangling = cites.filter((c) => !known.has(c.id));
  const unique = new Set(cites.map((c) => c.id));

  if (dangling.length === 0) {
    console.log(
      `\x1b[32mPASS\x1b[0m ${unique.size} bead citations across ${cites.length} references all resolve.`,
    );
    return;
  }

  console.error(`\x1b[31mFAIL\x1b[0m ${dangling.length} dangling bead citation(s):\n`);
  for (const d of dangling) {
    console.error(`  ${d.file}:${d.line} → ${d.id} does not exist`);
  }
  console.error(
    "\nA bead ID in a comment reads as a citation. One that resolves to nothing\n" +
      "is worse than no citation: a reader takes the claim on trust BECAUSE it\n" +
      "looks sourced. Fix the ID, or delete the pointer and keep the substance —\n" +
      "do not substitute a plausible-looking ID.",
  );
  process.exit(1);
}

main();
