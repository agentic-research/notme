/**
 * fixture-manifest.ts — the integrity anchor for schema/fixtures/ (notme-1629fe).
 *
 * WHY THIS EXISTS: schema/fixtures/ holds the canonical-CBOR vectors that the
 * CABundle signing input is pinned to (ADR-010). Those bytes are what every
 * implementation signs and verifies, so a silent change to them is a
 * signature split-brain across the trust fabric, not a test failure. Before
 * this check, the only gate was "bundleCanonical(json) == expected.hex": the
 * vector restated the encoder's own output, so an edit to the encoder AND the
 * vector in one PR was green, and the .bin a Go/Rust consumer would naturally
 * read was never looked at by anything.
 *
 * WHAT IT CHECKS, before any test is allowed to use a fixture:
 *   - every file in schema/fixtures/ (other than README.md and the manifest
 *     itself) is listed in SHA256SUMS, and every listed file exists;
 *   - every listed file's SHA-256 matches the pinned digest;
 *   - every fixture has all three of .json / .expected.hex / .bin, and
 *     .bin == hex_decode(.expected.hex).
 *
 * WHAT IT DOES NOT DO: stop a PR that edits the encoder, the vector AND the
 * manifest together. Nothing in-repo can. It turns a silent two-file edit into
 * a three-file edit that names itself in the diff and needs a CODEOWNERS
 * review on schema/fixtures/. The provenance-independent half of the anchor
 * is the RFC 8949 reference encoder in
 * worker/src/__tests__/bundle-canonical.test.ts, which re-derives the vectors
 * without sharing code with revocation.ts.
 *
 * SHA256SUMS is in standard `sha256sum` format, so a consumer can verify a
 * vendored copy with stock tools: `shasum -a 256 -c SHA256SUMS`.
 *
 * Run: `pnpm exec tsx scripts/fixture-manifest.ts` (part of `task docs:check`).
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

export const FIXTURES_DIR = join(__dirname, "..", "schema", "fixtures");
export const MANIFEST = "SHA256SUMS";
const UNPINNED = new Set(["README.md", MANIFEST]);
const SUFFIXES = [".json", ".expected.hex", ".bin"] as const;

/** Every problem with the fixture dir, as one line each; empty means clean. */
export function checkFixtures(dir: string = FIXTURES_DIR): string[] {
  const problems: string[] = [];
  const manifestPath = join(dir, MANIFEST);
  if (!existsSync(manifestPath)) return [`${MANIFEST}: missing from ${dir}`];

  const pinned = new Map<string, string>();
  for (const [i, raw] of readFileSync(manifestPath, "utf-8").split("\n").entries()) {
    const line = raw.trim();
    if (line === "") continue;
    const m = /^([0-9a-f]{64}) [ *](\S+)$/.exec(line);
    if (!m) {
      problems.push(`${MANIFEST}:${i + 1}: not a "<sha256>  <file>" line: ${line}`);
      continue;
    }
    if (pinned.has(m[2])) problems.push(`${MANIFEST}:${i + 1}: ${m[2]} listed twice`);
    pinned.set(m[2], m[1]);
  }

  const present = readdirSync(dir).filter((f) => !UNPINNED.has(f));
  for (const f of present) {
    if (!pinned.has(f)) problems.push(`${f}: present but not pinned in ${MANIFEST}`);
  }
  for (const [f, want] of pinned) {
    const p = join(dir, f);
    if (!existsSync(p)) {
      problems.push(`${f}: pinned in ${MANIFEST} but missing`);
      continue;
    }
    const got = createHash("sha256").update(readFileSync(p)).digest("hex");
    if (got !== want) problems.push(`${f}: sha256 ${got} != pinned ${want}`);
  }

  const names = new Set<string>();
  for (const f of present) {
    const s = SUFFIXES.find((x) => f.endsWith(x));
    if (s) names.add(f.slice(0, -s.length));
    else problems.push(`${f}: not a fixture file (${SUFFIXES.join(" / ")})`);
  }
  for (const name of names) {
    const missing = SUFFIXES.filter((s) => !existsSync(join(dir, name + s)));
    if (missing.length) {
      problems.push(`${name}: missing ${missing.map((s) => name + s).join(", ")}`);
      continue;
    }
    const hex = readFileSync(join(dir, `${name}.expected.hex`), "utf-8").trim();
    const bin = readFileSync(join(dir, `${name}.bin`));
    if (!/^(?:[0-9a-f]{2})+$/.test(hex)) {
      problems.push(`${name}.expected.hex: not one line of lowercase hex`);
    } else if (!Buffer.from(hex, "hex").equals(bin)) {
      problems.push(`${name}.bin: bytes differ from hex_decode(${name}.expected.hex)`);
    }
  }
  return problems;
}

/** Throw unless the fixture dir matches its manifest. Call before using any fixture. */
export function assertFixtures(dir: string = FIXTURES_DIR): void {
  const problems = checkFixtures(dir);
  if (problems.length) {
    throw new Error(
      `schema/fixtures integrity check failed (notme-1629fe):\n  ${problems.join("\n  ")}\n` +
        `If the encoding change is intended, regenerate ${MANIFEST} ` +
        "(`cd schema/fixtures && shasum -a 256 *.json *.expected.hex *.bin > SHA256SUMS`) " +
        "and expect every consumer to re-vendor.",
    );
  }
}

if (require.main === module) {
  const problems = checkFixtures();
  if (problems.length) {
    console.error(`fixture-manifest: ${problems.length} problem(s):\n  ${problems.join("\n  ")}`);
    process.exit(1);
  }
  console.log("fixture-manifest: schema/fixtures matches SHA256SUMS; every .bin equals its .expected.hex.");
}
