// check-image-versions.ts — assert server.json agrees with the tag the
// publish job is actually about to push.
//
// Invoke via `task version:check VERSION=0.1.0` (or
// `pnpm exec tsx scripts/check-image-versions.ts 0.1.0`). No shebang: run via
// the explicit interpreter so the lockfile-pinned `tsx` + `yaml` are used.
//
// THE RULE (cloister ADR-0041 §2):
//
//   `version` MUST equal the tag the publish job actually pushes — because
//   `<identifier>:<version>` has to resolve at the registry.
//
// Note what that is NOT. It is not "version matches the git tag". Those are
// different strings whenever the git tag is `v`-prefixed. notme strips the
// `v` (a `v0.1.0` tag pushes `:0.1.0`), so checking against the git tag would
// pass while the registry 404s. This script therefore takes VERSION — the
// SAME variable `image:publish` uses to tag — rather than reading git itself.
// `image:publish` calls this before pushing, so publishing a version
// server.json does not declare is structurally impossible, not merely
// discouraged.
//
// WHY THIS CHECKS BOTH HALVES: ley-line-open v0.11.2 shipped through a guard
// written to prevent exactly this class. That guard rejected a *tagged
// identifier* but permitted an *absent version* — so an identifier with no
// version at all went out and derived to nothing. Half a rule enforced is a
// guard that reports success on the failure it exists to catch. Every
// assertion below is therefore paired: presence AND correctness.
//
// WHY PER-ENTRY: cloister declares notme-identity and notme-proxy as two
// separate hypervisor-tier bundles and ADR-0038 derives each image
// separately, so "correct notme, stale notme-proxy" is a reachable state. A
// single combined assertion would pass straight through it. Each entry is
// resolved and judged on its own, and every violation is reported — the
// script does not stop at the first.
//
// Exit codes:
//   0 — server.json and the in-scope melange recipes all agree with VERSION
//   1 — one or more violations (each printed with file + what was expected)
//   2 — malformed input (missing VERSION, unreadable/unparseable file)

import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { parse } from "yaml";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");

// The images this repo publishes. Listed here rather than derived from
// server.json so that DELETING an entry is a failure instead of a silent
// pass — the empty-packages[] hole ADR-0041 §2 calls out in mache's local
// server.json, where an absent array falls through to ADR-0038 rule 3 and
// yields no image at all.
const EXPECTED_IDENTIFIERS = [
  "ghcr.io/agentic-research/notme",
  "ghcr.io/agentic-research/notme-proxy",
];

// Melange recipes whose package IS a notme artifact, so their version tracks
// the release tag (ADR-0041 producer contract item 2 — "kill the
// melange.yaml 0.1.0 drift; the version is the tag").
//
// melange-workerd.yaml is deliberately NOT here. It packages a vendored
// upstream binary and its version (1.20260402.1) is workerd's, not notme's.
// Forcing it to track our tag would make it lie about what it contains.
const VERSIONED_RECIPES = [
  "packages/melange-notme-app.yaml",
  "packages/melange-notme-proxy.yaml",
];

/**
 * Render a pushed OCI tag as the apk version a melange recipe must declare.
 *
 * These are NOT the same string for prereleases. apk reserves `-r<N>` for the
 * package release suffix, so `0.1.0-rc1` is not a legal apk version — melange
 * rejects it outright ("invalid version 0.1.0-rc1, could not parse"), while
 * `0.1.0_rc1` builds fine and yields `notme-app-0.1.0_rc1-r0.apk`. Both
 * verified against melange 0.48.2.
 *
 * So ADR-0041's producer-contract item 2 is that the recipe version TRACKS the
 * tag, not that it is byte-identical to it. `packages[].version` still has to
 * equal the pushed tag exactly — that one is a registry lookup and is checked
 * without normalisation.
 *
 * apk's suffix grammar (`_alpha`/`_beta`/`_pre`/`_rc`/`_p`, optional digits)
 * is narrower than semver's. A tag like `0.1.0-beta.2` maps to `0.1.0_beta.2`,
 * which melange rejects at build time with a clear parse error. That is the
 * right place for it to fail; this check does not reimplement apk's grammar.
 */
function toApkVersion(tag: string): string {
  return tag.replace(/-/g, "_");
}

interface Violation {
  file: string;
  detail: string;
}

const violations: Violation[] = [];

function fail(file: string, detail: string): void {
  violations.push({ file, detail });
}

function bail(message: string): never {
  console.error(`check-image-versions: ${message}`);
  process.exit(2);
}

function readOrBail(relPath: string): string {
  try {
    return readFileSync(join(ROOT, relPath), "utf8");
  } catch (err) {
    bail(`cannot read ${relPath}: ${(err as Error).message}`);
  }
}

/**
 * ADR-0041 §2: identifier is "the registry path with no tag and no digest —
 * the address only". Baking the tag in (llo's `…/ley-line-open:0.5.6`)
 * conflates the mutable handle with the address and breaks ADR-0038's derive
 * rule 2, which builds `<identifier>:<version>`.
 *
 * A registry host may legitimately carry a port (`localhost:5000/foo`), so
 * only the final path segment is checked for a `:` tag.
 */
function identifierIsBare(identifier: string): boolean {
  if (identifier.includes("@")) return false; // digest
  const lastSegment = identifier.split("/").pop() ?? "";
  return !lastSegment.includes(":");
}

/**
 * Strip any tag or digest, yielding the address alone.
 *
 * Used to LOCATE an entry before judging it, so a regressed
 * `…/notme:0.1.0` is still recognised as the notme entry and reported as
 * malformed, rather than reported as missing while the real problem goes
 * unnamed. Only the final path segment is stripped, so a registry port
 * (`localhost:5000/foo`) survives.
 */
function bareIdentifier(raw: string): string {
  const segments = raw.split("@")[0].split("/");
  const last = segments.pop() ?? "";
  segments.push(last.split(":")[0]);
  return segments.join("/");
}

function checkServerJson(version: string): void {
  const raw = readOrBail("server.json");
  let doc: { packages?: unknown };
  try {
    doc = JSON.parse(raw);
  } catch (err) {
    bail(`server.json is not valid JSON: ${(err as Error).message}`);
  }

  const packages = doc.packages;
  if (!Array.isArray(packages)) {
    fail("server.json", "`packages` is missing or not an array — nothing to derive an image from");
    return;
  }

  for (const identifier of EXPECTED_IDENTIFIERS) {
    // Match on the tag-stripped address, EXACTLY. Exact equality is what
    // keeps `ghcr.io/…/notme-proxy` from answering a lookup for
    // `ghcr.io/…/notme` — a prefix match here would find two entries for
    // notme and report a spurious ambiguity while notme-proxy went unchecked.
    const entries = packages.filter(
      (p): p is Record<string, unknown> =>
        typeof p === "object" &&
        p !== null &&
        bareIdentifier(String((p as Record<string, unknown>).identifier ?? "")) === identifier,
    );

    if (entries.length === 0) {
      fail(
        "server.json",
        `no packages[] entry for ${identifier} — cloister derives no image for this bundle`,
      );
      continue;
    }
    if (entries.length > 1) {
      fail(
        "server.json",
        `${entries.length} packages[] entries for ${identifier} — ambiguous, which one publishes?`,
      );
      continue;
    }

    const entry = entries[0];
    const where = `packages[] entry for ${identifier}`;

    if (entry.registryType !== "oci") {
      fail(
        "server.json",
        `${where}: registryType is ${JSON.stringify(entry.registryType)}, expected "oci"`,
      );
    }

    const rawIdentifier = String(entry.identifier ?? "");
    if (!identifierIsBare(rawIdentifier)) {
      fail(
        "server.json",
        `${where}: identifier ${JSON.stringify(rawIdentifier)} carries a tag or digest. ` +
          `ADR-0041 §2 — identifier is the address only; the tag belongs in \`version\`.`,
      );
    }

    // The ley-line-open v0.11.2 half: an ABSENT version is as fatal as a
    // wrong one. `<identifier>:<version>` with an empty version derives to
    // nothing, and nothing is not a pullable image.
    const entryVersion = entry.version;
    if (entryVersion === undefined || entryVersion === null || entryVersion === "") {
      fail(
        "server.json",
        `${where}: no \`version\`. ADR-0041 §2 — <identifier>:<version> derives to nothing ` +
          `without it (this is exactly what shipped in ley-line-open v0.11.2).`,
      );
      continue;
    }

    if (typeof entryVersion !== "string") {
      fail("server.json", `${where}: \`version\` is ${typeof entryVersion}, expected a string`);
      continue;
    }

    if (entryVersion !== version) {
      fail(
        "server.json",
        `${where}: version is ${JSON.stringify(entryVersion)} but the publish job pushes ` +
          `${JSON.stringify(version)}. ${rawIdentifier}:${entryVersion} would not resolve.`,
      );
    }
  }
}

function checkRecipes(version: string): void {
  for (const relPath of VERSIONED_RECIPES) {
    const raw = readOrBail(relPath);
    let doc: { package?: { version?: unknown; name?: unknown } };
    try {
      doc = parse(raw);
    } catch (err) {
      bail(`${relPath} is not valid YAML: ${(err as Error).message}`);
    }

    const recipeVersion = doc?.package?.version;
    if (recipeVersion === undefined || recipeVersion === null || recipeVersion === "") {
      fail(relPath, "`package.version` is missing");
      continue;
    }

    // YAML parses an unquoted 0.1.0 as a string, but 0.1 would become a
    // number — compare on the rendered form so a recipe that dropped a
    // patch segment fails loudly instead of throwing a type error.
    const expected = toApkVersion(version);
    if (String(recipeVersion) !== expected) {
      const note =
        expected === version
          ? ""
          : ` (apk spelling of the tag ${JSON.stringify(version)} — apk reserves \`-r\` for the ` +
            `package release, so a \`-\` prerelease must be written \`_\`)`;
      fail(
        relPath,
        `package.version is ${JSON.stringify(String(recipeVersion))} but the release expects ` +
          `${JSON.stringify(expected)}${note}. ADR-0041 producer contract item 2 — the recipe ` +
          `version tracks the tag.`,
      );
    }
  }
}

function main(): void {
  const version = (process.argv[2] ?? process.env.VERSION ?? "").trim();

  if (version === "") {
    bail(
      "no VERSION given. Pass the tag the publish job will push, e.g.\n" +
        "  task version:check VERSION=0.1.0\n" +
        "  pnpm exec tsx scripts/check-image-versions.ts 0.1.0",
    );
  }

  // A `v`-prefixed value here means the caller passed the raw git tag rather
  // than the pushed tag. For notme those differ, and silently accepting it
  // would reintroduce the precise confusion ADR-0041's 2026-07-28 correction
  // exists to remove.
  if (/^v\d/.test(version)) {
    bail(
      `VERSION is ${JSON.stringify(version)}, which looks like a raw git tag.\n` +
        `notme strips the \`v\` before pushing — pass the tag apko actually pushes ` +
        `(${JSON.stringify(version.slice(1))}), not the git ref.`,
    );
  }

  checkServerJson(version);
  checkRecipes(version);

  if (violations.length > 0) {
    console.error(`\nFAIL — ${violations.length} violation(s) against version ${version}:\n`);
    for (const v of violations) {
      console.error(`  ${v.file}`);
      console.error(`    ${v.detail}\n`);
    }
    process.exit(1);
  }

  console.log(
    `All image versions agree with the pushed tag ${version} ` +
      `(${EXPECTED_IDENTIFIERS.length} packages, ${VERSIONED_RECIPES.length} recipes).`,
  );
}

main();
