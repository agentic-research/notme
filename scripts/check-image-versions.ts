// check-image-versions.ts — assert server.json agrees with the tag the
// publish job is actually about to push, and that it validates against the
// schema it declares.
//
// Invoke via `task version:check VERSION=0.1.0` (or
// `pnpm exec tsx scripts/check-image-versions.ts 0.1.0`). No shebang: run via
// the explicit interpreter so the lockfile-pinned `tsx`, `yaml` and `ajv` are
// used.
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
// WHERE THE ADDRESSES LIVE (notme-6e5330, ley-line-open-0135fa): in
// `_meta."io.modelcontextprotocol.registry/publisher-provided".artifacts`,
// NOT in `packages[]`. The registry schema puts `transport` in
// `Package.required`, so a producer that publishes images and serves no MCP
// cannot use `packages[]` without either a placeholder transport — a runtime
// lie, since cloister derives session behaviour from it — or a document that
// fails its own declared schema. notme shipped the latter for two days. The
// publisher-provided extension is the schema's own open slot
// (`additionalProperties: true`) and is what ley-line-open v0.13.0's
// `leyline-mcp-descriptor` renders for artifact-only producers.
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
//   0 — server.json is schema-valid and it plus the in-scope melange recipes
//       all agree with VERSION
//   1 — one or more violations (each printed with file + what was expected)
//   2 — malformed input (missing VERSION, unreadable/unparseable file)

import { readFileSync } from "fs";
import { createHash } from "crypto";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { parse } from "yaml";
import Ajv from "ajv";
import addFormats from "ajv-formats";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");

// The images this repo publishes. Listed here rather than derived from
// server.json so that DELETING an entry is a failure instead of a silent
// pass — the empty-array hole ADR-0041 §2 calls out in mache's local
// server.json, where an absent list falls through to ADR-0038 rule 3 and
// yields no image at all.
const EXPECTED_IDENTIFIERS = [
  "ghcr.io/agentic-research/notme",
  "ghcr.io/agentic-research/notme-proxy",
];

// The schema's sanctioned extension slot, and the key within it that carries
// OCI addresses for a producer that serves no MCP. Spelled out rather than
// inlined because it is a load-bearing reverse-DNS string that a typo would
// turn into a silently-empty lookup.
const PUBLISHER_PROVIDED = "io.modelcontextprotocol.registry/publisher-provided";

// Vendored copy of the schema `server.json`'s `$schema` key names. Vendored
// so this check runs offline and in CI without a network dependency, and so
// an upstream edit arrives as a reviewable diff rather than a validation
// result that changes under a file nobody touched.
const SCHEMA_PATH = "schema/mcp/server.schema.2025-12-11.json";
const SCHEMA_URL = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json";

// sha256 of the vendored file, verified 2026-07-30 as byte-identical to both
// SCHEMA_URL and ley-line-open's copy (the one its emitter validates against).
// Asserted so "we vendored it" cannot quietly become "we vendored something".
const SCHEMA_SHA256 = "3fba09590c99f61735d234822279f4223fab9e300c0a81e81c91ab62a4114de0";

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
 * tag, not that it is byte-identical to it. The artifact `version` still has to
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

function parseServerJson(): Record<string, unknown> {
  const raw = readOrBail("server.json");
  try {
    return JSON.parse(raw) as Record<string, unknown>;
  } catch (err) {
    bail(`server.json is not valid JSON: ${(err as Error).message}`);
  }
}

/**
 * Validate server.json against the schema its own `$schema` key names.
 *
 * This exists because the previous shape did NOT. From 2026-07-28 the file
 * declared the 2025-12-11 schema and shipped two `packages[]` entries with no
 * `transport`, which that schema lists in `Package.required` — a document
 * failing its own declared spec, with nothing in the repo to notice
 * (notme-6e5330, found from ley-line-open). A comment asserting conformance
 * is not conformance; this is the check that makes the `$schema` key mean
 * something.
 */
function checkSchemaConformance(doc: Record<string, unknown>): void {
  const schemaRaw = readOrBail(SCHEMA_PATH);

  const actualSha = createHash("sha256").update(schemaRaw).digest("hex");
  if (actualSha !== SCHEMA_SHA256) {
    fail(
      SCHEMA_PATH,
      `sha256 is ${actualSha}, expected ${SCHEMA_SHA256}. The vendored schema has ` +
        `changed. If that is intentional, re-fetch from ${SCHEMA_URL}, diff it, and ` +
        `update SCHEMA_SHA256 — do not just make the numbers agree.`,
    );
    return; // Validating against an unexpected schema proves nothing.
  }

  const declared = doc.$schema;
  if (declared !== SCHEMA_URL) {
    fail(
      "server.json",
      `$schema is ${JSON.stringify(declared)} but this check validates against ` +
        `${SCHEMA_URL}. Declaring conformance to a schema nothing verifies is the ` +
        `exact shape of notme-6e5330.`,
    );
    return;
  }

  let schema: object;
  try {
    schema = JSON.parse(schemaRaw);
  } catch (err) {
    bail(`${SCHEMA_PATH} is not valid JSON: ${(err as Error).message}`);
  }

  // strict:false — the MCP schema uses `example` (singular), which is not a
  // JSON Schema keyword and which ajv's strict mode rejects as a typo for
  // `examples`. That is upstream's spelling, not ours to fix; refusing to
  // load their schema over it would just disable the check.
  const ajv = new Ajv({ strict: false, allErrors: true });
  addFormats(ajv);

  const validate = ajv.compile(schema);
  if (!validate(doc)) {
    for (const err of validate.errors ?? []) {
      fail("server.json", `schema violation at ${err.instancePath || "/"}: ${err.message}`);
    }
  }
}

/**
 * Refuse a `packages` key outright.
 *
 * Not a style rule. Every `packages[]` entry needs a `transport` to be
 * schema-valid, and notme has no MCP surface to describe with one — so the
 * only two ways this key comes back are a schema violation or a fabricated
 * transport that makes cloister generate backends for tools that do not
 * exist. Both are worse than the artifact-only shape, and both are silent.
 * A regression here is likelier than a deliberate change: `packages[]` is
 * what every other producer in the ecosystem uses.
 */
function checkNoPackagesKey(doc: Record<string, unknown>): void {
  if (!("packages" in doc)) return;
  fail(
    "server.json",
    "has a `packages` key. notme serves no MCP, so its images belong in " +
      `\`_meta."${PUBLISHER_PROVIDED}".artifacts\` — the schema's own extension slot. ` +
      "A `packages[]` entry requires `transport` (Package.required); adding a " +
      "placeholder one would make cloister derive session behaviour that does not " +
      "exist, and omitting it fails the declared schema (notme-6e5330).",
  );
}

function checkArtifactVersions(doc: Record<string, unknown>, version: string): void {
  const meta = doc._meta;
  if (typeof meta !== "object" || meta === null) {
    fail("server.json", "`_meta` is missing — nothing carries the published image addresses");
    return;
  }

  const provided = (meta as Record<string, unknown>)[PUBLISHER_PROVIDED];
  if (typeof provided !== "object" || provided === null) {
    fail(
      "server.json",
      `\`_meta."${PUBLISHER_PROVIDED}"\` is missing. This is where an artifact-only ` +
        `producer declares its images (ley-line-open-0135fa); without it a consumer ` +
        `has no address to derive and cloister's fail-closed pinning refuses the bundle.`,
    );
    return;
  }

  const artifacts = (provided as Record<string, unknown>).artifacts;
  if (!Array.isArray(artifacts)) {
    fail(
      "server.json",
      `\`_meta."${PUBLISHER_PROVIDED}".artifacts\` is missing or not an array — ` +
        `nothing to derive an image from`,
    );
    return;
  }

  for (const identifier of EXPECTED_IDENTIFIERS) {
    // Match on the tag-stripped address, EXACTLY. Exact equality is what
    // keeps `ghcr.io/…/notme-proxy` from answering a lookup for
    // `ghcr.io/…/notme` — a prefix match here would find two entries for
    // notme and report a spurious ambiguity while notme-proxy went unchecked.
    const entries = artifacts.filter(
      (a): a is Record<string, unknown> =>
        typeof a === "object" &&
        a !== null &&
        bareIdentifier(String((a as Record<string, unknown>).identifier ?? "")) === identifier,
    );

    if (entries.length === 0) {
      fail(
        "server.json",
        `no artifacts[] entry for ${identifier} — cloister derives no image for this bundle`,
      );
      continue;
    }
    if (entries.length > 1) {
      fail(
        "server.json",
        `${entries.length} artifacts[] entries for ${identifier} — ambiguous, which one publishes?`,
      );
      continue;
    }

    const entry = entries[0];
    const where = `artifacts[] entry for ${identifier}`;

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

/**
 * The document's own top-level `version`.
 *
 * Distinct from the artifact versions and easy to leave behind on a bump — a
 * registry listing notme at 0.1.0-rc2 while its images publish 0.1.0-rc3 is
 * the same drift class, in the field a human reads first.
 */
function checkDocumentVersion(doc: Record<string, unknown>, version: string): void {
  if (doc.version !== version) {
    fail(
      "server.json",
      `top-level \`version\` is ${JSON.stringify(doc.version)} but the publish job pushes ` +
        `${JSON.stringify(version)}`,
    );
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
  const arg = (process.argv[2] ?? process.env.VERSION ?? "").trim();

  // `--self` — validate the file against ITS OWN declared version.
  //
  // Why a second mode: the tag-bearing check can only run at release time,
  // when a VERSION exists. That left every other property here — schema
  // conformance, the shape of `artifacts`, recipes agreeing with each other —
  // unverified on the branch where it is actually introduced. notme's
  // `packages[]`/`transport` violation lived in main for two days and was
  // found from another repo (notme-6e5330); the over-long `description` was
  // found by this script's first run, having never been checked at all.
  //
  // So: `--self` is the PR gate and asserts everything except "does it match
  // the tag" (nothing on a branch knows the tag). `task version:check
  // VERSION=x` is the release gate and adds exactly that. Neither subsumes
  // the other, and running only the release one is how both defects shipped.
  if (arg === "--self") {
    const doc = parseServerJson();
    const declared = doc.version;
    if (typeof declared !== "string" || declared === "") {
      bail("server.json has no top-level `version` string to self-check against");
    }
    runChecks(doc, declared, "declared version");
    return;
  }

  const version = arg;

  if (version === "") {
    bail(
      "no VERSION given. Pass the tag the publish job will push, e.g.\n" +
        "  task version:check VERSION=0.1.0\n" +
        "  pnpm exec tsx scripts/check-image-versions.ts 0.1.0\n" +
        "or --self to check the file against its own declared version:\n" +
        "  task server:check",
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

  runChecks(parseServerJson(), version);
}

/**
 * Every assertion, against one version. Shared by both modes above.
 *
 * `source` only changes the success message, and deliberately so: `--self`
 * compares against the file's own declared version, which is NOT evidence
 * that anything matches a pushed tag. Saying "pushed tag" in both modes would
 * make the passing output overstate what ran — the same over-claiming that
 * let ley-line-open v0.11.2 through a guard reporting success.
 */
function runChecks(
  doc: Record<string, unknown>,
  version: string,
  source: "pushed tag" | "declared version" = "pushed tag",
): void {
  checkSchemaConformance(doc);
  checkNoPackagesKey(doc);
  checkDocumentVersion(doc, version);
  checkArtifactVersions(doc, version);
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
    `server.json is valid against ${SCHEMA_PATH} and all image versions agree with the ` +
      `${source} ${version} (${EXPECTED_IDENTIFIERS.length} artifacts, ` +
      `${VERSIONED_RECIPES.length} recipes).` +
      (source === "declared version"
        ? "\nNOTE: --self does NOT check the pushed tag. `task version:check VERSION=<tag>` does, and runs before every publish."
        : ""),
  );
}

main();
