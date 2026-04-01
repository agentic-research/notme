#!/usr/bin/env npx tsx
// doc-check.ts — verify that doc claims about code are accurate.
// Usage: npx tsx scripts/doc-check.ts [--skip-external] [--format json]
import { readFileSync, readdirSync, existsSync } from "fs";
import { join, relative, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const args = process.argv.slice(2);
const skipExternal = args.includes("--skip-external");
const jsonOutput = args.includes("--format") && args[args.indexOf("--format") + 1] === "json";

// ── Step 1: Extract truth from code ──

function extractTypes(): Set<string> {
  const types = new Set<string>();
  const capnp = readFileSync(join(ROOT, "schema/identity.capnp"), "utf-8");
  for (const m of capnp.matchAll(/^(?:struct|enum)\s+(\w+)/gm)) types.add(m[1]);
  const ts = readFileSync(join(ROOT, "gen/ts/identity.ts"), "utf-8");
  for (const m of ts.matchAll(/^export\s+(?:interface|enum|const|type|function)\s+(\w+)/gm)) types.add(m[1]);
  return types;
}

function extractEndpoints(): Set<string> {
  const endpoints = new Set<string>();
  const anyMethodPaths = new Set<string>(); // paths without explicit method guard
  const worker = readFileSync(join(ROOT, "worker/worker.ts"), "utf-8");
  for (const m of worker.matchAll(
    /(?:url\.)?pathname\s*===\s*"([^"]+)"(?:\s*&&\s*request\.method\s*===\s*"(\w+)")?/g
  )) {
    const [, path, method] = m;
    if (method) {
      endpoints.add(`${method} ${path}`);
    } else {
      endpoints.add(`GET ${path}`);
      anyMethodPaths.add(path);
    }
  }
  // Return a Set-like object: routes without method guard match any method
  return { has(claim: string): boolean {
    if (endpoints.has(claim)) return true;
    const parts = claim.match(/^(\w+)\s+(.+)$/);
    return !!(parts && anyMethodPaths.has(parts[2]));
  }} as Set<string>;
}

// ── Step 2: Parse frontmatter from docs ──

interface DocClaims { file: string; types: string[]; endpoints: string[]; links: string[] }

function walk(dir: string, out: string[]) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (/\.(html|md)$/.test(entry.name)) out.push(full);
  }
}

function findDocFiles(): string[] {
  const files: string[] = [];
  for (const dir of ["worker/public", "docs"]) {
    const abs = join(ROOT, dir);
    if (existsSync(abs)) walk(abs, files);
  }
  const readme = join(ROOT, "README.md");
  if (existsSync(readme)) files.push(readme);
  return files;
}

function parseList(block: string, prefix: string): string[] {
  const esc = prefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = block.match(new RegExp(`${esc}\\s*(.+?)(?:\\n|$)`));
  return match ? match[1].split(",").map((s) => s.trim()).filter(Boolean) : [];
}

function parseFrontmatter(filePath: string): DocClaims | null {
  const content = readFileSync(filePath, "utf-8");
  const match = content.match(/<!--\s*\n?\s*@doc-check\s*\n([\s\S]*?)-->/);
  if (!match) return null;
  const block = match[1];
  return {
    file: relative(ROOT, filePath),
    types: parseList(block, "@types:"),
    endpoints: parseList(block, "@endpoints:"),
    links: parseList(block, "@links:"),
  };
}

// ── Step 3: Validate ──

interface Result { file: string; claim: string; kind: "type" | "endpoint" | "link"; pass: boolean; detail?: string }

async function validate(): Promise<Result[]> {
  const types = extractTypes();
  const endpoints = extractEndpoints();
  const results: Result[] = [];
  const docs = findDocFiles().map(parseFrontmatter).filter((d): d is DocClaims => d !== null);
  if (docs.length === 0) { console.error("No files with @doc-check frontmatter found."); process.exit(1); }

  for (const doc of docs) {
    for (const t of doc.types) {
      const pass = types.has(t);
      results.push({ file: doc.file, claim: t, kind: "type", pass, detail: pass ? undefined : `type "${t}" not found in schema or gen/ts` });
    }
    for (const ep of doc.endpoints) {
      const n = ep.replace(/\s+/g, " ").trim();
      const pass = endpoints.has(n);
      results.push({ file: doc.file, claim: n, kind: "endpoint", pass, detail: pass ? undefined : `endpoint "${n}" not found in worker.ts` });
    }
    for (const link of doc.links) {
      if (skipExternal && !link.includes("notme.bot")) {
        results.push({ file: doc.file, claim: link, kind: "link", pass: true, detail: "skipped (external)" });
        continue;
      }
      try {
        const resp = await fetch(link, { method: "HEAD", redirect: "follow", signal: AbortSignal.timeout(5000) });
        const pass = resp.status < 400;
        results.push({ file: doc.file, claim: link, kind: "link", pass, detail: pass ? undefined : `HTTP ${resp.status}` });
      } catch (e: any) {
        results.push({ file: doc.file, claim: link, kind: "link", pass: false, detail: e.message });
      }
    }
  }
  return results;
}

// ── Step 4: Report ──

async function main() {
  const results = await validate();
  if (jsonOutput) {
    console.log(JSON.stringify(results, null, 2));
  } else {
    let currentFile = "";
    for (const r of results) {
      if (r.file !== currentFile) { currentFile = r.file; console.log(`\n  ${r.file}`); }
      const icon = r.pass ? "\x1b[32mPASS\x1b[0m" : "\x1b[31mFAIL\x1b[0m";
      console.log(`    [${icon}] ${r.kind}: ${r.claim}${r.detail ? ` (${r.detail})` : ""}`);
    }
    console.log();
  }
  const failed = results.filter((r) => !r.pass);
  if (failed.length > 0) {
    if (!jsonOutput) console.log(`\x1b[31m${failed.length} claim(s) failed.\x1b[0m`);
    process.exit(1);
  } else {
    if (!jsonOutput) console.log(`\x1b[32mAll ${results.length} claims verified.\x1b[0m`);
  }
}

main();
