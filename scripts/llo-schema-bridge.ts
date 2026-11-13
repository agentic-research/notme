#!/usr/bin/env npx tsx
/**
 * llo-schema-bridge.ts — resolve ley-line-open's RELEASED zod codegen plugin,
 * pinned (notme-3e9c73).
 *
 * gen/ts/identity.zod.ts is generated from schema/identity.capnp by LLO's
 * `capnpc-schema-bridge-zod`, the maintained successor of the copy notme used
 * to vendor under packages/schema-bridge. notme does not build it. It runs the
 * binary LLO released, at the tag schema/codegen/llo-release.json pins.
 *
 * TRUST is the same as for wasm/ (scripts/fetch-llo-wasm.ts): LLO signs
 * nothing it releases, so the pin is trust-on-first-use. The checks are:
 *   - schema/codegen/SHA256SUMS is that release's SHA256SUMS, unmodified, and
 *     its sha256 is pinned in llo-release.json;
 *   - each platform binary's sha256 and size are pinned, and must also equal
 *     its SHA256SUMS line;
 *   - a downloaded binary is used only if it matches both, and a cached one
 *     is re-hashed on every run, so a swapped file never reaches capnp.
 *   - a download that finds a signature next to SHA256SUMS fails, so the day
 *     LLO signs, this script has to start verifying it.
 *
 * The binaries are not committed (four of them, ~700 KB each). They are cached
 * under node_modules/.cache/llo-schema-bridge/<tag>/.
 *
 * Usage (repo root):
 *   pnpm exec tsx scripts/llo-schema-bridge.ts --path    print the verified plugin path for this host (downloads on a cache miss)
 *   pnpm exec tsx scripts/llo-schema-bridge.ts --check   offline: SHA256SUMS and every pin agree (docs:check)
 *   pnpm exec tsx scripts/llo-schema-bridge.ts --pin vX.Y.Z
 *       re-pin to another release: record its SHA256SUMS and every platform
 *       binary's digest. The llo-release.json diff is the review surface.
 *
 * Exit: 0 ok · 1 any verification failure · 2 usage error or unsupported host.
 */
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { parseSums } from "./fetch-llo-wasm";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
export const PIN_DIR = join(ROOT, "schema", "codegen");
const MANIFEST = "llo-release.json";
const SUMS = "SHA256SUMS";
const LOCAL = new Set(["README.md", MANIFEST, SUMS]);
const CACHE = join(ROOT, "node_modules", ".cache", "llo-schema-bridge");
const PLATFORMS = ["darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64"] as const;
const SIGNATURE_CANDIDATES = [`${SUMS}.sigstore.json`, `${SUMS}.bundle`, `${SUMS}.sig`, `${SUMS}.asc`, `${SUMS}.intoto.jsonl`];

interface Pin {
  file: string;
  sha256: string;
  size: number;
}
export interface PluginManifest {
  repo: string;
  tag: string;
  tagCommit: string;
  sha256sums: { file: string; sha256: string };
  plugin: string;
  assets: Pin[];
  signature: { status: "none-published"; checked: string };
}

const sha256 = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
const readManifest = (): PluginManifest => JSON.parse(readFileSync(join(PIN_DIR, MANIFEST), "utf-8")) as PluginManifest;
const releaseUrl = (m: Pick<PluginManifest, "repo" | "tag">, file: string) =>
  `https://github.com/${m.repo}/releases/download/${m.tag}/${file}`;

/** The release asset name for this host, or null when LLO ships none. */
export function hostAsset(plugin: string, platform: string = process.platform, arch: string = process.arch): string | null {
  const os = platform === "darwin" || platform === "linux" ? platform : null;
  const cpu = arch === "x64" ? "amd64" : arch === "arm64" ? "arm64" : null;
  return os && cpu ? `${plugin}-${os}-${cpu}` : null;
}

function checkBytes(file: string, bytes: Uint8Array, pin: Pin, sums: Map<string, string>): string[] {
  const problems: string[] = [];
  const got = sha256(bytes);
  if (got !== pin.sha256) problems.push(`${file}: sha256 ${got} != pinned ${pin.sha256} (${MANIFEST})`);
  const listed = sums.get(file);
  if (listed !== pin.sha256) problems.push(`${file}: ${SUMS} lists ${listed ?? "nothing"}, pinned ${pin.sha256}`);
  if (bytes.length !== pin.size) problems.push(`${file}: ${bytes.length} bytes != pinned ${pin.size}`);
  return problems;
}

/** Offline: the vendored SHA256SUMS and the manifest agree. Empty means clean. */
export function checkPins(): string[] {
  if (!existsSync(join(PIN_DIR, MANIFEST))) return [`${MANIFEST}: missing from schema/codegen/`];
  const m = readManifest();
  const problems: string[] = [];
  const sumsPath = join(PIN_DIR, SUMS);
  if (!existsSync(sumsPath)) return [`${SUMS}: missing from schema/codegen/ (run \`task llo:schema-bridge -- --pin ${m.tag}\`)`];
  const sumsBytes = readFileSync(sumsPath);
  if (sha256(sumsBytes) !== m.sha256sums.sha256) problems.push(`${SUMS}: sha256 ${sha256(sumsBytes)} != pinned ${m.sha256sums.sha256}`);
  let sums: Map<string, string>;
  try {
    sums = parseSums(sumsBytes.toString("utf-8"));
  } catch (e) {
    return [...problems, (e as Error).message];
  }
  const want = PLATFORMS.map((p) => `${m.plugin}-${p}`);
  const have = m.assets.map((a) => a.file);
  for (const w of want) if (!have.includes(w)) problems.push(`${MANIFEST}: no pin for ${w}`);
  for (const h of have) if (!want.includes(h)) problems.push(`${MANIFEST}: pins ${h}, which is not a ${m.plugin} platform binary`);
  for (const a of m.assets) {
    if (!/^[0-9a-f]{64}$/.test(a.sha256)) problems.push(`${a.file}: pinned sha256 is not 64 hex digits`);
    if (!(a.size > 0)) problems.push(`${a.file}: pinned size is not positive`);
    const listed = sums.get(a.file);
    if (listed !== a.sha256) problems.push(`${a.file}: ${SUMS} lists ${listed ?? "nothing"}, pinned ${a.sha256}`);
  }
  for (const f of readdirSync(PIN_DIR)) if (!LOCAL.has(f)) problems.push(`schema/codegen/${f}: not part of the plugin pin`);
  return problems;
}

async function download(url: string): Promise<Uint8Array> {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`GET ${url}: HTTP ${res.status}`);
  return new Uint8Array(await res.arrayBuffer());
}

async function signaturesPublished(m: PluginManifest): Promise<string[]> {
  const found: string[] = [];
  for (const c of SIGNATURE_CANDIDATES) {
    const res = await fetch(releaseUrl(m, c), { method: "HEAD", redirect: "follow" });
    if (res.ok) found.push(c);
  }
  return found;
}

/** The verified plugin for this host: cached bytes re-hashed, or downloaded and verified. */
export async function resolvePlugin(): Promise<string> {
  const problems = checkPins();
  if (problems.length) throw new Error(`pins are inconsistent:\n  ${problems.join("\n  ")}`);
  const m = readManifest();
  const file = hostAsset(m.plugin);
  if (!file) throw Object.assign(new Error(`LLO ships no ${m.plugin} for ${process.platform}/${process.arch}`), { exitCode: 2 });
  const pin = m.assets.find((a) => a.file === file)!;
  const sums = parseSums(readFileSync(join(PIN_DIR, SUMS), "utf-8"));
  const dir = join(CACHE, m.tag);
  const path = join(dir, file);
  if (existsSync(path)) {
    const bad = checkBytes(file, new Uint8Array(readFileSync(path)), pin, sums);
    if (!bad.length) {
      chmodSync(path, 0o755);
      return path;
    }
    // A cached file that fails its pin is replaced, never used.
    console.error(`llo-schema-bridge: cached ${file} failed its pin, re-downloading:\n  ${bad.join("\n  ")}`);
  }
  const sigs = await signaturesPublished(m);
  if (sigs.length) {
    throw new Error(`${m.tag} now publishes ${sigs.join(", ")}: LLO signs its release. Verify it here and record it in ${MANIFEST} before use.`);
  }
  const bytes = await download(releaseUrl(m, file));
  const bad = checkBytes(file, bytes, pin, sums);
  if (bad.length) throw new Error(`refused ${file} from ${m.repo}@${m.tag}:\n  ${bad.join("\n  ")}`);
  mkdirSync(dir, { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, bytes, { mode: 0o755 });
  renameSync(tmp, path);
  return path;
}

function tagCommit(repo: string, tag: string): string {
  const out = execFileSync("git", ["ls-remote", `https://github.com/${repo}`, `refs/tags/${tag}`, `refs/tags/${tag}^{}`], { encoding: "utf-8" });
  const lines = out.trim().split("\n").map((l) => l.split("\t"));
  const peeled = lines.find(([, ref]) => ref === `refs/tags/${tag}^{}`) ?? lines.find(([, ref]) => ref === `refs/tags/${tag}`);
  if (!peeled) throw new Error(`${repo}: no tag ${tag}`);
  return peeled[0];
}

async function repin(tag: string): Promise<PluginManifest> {
  const prev = readManifest();
  const next: PluginManifest = { ...prev, tag, tagCommit: tagCommit(prev.repo, tag) };
  const sigs = await signaturesPublished(next);
  if (sigs.length) throw new Error(`${tag} publishes ${sigs.join(", ")}: verify it before pinning.`);
  const sumsBytes = await download(releaseUrl(next, SUMS));
  const sums = parseSums(new TextDecoder().decode(sumsBytes));
  next.sha256sums = { file: SUMS, sha256: sha256(sumsBytes) };
  next.assets = [];
  for (const p of PLATFORMS) {
    const file = `${prev.plugin}-${p}`;
    const want = sums.get(file);
    if (!want) throw new Error(`${tag}: ${SUMS} lists no ${file}`);
    const bytes = await download(releaseUrl(next, file));
    if (sha256(bytes) !== want) throw new Error(`${tag}: ${file} does not match its ${SUMS} line`);
    next.assets.push({ file, sha256: want, size: bytes.length });
  }
  next.signature = { status: "none-published", checked: `${new Date().toISOString().slice(0, 10)}: no ${SIGNATURE_CANDIDATES.join(" / ")} on ${tag}` };
  writeFileSync(join(PIN_DIR, SUMS), sumsBytes);
  writeFileSync(join(PIN_DIR, MANIFEST), JSON.stringify(next, null, 2) + "\n");
  return next;
}

async function main(argv: string[]): Promise<number> {
  if (argv[0] === "--check" && argv.length === 1) {
    const problems = checkPins();
    if (problems.length) {
      console.error(`llo-schema-bridge: ${problems.length} problem(s):\n  ${problems.join("\n  ")}`);
      return 1;
    }
    const m = readManifest();
    console.log(`llo-schema-bridge: ${m.plugin} pinned to ${m.repo}@${m.tag} for ${PLATFORMS.join(", ")}; pins match its ${SUMS}.`);
    return 0;
  }
  if (argv[0] === "--path" && argv.length === 1) {
    process.stdout.write(`${await resolvePlugin()}\n`);
    return 0;
  }
  if (argv[0] === "--pin" && /^v\d+\.\d+\.\d+$/.test(argv[1] ?? "") && argv.length === 2) {
    const m = await repin(argv[1]);
    console.log(`llo-schema-bridge: re-pinned to ${m.tag} (${m.tagCommit}); REVIEW the ${MANIFEST} diff, then run \`task schema:zod\`.`);
    return 0;
  }
  console.error("usage: llo-schema-bridge.ts --path | --check | --pin vX.Y.Z");
  return 2;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e: unknown) => {
      console.error(`llo-schema-bridge: ${(e as Error).message}`);
      process.exit((e as { exitCode?: number }).exitCode ?? 1);
    },
  );
}
