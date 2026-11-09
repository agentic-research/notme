#!/usr/bin/env npx tsx
/**
 * fetch-llo-wasm.ts — vendor ley-line-open's released wasm verifier, pinned
 * (notme-bc4cd2).
 *
 * notme does not implement the third-party verifier for its own credentials;
 * LLO does, and releases it as `leyline_sign.wasm`. notme's tests run THOSE
 * bytes against chains notme mints, so what is vendored has to be exactly
 * what LLO released, and a swap has to fail the gate.
 *
 * TRUST, stated as it is rather than as it would be nice to be:
 *   - LLO signs nothing it releases. v0.25.0 ships no cosign/sigstore bundle
 *     for SHA256SUMS or any asset, and GitHub has no artifact attestation for
 *     either digest (`gh attestation verify` → 404; release.yml attests only
 *     the OCI image). So SHA256SUMS proves the assets match a file served
 *     from the SAME release, not who built them.
 *   - What this script adds is a PIN: wasm/llo-release.json records the
 *     sha256 of SHA256SUMS and of each vendored asset, reviewed once, in this
 *     repo. A later download (or a vendored file) that differs from the pin
 *     is refused, so a replaced release asset cannot silently reach notme.
 *     That is trust-on-first-use, plus whatever review the pin commit got.
 *   - The fetch probes for a signature next to SHA256SUMS and FAILS if one
 *     appears while the manifest says there is none, so the day LLO starts
 *     signing, this script is forced to start verifying.
 *
 * Usage (repo root):
 *   pnpm exec tsx scripts/fetch-llo-wasm.ts            download the pinned tag, verify, write wasm/
 *   pnpm exec tsx scripts/fetch-llo-wasm.ts --check    offline: vendored files match the pins (docs:check)
 *   pnpm exec tsx scripts/fetch-llo-wasm.ts --pin vX.Y.Z
 *       re-pin to another release: download its SHA256SUMS, record new
 *       digests in the manifest, then vendor. The diff to llo-release.json IS
 *       the review surface; read it.
 *
 * Exit: 0 ok · 1 any verification failure · 2 usage error.
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
export const LLO_WASM_DIR = join(HERE, "..", "wasm");
export const LLO_MANIFEST = "llo-release.json";
const SUMS = "SHA256SUMS";
/** Files in wasm/ that are not release assets. */
const LOCAL = new Set(["README.md", LLO_MANIFEST, SUMS]);
/** Where a signature over SHA256SUMS would be, if LLO published one. */
const SIGNATURE_CANDIDATES = [
  `${SUMS}.sigstore.json`,
  `${SUMS}.bundle`,
  `${SUMS}.sig`,
  `${SUMS}.asc`,
  `${SUMS}.intoto.jsonl`,
];

export interface LloManifest {
  repo: string;
  tag: string;
  tagCommit: string;
  sha256sums: { file: string; sha256: string };
  assets: Array<{ file: string; sha256: string; size: number }>;
  signature: { status: "none-published"; checked: string };
  verifiedAgainstSource?: string;
}

const sha256 = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");

export function readLloManifest(dir: string = LLO_WASM_DIR): LloManifest {
  return JSON.parse(readFileSync(join(dir, LLO_MANIFEST), "utf-8")) as LloManifest;
}

/** Parse `sha256sum` format into file → digest. */
export function parseSums(text: string): Map<string, string> {
  const m = new Map<string, string>();
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    const r = /^([0-9a-f]{64}) [ *](\S+)$/.exec(line);
    if (!r) throw new Error(`${SUMS}: not a "<sha256>  <file>" line: ${line}`);
    if (m.has(r[2])) throw new Error(`${SUMS}: ${r[2]} listed twice`);
    m.set(r[2], r[1]);
  }
  return m;
}

/**
 * Check one asset's bytes against BOTH the manifest pin and the release's
 * SHA256SUMS line. Two independent statements of the same digest: the pin
 * is notme's, the sums line is LLO's.
 */
function checkAsset(
  file: string,
  bytes: Uint8Array,
  pin: { sha256: string; size: number },
  sums: Map<string, string>,
): string[] {
  const problems: string[] = [];
  const got = sha256(bytes);
  if (got !== pin.sha256) problems.push(`${file}: sha256 ${got} != pinned ${pin.sha256} (${LLO_MANIFEST})`);
  const listed = sums.get(file);
  if (!listed) problems.push(`${file}: not listed in the release's ${SUMS}`);
  else if (listed !== got) problems.push(`${file}: sha256 ${got} != ${SUMS} ${listed}`);
  if (bytes.length !== pin.size) problems.push(`${file}: ${bytes.length} bytes != pinned ${pin.size}`);
  if (file.endsWith(".wasm")) problems.push(...checkWasmSurface(file, bytes));
  return problems;
}

/**
 * Node's WebAssembly, typed as Node has it. tsconfig.scripts.json also loads
 * @cloudflare/workers-types, whose WebAssembly is workerd's (no compile, an
 * abstract Module) because workerd refuses to compile wasm from bytes.
 */
export const NodeWasm = WebAssembly as unknown as {
  Module: { new (bytes: Uint8Array): WebAssembly.Module; exports(m: WebAssembly.Module): Array<{ name: string }> };
  compile(bytes: Uint8Array): Promise<WebAssembly.Module>;
};

/** leyline_sign.wasm must still export what notme binds by name. */
function checkWasmSurface(file: string, bytes: Uint8Array): string[] {
  if (file !== "leyline_sign.wasm") return [];
  let names: string[];
  try {
    names = NodeWasm.Module.exports(new NodeWasm.Module(bytes)).map((e) => e.name);
  } catch (e) {
    return [`${file}: does not compile as wasm: ${(e as Error).message}`];
  }
  return ["memory", "lsign_alloc", "lsign_free", "leyline_verify_cert_path"]
    .filter((n) => !names.includes(n))
    .map((n) => `${file}: no export ${n}`);
}

/** Every problem with the vendored set, one line each; empty means clean. */
export function checkVendoredLloWasm(dir: string = LLO_WASM_DIR): string[] {
  const problems: string[] = [];
  if (!existsSync(join(dir, LLO_MANIFEST))) return [`${LLO_MANIFEST}: missing from ${dir}`];
  const manifest = readLloManifest(dir);
  const sumsPath = join(dir, SUMS);
  if (!existsSync(sumsPath)) return [`${SUMS}: missing (run \`task llo:wasm\`)`];
  const sumsBytes = readFileSync(sumsPath);
  const sumsGot = sha256(sumsBytes);
  if (sumsGot !== manifest.sha256sums.sha256) {
    problems.push(`${SUMS}: sha256 ${sumsGot} != pinned ${manifest.sha256sums.sha256}`);
  }
  let sums: Map<string, string>;
  try {
    sums = parseSums(sumsBytes.toString("utf-8"));
  } catch (e) {
    return [...problems, (e as Error).message];
  }
  const pinned = new Set(manifest.assets.map((a) => a.file));
  for (const f of readdirSync(dir)) {
    if (!LOCAL.has(f) && !pinned.has(f)) problems.push(`${f}: present in wasm/ but not pinned in ${LLO_MANIFEST}`);
  }
  for (const a of manifest.assets) {
    const p = join(dir, a.file);
    if (!existsSync(p)) {
      problems.push(`${a.file}: pinned but missing (run \`task llo:wasm\`)`);
      continue;
    }
    problems.push(...checkAsset(a.file, readFileSync(p), a, sums));
  }
  return problems;
}

/**
 * Read one pinned asset and return its bytes only if they match the pin.
 * Hashes the SAME bytes it returns, so nothing can change between check and use.
 */
export function readPinnedAsset(file: string, dir: string = LLO_WASM_DIR): Uint8Array {
  const manifest = readLloManifest(dir);
  const pin = manifest.assets.find((a) => a.file === file);
  if (!pin) throw new Error(`${LLO_MANIFEST} pins no ${file}`);
  const sums = parseSums(readFileSync(join(dir, SUMS), "utf-8"));
  const bytes = new Uint8Array(readFileSync(join(dir, file)));
  const problems = checkAsset(file, bytes, pin, sums);
  if (problems.length) throw new Error(`vendored ${file} failed its pin (notme-bc4cd2):\n  ${problems.join("\n  ")}`);
  return bytes;
}

const releaseUrl = (m: Pick<LloManifest, "repo" | "tag">, file: string) =>
  `https://github.com/${m.repo}/releases/download/${m.tag}/${file}`;

async function download(url: string): Promise<Uint8Array> {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`GET ${url}: HTTP ${res.status}`);
  return new Uint8Array(await res.arrayBuffer());
}

async function exists(url: string): Promise<boolean> {
  const res = await fetch(url, { method: "HEAD", redirect: "follow" });
  return res.ok;
}

function tagCommit(repo: string, tag: string): string {
  const out = execFileSync("git", ["ls-remote", `https://github.com/${repo}`, `refs/tags/${tag}`, `refs/tags/${tag}^{}`], {
    encoding: "utf-8",
  });
  const lines = out.trim().split("\n").map((l) => l.split("\t"));
  // An annotated tag lists the peeled commit as `<tag>^{}`; prefer it.
  const peeled = lines.find(([, ref]) => ref === `refs/tags/${tag}^{}`) ?? lines.find(([, ref]) => ref === `refs/tags/${tag}`);
  if (!peeled) throw new Error(`${repo}: no tag ${tag}`);
  return peeled[0];
}

async function fetchAndVendor(manifest: LloManifest): Promise<string[]> {
  const problems: string[] = [];
  const found: string[] = [];
  for (const c of SIGNATURE_CANDIDATES) if (await exists(releaseUrl(manifest, c))) found.push(c);
  if (found.length) {
    problems.push(
      `${manifest.tag} now publishes ${found.join(", ")}: LLO signs its release. ` +
        `Wire verification of it into this script and record it in ${LLO_MANIFEST} before vendoring.`,
    );
    return problems;
  }

  const sumsBytes = await download(releaseUrl(manifest, SUMS));
  const sumsGot = sha256(sumsBytes);
  if (sumsGot !== manifest.sha256sums.sha256) {
    return [`${SUMS} of ${manifest.tag}: sha256 ${sumsGot} != pinned ${manifest.sha256sums.sha256} — the release changed after it was pinned`];
  }
  const sums = parseSums(new TextDecoder().decode(sumsBytes));
  const fetched = new Map<string, Uint8Array>();
  for (const a of manifest.assets) {
    const bytes = await download(releaseUrl(manifest, a.file));
    problems.push(...checkAsset(a.file, bytes, a, sums));
    fetched.set(a.file, bytes);
  }
  if (problems.length) return problems; // write nothing unless everything verified
  writeFileSync(join(LLO_WASM_DIR, SUMS), sumsBytes);
  for (const [f, b] of fetched) writeFileSync(join(LLO_WASM_DIR, f), b);
  return [];
}

async function repin(manifest: LloManifest, tag: string): Promise<LloManifest> {
  const next: LloManifest = { ...manifest, tag, tagCommit: tagCommit(manifest.repo, tag) };
  const sumsBytes = await download(releaseUrl(next, SUMS));
  const sums = parseSums(new TextDecoder().decode(sumsBytes));
  next.sha256sums = { file: SUMS, sha256: sha256(sumsBytes) };
  next.assets = [];
  for (const a of manifest.assets) {
    const want = sums.get(a.file);
    if (!want) throw new Error(`${tag}: ${SUMS} lists no ${a.file}`);
    const bytes = await download(releaseUrl(next, a.file));
    next.assets.push({ file: a.file, sha256: want, size: bytes.length });
  }
  next.signature = { status: "none-published", checked: `${new Date().toISOString().slice(0, 10)}: no ${SIGNATURE_CANDIDATES.join(" / ")} on ${tag}` };
  delete next.verifiedAgainstSource; // a statement about the OLD tag
  return next;
}

async function main(argv: string[]): Promise<number> {
  if (argv[0] === "--check") {
    const problems = checkVendoredLloWasm();
    if (problems.length) {
      console.error(`llo-wasm: ${problems.length} problem(s):\n  ${problems.join("\n  ")}`);
      return 1;
    }
    const m = readLloManifest();
    console.log(`llo-wasm: wasm/ matches ${m.repo}@${m.tag} (${m.assets.map((a) => a.file).join(", ")}) and its ${SUMS}.`);
    return 0;
  }
  let manifest = readLloManifest();
  if (argv[0] === "--pin") {
    if (!/^v\d+\.\d+\.\d+$/.test(argv[1] ?? "")) {
      console.error("usage: fetch-llo-wasm.ts --pin vX.Y.Z");
      return 2;
    }
    manifest = await repin(manifest, argv[1]);
    writeFileSync(join(LLO_WASM_DIR, LLO_MANIFEST), JSON.stringify(manifest, null, 2) + "\n");
    console.log(`llo-wasm: re-pinned to ${manifest.tag} (${manifest.tagCommit}); REVIEW the ${LLO_MANIFEST} diff.`);
  } else if (argv.length) {
    console.error("usage: fetch-llo-wasm.ts [--check | --pin vX.Y.Z]");
    return 2;
  }
  const problems = await fetchAndVendor(manifest);
  if (problems.length) {
    console.error(`llo-wasm: refused ${manifest.tag}:\n  ${problems.join("\n  ")}`);
    return 1;
  }
  console.log(`llo-wasm: vendored ${manifest.assets.map((a) => a.file).join(", ")} from ${manifest.repo}@${manifest.tag}; ${SUMS} and every asset match their pins. No signature is published (see ${LLO_MANIFEST}).`);
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e: unknown) => {
      console.error(`llo-wasm: ${(e as Error).message}`);
      process.exit(1);
    },
  );
}
