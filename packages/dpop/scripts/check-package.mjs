import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const packageDir = dirname(dirname(fileURLToPath(import.meta.url)));
const destination = mkdtempSync(join(tmpdir(), "notme-dpop-pack-"));

try {
  const packedName = execFileSync(
    "pnpm",
    ["pack", "--pack-destination", destination],
    { cwd: packageDir, encoding: "utf8" },
  ).trim().split("\n").at(-1);
  const archive = packedName.startsWith(destination)
    ? packedName
    : join(destination, packedName);
  const listing = execFileSync("tar", ["-tzf", archive], {
    encoding: "utf8",
  });
  const required = [
    "package/README.md",
    "package/docs/verification.mdx",
    "package/docs/replay-protection.mdx",
    "package/docs/errors.mdx",
    "package/docs/migration-0.3.mdx",
    "package/dist/index.js",
    "package/dist/index.d.ts",
  ];
  for (const path of required) {
    if (!listing.split("\n").includes(path)) {
      throw new Error(`packed package missing ${path}`);
    }
  }

  execFileSync("tar", ["-xzf", archive, "-C", destination]);
  const readme = readFileSync(
    join(destination, "package", "README.md"),
    "utf8",
  );
  for (const term of [
    "checkAndRecordJti",
    "DPoPVerificationError",
    "migration-0.3.mdx",
  ]) {
    if (!readme.includes(term)) {
      throw new Error(`packed README missing current API term: ${term}`);
    }
  }
  for (const stale of [
    "seenJti:",
    "Pass []",
    "clockTolerance defaults to 0",
  ]) {
    if (readme.includes(stale)) {
      throw new Error(`packed README contains stale 0.2 guidance: ${stale}`);
    }
  }

  const sdk = await import(
    pathToFileURL(join(destination, "package", "dist", "index.js")).href
  );
  for (const name of [
    "verifyDPoPToken",
    "verifyAccessToken",
    "DPoPVerificationError",
  ]) {
    if (typeof sdk[name] !== "function") {
      throw new Error(`packed ESM entry point missing ${name}`);
    }
  }
} finally {
  rmSync(destination, { recursive: true, force: true });
}
