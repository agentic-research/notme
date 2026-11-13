/**
 * kek-rehearsal.test.ts — the rehearsal's "same key" means the same KEY
 * BYTES, not the same id (notme-ed6114, review F5).
 *
 * listEpochKeys reads the live key_id before it loads the key, so a cold
 * load that regenerated the key — the very bug the rehearsal hunts — would
 * publish the old id beside the new public key, and an id comparison reads
 * "same key". This runs the script's own `kid()` (extracted verbatim) on two
 * epochs.json bodies that differ only in the public key.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const script = readFileSync(fileURLToPath(new URL("../../../scripts/kek-rehearsal.sh", import.meta.url).href), "utf8");
const kidFn = script.split("\n").find((l) => l.startsWith("kid() "));

function kidOf(body: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), "kek-rehearsal-"));
  const probe = join(dir, "probe.json");
  writeFileSync(probe, JSON.stringify(body));
  return execFileSync("bash", ["-c", `${kidFn}\nkid`], { env: { ...process.env, PROBE: probe } })
    .toString()
    .trim();
}

const live = (keyId: string, publicRawB64: string) => ({
  epochs: [
    { epoch: 1, untilEpoch: 2, keyId: "retired", publicRawB64: "cmV0aXJlZA==", retiredAt: 1 },
    { epoch: 2, untilEpoch: null, keyId, publicRawB64, retiredAt: null },
  ],
});

describe("kek-rehearsal kid()", () => {
  it("is defined", () => {
    expect(kidFn).toBeDefined();
  });

  it("distinguishes a regenerated key that kept the old id", () => {
    expect(kidOf(live("k1", "AAAA"))).not.toBe(kidOf(live("k1", "BBBB")));
  });

  it("is stable for the same key", () => {
    expect(kidOf(live("k1", "AAAA"))).toBe(kidOf(live("k1", "AAAA")));
  });

  it("reads the LIVE entry, not a retired one", () => {
    expect(kidOf(live("k1", "AAAA"))).toContain("k1");
    expect(kidOf(live("k1", "AAAA"))).not.toContain("retired");
  });
});
