/**
 * scripts/verify-ct-log.ts (notme-1b46a8): the log-key pin check.
 * Drives run() against temp pin and metadata files, so the exit codes are the
 * ones `task ct:verify` returns.
 */
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { DEFAULT_PIN, run } from "../../../scripts/verify-ct-log";

const dir = mkdtempSync(join(tmpdir(), "ct-verify-"));
const put = (name: string, v: unknown) => {
  const p = join(dir, name);
  writeFileSync(p, JSON.stringify(v));
  return p;
};
const metadata = () => {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const der = publicKey.export({ type: "spki", format: "der" });
  return {
    log_id: createHash("sha256").update(der).digest("base64"),
    key: der.toString("base64"),
  };
};
const cleanCfg = put("cfg-clean.json", { logs: {} });
const placeholderCfg = put("cfg-placeholder.json", { url: "https://REPLACE-ME.example/" });
const quiet = async (argv0: string[]) => {
  const argv = argv0.includes("--config") ? argv0 : [...argv0, "--config", cleanCfg];
  const spies = [vi.spyOn(console, "log"), vi.spyOn(console, "error")].map((s) =>
    s.mockImplementation(() => {}),
  );
  try {
    return await run(argv);
  } finally {
    spies.forEach((s) => s.mockRestore());
  }
};

describe("ct:verify", () => {
  const pending = () => put("pending.json", { status: "not-provisioned" });

  it("exits 0 without reading anything while not provisioned", async () => {
    expect(await quiet(["--pin", pending(), "--metadata", "/nonexistent"])).toBe(0);
  });

  it("--write records a pin, and a matching log then exits 0", async () => {
    const md = put("md.json", metadata());
    const pin = pending();
    expect(await quiet(["--pin", pin, "--write", "--metadata", md])).toBe(0);
    expect(JSON.parse(readFileSync(pin, "utf8")).status).toBe("provisioned");
    expect(await quiet(["--pin", pin, "--metadata", md])).toBe(0);
  });

  it("exits 1 when the log serves a different key", async () => {
    const pin = pending();
    await quiet(["--pin", pin, "--write", "--metadata", put("a.json", metadata())]);
    expect(await quiet(["--pin", pin, "--metadata", put("b.json", metadata())])).toBe(1);
  });

  it("exits 1 when the metadata's log_id is not SHA-256(key), even if the key matches", async () => {
    const m = metadata();
    const pin = pending();
    await quiet(["--pin", pin, "--write", "--metadata", put("m.json", m)]);
    const lying = { ...m, log_id: createHash("sha256").update("x").digest("base64") };
    expect(await quiet(["--pin", pin, "--metadata", put("lying.json", lying)])).toBe(1);
  });

  it("--write refuses (exit 2) to replace a different recorded pin and leaves it untouched", async () => {
    const pin = pending();
    await quiet(["--pin", pin, "--write", "--metadata", put("a2.json", metadata())]);
    const before = readFileSync(pin, "utf8");
    expect(await quiet(["--pin", pin, "--write", "--metadata", put("b2.json", metadata())])).toBe(2);
    expect(readFileSync(pin, "utf8")).toBe(before);
  });

  it("--write is idempotent for the same key", async () => {
    const md = put("same.json", metadata());
    const pin = pending();
    await quiet(["--pin", pin, "--write", "--metadata", md]);
    expect(await quiet(["--pin", pin, "--write", "--metadata", md])).toBe(0);
  });

  it("exits 1 for a malformed pin and for an unreadable log", async () => {
    expect(await quiet(["--pin", put("bad.json", { status: "wat" }), "--metadata", put("m3.json", metadata())])).toBe(1);
    const pin = pending();
    await quiet(["--pin", pin, "--write", "--metadata", put("m4.json", metadata())]);
    expect(await quiet(["--pin", pin, "--metadata", join(dir, "missing.json")])).toBe(1);
  });

  it("exits 1 when provisioned (or writing) while the config still has REPLACE-ME", async () => {
    const md = put("mr.json", metadata());
    const pin = pending();
    expect(await quiet(["--pin", pin, "--write", "--metadata", md, "--config", placeholderCfg])).toBe(1);
    expect(JSON.parse(readFileSync(pin, "utf8")).status).toBe("not-provisioned");
    await quiet(["--pin", pin, "--write", "--metadata", md]);
    expect(await quiet(["--pin", pin, "--metadata", md, "--config", placeholderCfg])).toBe(1);
    // placeholder state stays 0 even with the placeholder config (today's state)
    expect(await quiet(["--pin", pending(), "--config", placeholderCfg])).toBe(0);
  });

  it("the committed pin is in a state the script recognises", () => {
    const pin = JSON.parse(readFileSync(DEFAULT_PIN, "utf8"));
    expect(["not-provisioned", "provisioned"]).toContain(pin.status);
    if (pin.status === "provisioned") {
      // Self-consistent: id is SHA-256(key), and the recorded digest is of the key.
      const key = Buffer.from(pin.key, "base64");
      expect(createHash("sha256").update(key).digest("base64")).toBe(pin.log_id);
      expect(createHash("sha256").update(key).digest("hex")).toBe(pin.key_spki_sha256);
    }
  });
});
