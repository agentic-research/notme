import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const publicDir = fileURLToPath(new URL("../../public/", import.meta.url));
const apas = readFileSync(`${publicDir}/apas.html`, "utf8");
const home = readFileSync(`${publicDir}/index.html`, "utf8");

describe("APAS public summary", () => {
  it("mirrors the current canonical draft metadata", () => {
    expect(apas).toContain("0.2.1-draft");
    expect(apas).toContain("2026-07-26");
    expect(apas).toContain("DRAFT");
  });

  it("describes shipped handoff envelopes without claiming full L2", () => {
    const summary = apas.toLowerCase();
    expect(summary).toContain("in-toto + dsse handoff envelope");
    expect(summary).toContain("signed when configured");
    expect(summary).toContain("dispatch manifests + commit signing");
    expect(summary).not.toContain("dsse not yet");
  });

  it("uses implementation-agnostic work-item vocabulary", () => {
    expect(apas).toContain("workItemRef");
    expect(apas).not.toContain("beadRef");
  });

  it("keeps the homepage status in sync", () => {
    expect(home).toContain("APAS 0.2.1-draft");
    expect(home).not.toContain("DSSE signing coming");
  });
});
