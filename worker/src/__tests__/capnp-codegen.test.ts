/**
 * capnp-to-ts.ts fails loudly on what it cannot translate (notme-b96b4c).
 *
 * The generator is a small line parser for the subset of Cap'n Proto that
 * schema/identity.capnp uses. It used to translate anything else to
 * `unknown` / `z.unknown()` and exit 0, so a schema edit using Float64, a
 * group, an annotation or a generic would ship with "validation" that
 * accepts any value — type safety in name only. Unsupported input now stops
 * code generation with a message naming the construct.
 *
 * The first case doubles as the drift check: the committed gen/ts/identity.ts
 * must be exactly what the generator produces from the committed schema.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const ROOT = fileURLToPath(new URL("../../../", import.meta.url).href);
const TSX = join(ROOT, "node_modules/.bin/tsx");
const GENERATOR = join(ROOT, "schema/codegen/capnp-to-ts.ts");

function generate(source: string) {
  const dir = mkdtempSync(join(tmpdir(), "capnp-codegen-"));
  const file = join(dir, "test.capnp");
  writeFileSync(file, source);
  return spawnSync(TSX, [GENERATOR, file], { encoding: "utf8" });
}

const HEADER = `@0xb8e3f1a2c4d5e6f7;\nusing Go = import "/go.capnp";\n$Go.package("x");\n`;
const struct = (body: string) => `${HEADER}struct Thing {\n${body}\n}\n`;

describe("capnp-to-ts", () => {
  it("regenerates the committed gen/ts/identity.ts exactly (no drift)", () => {
    const r = spawnSync(TSX, [GENERATOR, join(ROOT, "schema/identity.capnp")], { encoding: "utf8" });
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toBe(readFileSync(join(ROOT, "gen/ts/identity.ts"), "utf8"));
  });

  it("accepts the supported subset, including file-level using and $annotations", () => {
    const r = generate(struct("  name @0 :Text;\n  tags @1 :List(Text);\n  n @2 :UInt32;"));
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).not.toContain("unknown");
  });

  const refused: Array<[string, string, RegExp]> = [
    ["a type it cannot map (Float64)", struct("  ratio @0 :Float64;"), /Float64.*Thing\.ratio/],
    ["a small integer (UInt8)", struct("  b @0 :UInt8;"), /UInt8.*Thing\.b/],
    ["AnyPointer", struct("  p @0 :AnyPointer;"), /AnyPointer.*Thing\.p/],
    ["a reference to an undefined type", struct("  x @0 :Nowhere;"), /Nowhere.*Thing\.x/],
    ["a field annotation", struct('  name @0 :Text $Go.name("n");'), /annotation.*Thing\.name/i],
    ["a group", struct("  g :group {\n    a @0 :Text;\n  }"), /unsupported.*group/i],
    ["a generic struct", `${HEADER}struct Box(T) {\n  v @0 :T;\n}\n`, /generic.*Box/i],
    ["an interface", `${HEADER}interface Svc {\n  call @0 () -> ();\n}\n`, /unsupported.*interface/i],
    ["an unrecognised line inside a struct", struct("  const k :Text = \"x\";"), /unsupported.*Thing/i],
  ];

  for (const [what, source, message] of refused) {
    it(`refuses ${what}, naming it, and emits nothing`, () => {
      const r = generate(source);
      expect(r.status).not.toBe(0);
      expect(r.stderr).toMatch(message);
      expect(r.stdout).toBe("");
    });
  }
});
