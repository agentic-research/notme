#!/usr/bin/env node
/**
 * capnp-to-ts.ts — Generate TypeScript types + Zod schemas from .capnp files.
 *
 * Reads a Cap'n Proto schema and emits:
 *   1. TypeScript interfaces (for type-safe code)
 *   2. Zod schemas (for runtime validation of untrusted input)
 *
 * Usage: npx tsx schema/codegen/capnp-to-ts.ts schema/identity.capnp > gen/ts/identity.ts
 *
 * This is a lightweight parser — handles the subset of Cap'n Proto we actually use:
 *   struct, enum, union, List(T), Text, Data, Bool, UInt32, UInt64, Int64
 * plus the file id, `using` imports and file-level `$annotations`, which it
 * ignores (they configure other generators, e.g. Go's package name).
 *
 * ANYTHING ELSE IS AN ERROR (notme-b96b4c). This used to translate what it
 * did not understand to `unknown` / `z.unknown()` and exit 0, so a schema
 * edit using Float64, a group, a field annotation or a generic shipped with a
 * Zod schema that accepted any value. It now stops, naming the construct, and
 * emits nothing. To support a new construct, add it here deliberately (or
 * move to a real capnp toolchain) rather than relaxing the check.
 */

import { readFileSync } from "fs";

interface Field {
  name: string;
  index: number;
  type: string;
  comment?: string;
}

interface Struct {
  name: string;
  fields: Field[];
  unionFields?: Field[];
}

interface Enum {
  name: string;
  values: { name: string; index: number }[];
}

// Map capnp types to TS + Zod
const TYPE_MAP: Record<string, { ts: string; zod: string }> = {
  Text: { ts: "string", zod: "z.string()" },
  Data: { ts: "Uint8Array", zod: "z.instanceof(Uint8Array)" },
  Bool: { ts: "boolean", zod: "z.boolean()" },
  UInt32: { ts: "number", zod: "z.number().int().nonnegative()" },
  UInt64: { ts: "number", zod: "z.number().int().nonnegative()" },
  Int64: { ts: "number", zod: "z.number().int()" },
};

class UnsupportedSchema extends Error {}

const unsupported = (what: string, line: number): never => {
  throw new UnsupportedSchema(
    `capnp-to-ts: unsupported ${what} (line ${line}). ` +
      `Supported: struct, enum, union, List(T), ${Object.keys(TYPE_MAP).join(", ")}, ` +
      "references to structs and enums in the same file.",
  );
};

function parseCapnp(source: string): { structs: Struct[]; enums: Enum[] } {
  const structs: Struct[] = [];
  const enums: Enum[] = [];
  const lines = source.split("\n");

  let current: Struct | null = null;
  let currentEnum: Enum | null = null;
  let inUnion = false;
  let braceDepth = 0;

  for (const [i, rawLine] of lines.entries()) {
    const n = i + 1;
    // Comments carry no structure; drop them before anything inspects the line.
    const line = rawLine.replace(/#.*$/, "").trim();
    const comment = rawLine.includes("#") ? rawLine.slice(rawLine.indexOf("#") + 1).trim() : undefined;
    if (!line) continue;

    // Top level: only the file id, imports, file annotations, struct and enum.
    if (!current && !currentEnum) {
      if (/^@0x[0-9a-fA-F]+\s*;$/.test(line)) continue;
      if (/^using\s+\w+\s*=\s*import\s+"[^"]+"\s*;$/.test(line)) continue;
      if (/^\$[\w.]+\(.*\)\s*;$/.test(line)) continue;
      if (/^struct\s+\w+\s*\(/.test(line)) unsupported(`generic struct ${line.match(/^struct\s+(\w+)/)![1]}`, n);
      if (!/^(struct|enum)\s+\w+\s*\{?$/.test(line)) {
        unsupported(`top-level construct "${line.split(/\s+/)[0]}" (${line.split(/\s+/)[0] === "interface" ? "interface" : "unrecognised"})`, n);
      }
    }

    // Track brace depth
    if (line.includes("{")) braceDepth++;
    if (line.includes("}")) {
      braceDepth--;
      if (braceDepth <= 0 && current) {
        structs.push(current);
        current = null;
        inUnion = false;
      }
      if (braceDepth <= 0 && currentEnum) {
        enums.push(currentEnum);
        currentEnum = null;
      }
      continue;
    }

    // Struct definition
    const structMatch = line.match(/^struct\s+(\w+)\s*\{?/);
    if (structMatch && !current) {
      current = { name: structMatch[1], fields: [] };
      braceDepth = line.includes("{") ? 1 : 0;
      continue;
    }

    // Enum definition
    const enumMatch = line.match(/^enum\s+(\w+)\s*\{?/);
    if (enumMatch) {
      currentEnum = { name: enumMatch[1], values: [] };
      braceDepth = line.includes("{") ? 1 : 0;
      continue;
    }

    // Enum value
    if (currentEnum) {
      const valMatch = line.match(/^(\w+)\s+@(\d+)\s*;/);
      if (valMatch) {
        currentEnum.values.push({
          name: valMatch[1],
          index: parseInt(valMatch[2]),
        });
      }
      continue;
    }

    // Union start
    if (current && line === "union {") {
      inUnion = true;
      current.unionFields = [];
      continue;
    }

    // Field in struct or union
    if (current) {
      if (/:\s*group\b/.test(line)) unsupported(`group in ${current.name}`, n);
      const fieldMatch = line.match(/^(\w+)\s+@(\d+)\s*:\s*(.+?)\s*;$/);
      if (!fieldMatch) unsupported(`line in struct ${current.name}: "${line}"`, n);
      if (fieldMatch) {
        if (fieldMatch[3].includes("$")) {
          unsupported(`field annotation on ${current.name}.${fieldMatch[1]}`, n);
        }
        const field: Field = {
          name: fieldMatch[1],
          index: parseInt(fieldMatch[2]),
          type: fieldMatch[3].trim(),
          comment,
        };
        if (inUnion && current.unionFields) {
          current.unionFields.push(field);
        } else {
          current.fields.push(field);
        }
      }
    }
  }

  return { structs, enums };
}

function resolveType(
  capnpType: string,
  enums: Enum[],
  structs: Struct[],
  where = "",
): { ts: string; zod: string } {
  // Direct type mapping
  if (TYPE_MAP[capnpType]) return TYPE_MAP[capnpType];

  // List(T)
  const listMatch = capnpType.match(/^List\((\w+)\)$/);
  if (listMatch) {
    const inner = resolveType(listMatch[1], enums, structs, where);
    return {
      ts: `${inner.ts}[]`,
      zod: `z.array(${inner.zod})`,
    };
  }

  // Enum reference
  if (enums.find((e) => e.name === capnpType)) {
    return {
      ts: capnpType,
      zod: `${capnpType}Schema`,
    };
  }

  // Struct reference
  if (structs.find((s) => s.name === capnpType)) {
    return {
      ts: capnpType,
      zod: `${capnpType}Schema`,
    };
  }

  // No silent fallback: an unmapped type would emit z.unknown(), which
  // validates nothing.
  throw new UnsupportedSchema(
    `capnp-to-ts: unsupported type ${capnpType}${where ? ` in ${where}` : ""}. ` +
      `Supported: ${Object.keys(TYPE_MAP).join(", ")}, List(T), and structs/enums defined in the same file.`,
  );
}

// Topological sort: emit structs that are referenced before structs that reference them
function topoSort(structs: Struct[]): Struct[] {
  const structNames = new Set(structs.map((s) => s.name));
  const deps = new Map<string, Set<string>>();

  for (const s of structs) {
    const d = new Set<string>();
    for (const f of [...s.fields, ...(s.unionFields ?? [])]) {
      const listMatch = f.type.match(/^List\((\w+)\)$/);
      const refName = listMatch ? listMatch[1] : f.type;
      if (structNames.has(refName) && refName !== s.name) d.add(refName);
    }
    deps.set(s.name, d);
  }

  const sorted: Struct[] = [];
  const visited = new Set<string>();

  function visit(name: string) {
    if (visited.has(name)) return;
    visited.add(name);
    for (const dep of deps.get(name) ?? []) visit(dep);
    const s = structs.find((x) => x.name === name);
    if (s) sorted.push(s);
  }

  for (const s of structs) visit(s.name);
  return sorted;
}

function generateTS(
  structs: Struct[],
  enums: Enum[],
): string {
  const sortedStructs = topoSort(structs);
  const lines: string[] = [
    "// AUTO-GENERATED from schema/identity.capnp — do not edit manually.",
    '// Run: npx tsx schema/codegen/capnp-to-ts.ts schema/identity.capnp',
    "",
    'import { z } from "zod";',
    "",
  ];

  // Enums
  for (const e of enums) {
    // TS enum
    lines.push(`export enum ${e.name} {`);
    for (const v of e.values) {
      lines.push(`  ${v.name} = "${v.name}",`);
    }
    lines.push("}");
    lines.push("");

    // Zod schema
    lines.push(
      `export const ${e.name}Schema = z.nativeEnum(${e.name});`,
    );
    lines.push("");
  }

  // Structs (topologically sorted — dependencies emitted first)
  for (const s of sortedStructs) {
    // TS interface
    lines.push(`export interface ${s.name} {`);
    for (const f of s.fields) {
      const { ts } = resolveType(f.type, enums, structs, `${s.name}.${f.name}`);
      const comment = f.comment ? ` // ${f.comment}` : "";
      lines.push(`  ${f.name}: ${ts};${comment}`);
    }
    if (s.unionFields) {
      lines.push("  // union — exactly one field is set");
      for (const f of s.unionFields) {
        const { ts } = resolveType(f.type, enums, structs, `${s.name}.${f.name}`);
        lines.push(`  ${f.name}?: ${ts};`);
      }
    }
    lines.push("}");
    lines.push("");

    // Zod schema
    lines.push(`export const ${s.name}Schema: z.ZodType<${s.name}> = z.object({`);
    for (const f of s.fields) {
      const { zod } = resolveType(f.type, enums, structs, `${s.name}.${f.name}`);
      lines.push(`  ${f.name}: ${zod},`);
    }
    if (s.unionFields) {
      for (const f of s.unionFields) {
        const { zod } = resolveType(f.type, enums, structs, `${s.name}.${f.name}`);
        lines.push(`  ${f.name}: ${zod}.optional(),`);
      }
    }
    lines.push("}) as any;");
    lines.push("");
  }

  return lines.join("\n");
}

// Main
const inputFile = process.argv[2];
if (!inputFile) {
  console.error("Usage: npx tsx schema/codegen/capnp-to-ts.ts <file.capnp>");
  process.exit(1);
}

const source = readFileSync(inputFile, "utf-8");
try {
  // Generate fully before printing anything, so a refusal emits no partial file.
  const { structs, enums } = parseCapnp(source);
  console.log(generateTS(structs, enums));
} catch (e) {
  if (!(e instanceof UnsupportedSchema)) throw e;
  console.error(e.message);
  process.exit(1);
}
