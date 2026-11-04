/**
 * error-body-guard.test.ts — no route hands an exception's text to the
 * client (notme-b567c9).
 *
 * error-bodies.do.test.ts proves the property at the routes it can drive.
 * This is the guard for the rest. Every response constructor in worker.ts
 * and src/ — `jsonErr(`, `Response.json(`, `new Response(`, and the helper
 * itself, `opaqueError(` — has its argument list extracted (parens matched,
 * string literals and the static text of template literals dropped), and is
 * refused if it contains:
 *   - any `.message`, `.stack` or `["message"]` / `['message']`;
 *   - a TAINTED identifier: inside a `catch (x) { … }` block, `x` or a
 *     variable the block assigns from it (`const m = e.message` — one level
 *     of hoisting). That covers `${e}`, `String(e)`, `e.toString()`,
 *     `JSON.stringify(e)`, `(e as Error).message` and a hoisted `m`.
 * `opaqueError`'s second argument (the public message) must be a plain string
 * literal; its fourth (the logged detail) is the one place a caught value may
 * go.
 *
 * NOT CAUGHT, said plainly: taint that travels further than one assignment
 * (through a function call, a property, a second variable), or a caught value
 * renamed by destructuring. This is a tripwire for the shape the defect always
 * took, not a dataflow analysis.
 */
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const WORKER = new URL("../../", import.meta.url);
const SRC = new URL("../", import.meta.url);

function sources(): Array<{ file: string; text: string }> {
  const out = [{ file: "worker.ts", text: readFileSync(fileURLToPath(new URL("worker.ts", WORKER)), "utf8") }];
  const walk = (dir: URL, rel: string) => {
    for (const ent of readdirSync(fileURLToPath(dir), { withFileTypes: true })) {
      if (ent.isDirectory()) {
        if (ent.name === "__tests__") continue;
        walk(new URL(`${ent.name}/`, dir), `${rel}${ent.name}/`);
      } else if (ent.name.endsWith(".ts") && !ent.name.endsWith(".test.ts")) {
        out.push({ file: `src/${rel}${ent.name}`, text: readFileSync(fileURLToPath(new URL(ent.name, dir)), "utf8") });
      }
    }
  };
  walk(SRC, "");
  return out;
}

const SINKS = /\b(jsonErr|Response\.json|new Response|opaqueError)\s*\(/g;

/** The text between the `(` at `open` and its matching `)`, or null. */
function callArgs(src: string, open: number): string | null {
  let depth = 0;
  let quote: string | null = null;
  for (let i = open; i < src.length; i++) {
    const c = src[i]!;
    if (quote) {
      if (c === "\\") i++;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") quote = c;
    else if (c === "(") depth++;
    else if (c === ")" && --depth === 0) return src.slice(open + 1, i);
  }
  return null;
}

/**
 * Drop "..." and '...' literals entirely, and keep only the `${…}`
 * expressions of template literals — their static text is not code.
 */
function codeOnly(args: string): string {
  let out = "";
  for (let i = 0; i < args.length; i++) {
    const c = args[i]!;
    if (c === '"' || c === "'") {
      for (i++; i < args.length && args[i] !== c; i++) if (args[i] === "\\") i++;
      out += '""';
    } else if (c === "`") {
      out += '""';
      for (i++; i < args.length && args[i] !== "`"; i++) {
        if (args[i] === "\\") i++;
        else if (args[i] === "$" && args[i + 1] === "{") {
          let d = 0;
          let j = i + 1;
          for (; j < args.length; j++) {
            if (args[j] === "{") d++;
            else if (args[j] === "}" && --d === 0) break;
          }
          out += ` (${args.slice(i + 2, j)}) `;
          i = j;
        }
      }
    } else out += c;
  }
  return out;
}

/** Split top-level arguments on commas. */
function topLevelArgs(args: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let start = 0;
  for (let i = 0; i < args.length; i++) {
    const c = args[i]!;
    if (quote) {
      if (c === "\\") i++;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") quote = c;
    else if ("([{".includes(c)) depth++;
    else if (")]}".includes(c)) depth--;
    else if (c === "," && depth === 0) {
      parts.push(args.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(args.slice(start));
  return parts.map((p) => p.trim());
}

/** Index of the `}` matching the `{` at `open` (strings skipped), or -1. */
function blockEnd(src: string, open: number): number {
  let depth = 0;
  let quote: string | null = null;
  for (let i = open; i < src.length; i++) {
    const c = src[i]!;
    if (quote) {
      if (c === "\\") i++;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") quote = c;
    else if (c === "{") depth++;
    else if (c === "}" && --depth === 0) return i;
  }
  return -1;
}

type CatchScope = { start: number; end: number; names: Set<string> };

/**
 * Each `} catch (x) { … }` block — a try/catch, not a promise
 * `.catch(function …)` — with its tainted names: `x`, plus variables the
 * block assigns from it (one level). Scoped to the block, so an unrelated
 * variable that happens to share the name elsewhere is not tainted.
 */
function catchScopes(src: string): CatchScope[] {
  const ref = (n: string) => new RegExp(`(?<![.\\w$])${n}\\b`);
  const scopes: CatchScope[] = [];
  for (const m of src.matchAll(/\}\s*catch\s*\(\s*(\w+)[^)]*\)\s*\{/g)) {
    const start = m.index! + m[0].length - 1;
    const end = blockEnd(src, start);
    if (end < 0) continue;
    const names = new Set([m[1]!]);
    const body = src.slice(start, end);
    for (const a of body.matchAll(/\b(?:const|let|var)\s+(\w+)\s*(?::[^=;]+)?=([^;]*)/g)) {
      const rhs = codeOnly(a[2]!);
      if ([...names].some((n) => ref(n).test(rhs))) names.add(a[1]!);
    }
    scopes.push({ start, end, names });
  }
  return scopes;
}

const MEMBER = /\.\s*(message|stack)\b|\[\s*["'`](message|stack)["'`]\s*\]/;

/** Every leaking response constructor in `src`, as `line: snippet`. */
function leaks(src: string): string[] {
  const scopes = catchScopes(src);
  const hits: string[] = [];
  for (const m of src.matchAll(SINKS)) {
    // A declaration (`function jsonErr(…)`), not a call.
    if (/\bfunction\s+$/.test(src.slice(Math.max(0, m.index! - 12), m.index))) continue;
    const taint = new Set(
      scopes.filter((sc) => m.index! > sc.start && m.index! < sc.end).flatMap((sc) => [...sc.names]),
    );
    const open = m.index! + m[0].length - 1;
    const raw = callArgs(src, open);
    if (raw === null) continue;
    const line = src.slice(0, m.index).split("\n").length;
    const where = `${line}: ${(m[0] + raw).replace(/\s+/g, " ").slice(0, 110)}`;
    let checked = raw;
    if (m[1] === "opaqueError") {
      const args = topLevelArgs(raw);
      // The public message must be a plain literal; the detail (4th) is free.
      if (!/^"[^"\\]*"$/.test(args[1] ?? "")) {
        hits.push(where);
        continue;
      }
      checked = args.slice(0, 3).join(",");
    }
    const code = codeOnly(checked);
    if (MEMBER.test(code) || [...taint].some((n) => new RegExp(`(?<![.\\w$])${n}\\b`).test(code))) {
      hits.push(where);
    }
  }
  return hits;
}

describe("errors.no-exception-text-in-responses (notme-b567c9)", () => {
  it("no response body is built from an exception's message", () => {
    const hits: string[] = [];
    for (const { file, text } of sources()) for (const h of leaks(text)) hits.push(`${file}:${h}`);
    expect(hits).toEqual([]);
  });

  it("the guard itself matches the shapes it exists for", () => {
    // Without this a parser slip makes the test above vacuously green. Each
    // shape sits in a catch block, as it would in a route.
    const inCatch = (body: string) => `try { x(); } catch (e: any) {\n${body}\n}`;
    const shapes = [
      'return jsonErr("x: " + e.message, 500);',
      'return Response.json({ error: "x: " + e.message }, { status: 500 });',
      "return Response.json(\n  { error: `x: ${e?.message ?? \"unknown\"}` },\n  { status: 503 },\n);",
      "return jsonErr(`invalid token: ${e.message}`, 401);",
      'return opaqueError("tag", "bad: " + e.message, 400, e);',
      "return opaqueError(\"tag\", `bad: ${e}`, 400, e);",
      'return opaqueError("tag", msg, 400, e);',
      "return jsonErr(`x: ${e}`, 500);",
      'return jsonErr("x: " + (e as Error).message, 500);',
      'return Response.json({ error: JSON.stringify(e) }, { status: 500 });',
      'return jsonErr(e.stack, 500);',
      'return jsonErr("x: " + e.toString(), 500);',
      'return jsonErr("x: " + e["message"], 500);',
      'return jsonErr("x: " + String(e), 500);',
      'const m = e.message;\nreturn jsonErr(m, 500);',
      'return new Response(`failed: ${e}`, { status: 500 });',
    ];
    for (const s of shapes) expect(leaks(inCatch(s)), s).not.toEqual([]);
    // And what must pass: the detail logged, a constant body, the detail
    // passed only as opaqueError's logged argument, a literal that merely
    // contains the word "message".
    const clean = [
      'console.error("[x]", e.message);\nreturn jsonErr("x", 500);',
      'return opaqueError("tag", "invalid token", 401, e);',
      'return jsonErr("no message here: e.message is not code", 500);',
      "return Response.json({ error: `${pop.algorithm} proof-of-possession failed` }, { status: 401 });",
    ];
    for (const s of clean) expect(leaks(inCatch(s)), s).toEqual([]);
  });
});
