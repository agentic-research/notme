/**
 * error-body-guard.test.ts — no route hands an exception's text to the
 * client (notme-b567c9).
 *
 * error-bodies.do.test.ts proves the property at the routes it can drive.
 * This is the guard for the rest: the defect was always the same shape —
 * `jsonErr("… " + e.message, …)` or `Response.json({ error: … e.message })`
 * — so the source is scanned for an exception's `.message` / `String(e)`
 * inside a response constructor. A new instance fails here instead of in a
 * review. Logging the detail (`console.*`) is the intended home and is not
 * matched.
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

// A response constructor, then (within the same call, before its closing
// `;`) anything's `.message`, or `String(e)` of a caught value. Broad on
// purpose: no response here legitimately carries a `.message`.
const LEAK =
  /(?:jsonErr|Response\.json|new Response)\((?:(?!;\s*\n)[\s\S]){0,240}?(?:\b\w+\??\.message\b|String\((?:e|err|error|\w+Err)\))/g;

describe("errors.no-exception-text-in-responses (notme-b567c9)", () => {
  it("no response body is built from an exception's message", () => {
    const hits: string[] = [];
    for (const { file, text } of sources()) {
      for (const m of text.matchAll(LEAK)) {
        const line = text.slice(0, m.index).split("\n").length;
        hits.push(`${file}:${line}: ${m[0].replace(/\s+/g, " ").slice(0, 120)}`);
      }
    }
    expect(hits).toEqual([]);
  });

  it("the guard itself matches the shapes it exists for", () => {
    // Without this a regex typo makes the test above vacuously green.
    const shapes = [
      'return jsonErr("x: " + e.message, 500);',
      'return Response.json({ error: "x: " + e.message }, { status: 500 });',
      "return Response.json(\n  { error: `x: ${e?.message ?? \"unknown\"}` },\n  { status: 503 },\n);",
      'return jsonErr(`invalid token: ${e.message}`, 401);',
    ];
    for (const s of shapes) expect(s.match(LEAK), s).not.toBeNull();
    expect('console.error("[x]", e.message);\nreturn jsonErr("x", 500);'.match(LEAK)).toBeNull();
  });
});
