/**
 * config-drift.ts — refuse to deploy while the live, gitignored
 * worker/wrangler.toml lags the committed worker/wrangler.toml.example
 * (notme-a3804c, overnight review H3).
 *
 * ── WHY ──
 * What `wrangler deploy` reads is worker/wrangler.toml. It carries real
 * resource ids, so it is gitignored and nobody reviews it; the template is
 * the only copy the tests and reviewers see. They drift: the 2026-11-04
 * review found production deploying at compatibility_date 2026-03-01 against
 * a tested 2026-10-19, with no [version_metadata], and a staging with no
 * REKOR_URL, where a revocation would land in the PUBLIC Rekor for good.
 * Nothing compared the two before a deploy. This does, and every task that
 * deploys or moves traffic depends on it (Taskfile.yml worker:config-drift).
 *
 * ── WHAT IT FAILS ON ──  (each listed, by NAME, in one report)
 *  1. compatibility_date older than the template's (or missing);
 *  2. [version_metadata] missing or a different binding, at top level or in
 *     [env.staging.version_metadata];
 *  3. a ratelimit binding the template declares (name AND namespace_id) that
 *     the live file lacks, in production and in staging;
 *  4. staging REKOR_URL that is not the template's (Sigstore's STAGING Rekor);
 *  5. a nodejs_compat / nodejs_compat_v2 entry in compatibility_flags: at
 *     this date both are defaults and workerd refuses the listing;
 *  6. any [env.staging.vars] key the template has and the live file lacks;
 *  7. no production [vars] SIGNET_AUTHORITY_URL (the public-Rekor guard in
 *     rekor-revocation.ts treats an unset authority as not production);
 *  8. an [observability] head_sampling_rate below the template's, production
 *     or staging: sampling drops whole invocations, console.* audit events
 *     included (unset is Cloudflare's default, 1).
 *
 * ── WHAT IT NEVER DOES ──
 * Print a VALUE from the live file. The report names keys only: [vars] may
 * hold things an operator considers sensitive, and a deploy log is not the
 * place to find out. (Values from the template are public and may appear.)
 * A parse error reports the line number, not the line.
 *
 * Live file absent (CI, a fresh clone): a message and exit 0 — CI builds its
 * config from the template (scripts/staging-config.ts), so there is nothing
 * to drift. STRICT=1 makes absence a failure.
 *
 * Usage: tsx scripts/config-drift.ts [--template <path>] [--live <path>]
 * Exit:  0 no drift, or live absent without STRICT=1 · 1 drift, parse error,
 *        or live absent with STRICT=1.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// ── a minimal TOML reader ──────────────────────────────────────────────────
//
// No TOML parser is a dependency of this repo, and the check must not grow
// one for a deploy gate. This reads the TOML that wrangler configs use:
// [tables], [[arrays of tables]], dotted and quoted keys, basic/literal and
// multi-line strings, numbers, booleans, dates (kept as strings), arrays and
// inline tables. Anything else is a parse error, which FAILS the check
// (closed) — and names only the line number.

export type TomlValue = string | number | boolean | TomlValue[] | TomlTable;
export interface TomlTable {
  [key: string]: TomlValue;
}

export class TomlError extends Error {}

export function parseToml(text: string): TomlTable {
  const root: TomlTable = {};
  let i = 0;
  let current: TomlTable = root;
  const line = () => text.slice(0, i).split("\n").length;
  const fail = (what: string): never => {
    throw new TomlError(`${what} at line ${line()}`);
  };

  const skipWs = () => {
    while (i < text.length && (text[i] === " " || text[i] === "\t")) i++;
  };
  const skipComment = () => {
    if (text[i] === "#") while (i < text.length && text[i] !== "\n") i++;
  };
  /** Whitespace, newlines and comments (inside arrays). */
  const skipAll = () => {
    for (;;) {
      skipWs();
      skipComment();
      if (text[i] === "\n" || text[i] === "\r") i++;
      else return;
    }
  };
  const endOfLine = () => {
    skipWs();
    skipComment();
    if (text[i] === "\r") i++;
    if (i < text.length && text[i] !== "\n") fail("unexpected content after a value");
  };

  const ESC: Record<string, string> = { b: "\b", t: "\t", n: "\n", f: "\f", r: "\r", '"': '"', "\\": "\\" };
  const basicString = (multi: boolean): string => {
    let out = "";
    if (multi && text[i] === "\n") i++;
    else if (multi && text.startsWith("\r\n", i)) i += 2;
    for (;;) {
      if (i >= text.length) fail("unterminated string");
      if (multi ? text.startsWith('"""', i) : text[i] === '"') {
        i += multi ? 3 : 1;
        // A multi-line string may end in up to two extra quotes.
        while (multi && text[i] === '"') {
          out += '"';
          i++;
        }
        return out;
      }
      const c = text[i]!;
      if (!multi && c === "\n") fail("newline in a string");
      if (c === "\\") {
        const n = text[i + 1]!;
        if (n in ESC) {
          out += ESC[n];
          i += 2;
        } else if (n === "u" || n === "U") {
          const len = n === "u" ? 4 : 8;
          const hex = text.slice(i + 2, i + 2 + len);
          if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length !== len) fail("bad unicode escape");
          out += String.fromCodePoint(parseInt(hex, 16));
          i += 2 + len;
        } else if (multi && /[ \t\r\n]/.test(n)) {
          // Line-ending backslash: trim the newline and following whitespace.
          i++;
          while (i < text.length && /[ \t\r\n]/.test(text[i]!)) i++;
        } else {
          fail("bad escape");
        }
        continue;
      }
      out += c;
      i++;
    }
  };
  const literalString = (multi: boolean): string => {
    if (multi && text[i] === "\n") i++;
    else if (multi && text.startsWith("\r\n", i)) i += 2;
    const close = multi ? "'''" : "'";
    const end = text.indexOf(close, i);
    if (end < 0) fail("unterminated string");
    let s = text.slice(i, end);
    if (!multi && s.includes("\n")) fail("newline in a string");
    i = end + close.length;
    while (multi && text[i] === "'") {
      s += "'";
      i++;
    }
    return s;
  };

  const key = (): string[] => {
    const parts: string[] = [];
    for (;;) {
      skipWs();
      if (text[i] === '"') {
        i++;
        parts.push(basicString(false));
      } else if (text[i] === "'") {
        i++;
        parts.push(literalString(false));
      } else {
        const m = /^[A-Za-z0-9_-]+/.exec(text.slice(i, i + 256));
        if (!m) fail("bad key");
        parts.push(m![0]);
        i += m![0].length;
      }
      skipWs();
      if (text[i] !== ".") return parts;
      i++;
    }
  };

  const value = (): TomlValue => {
    skipWs();
    const c = text[i];
    if (text.startsWith('"""', i)) {
      i += 3;
      return basicString(true);
    }
    if (c === '"') {
      i++;
      return basicString(false);
    }
    if (text.startsWith("'''", i)) {
      i += 3;
      return literalString(true);
    }
    if (c === "'") {
      i++;
      return literalString(false);
    }
    if (c === "[") {
      i++;
      const arr: TomlValue[] = [];
      for (;;) {
        skipAll();
        if (text[i] === "]") {
          i++;
          return arr;
        }
        arr.push(value());
        skipAll();
        if (text[i] === ",") i++;
        else if (text[i] !== "]") fail("bad array");
      }
    }
    if (c === "{") {
      i++;
      const tbl: TomlTable = {};
      skipWs();
      if (text[i] === "}") {
        i++;
        return tbl;
      }
      for (;;) {
        const k = key();
        if (text[i] !== "=") fail("expected =");
        i++;
        assign(tbl, k, value());
        skipWs();
        if (text[i] === ",") i++;
        else if (text[i] === "}") {
          i++;
          return tbl;
        } else fail("bad inline table");
      }
    }
    const m = /^[^\s,\]}#]+/.exec(text.slice(i, i + 256));
    if (!m) fail("bad value");
    const raw = m![0];
    i += raw.length;
    if (raw === "true") return true;
    if (raw === "false") return false;
    // Dates and times stay strings: the check compares dates as text.
    if (/^\d{4}-\d{2}-\d{2}/.test(raw)) {
      // A local date-time may carry a space before the time.
      const t = /^ \d{2}:\d{2}[^\s,\]}#]*/.exec(text.slice(i, i + 64));
      if (t) {
        i += t[0].length;
        return raw + t[0];
      }
      return raw;
    }
    const num = raw.replace(/_/g, "");
    if (/^[+-]?(0x[0-9a-fA-F]+|0o[0-7]+|0b[01]+|\d+(\.\d+)?([eE][+-]?\d+)?|inf|nan)$/.test(num)) {
      return Number(num);
    }
    return fail("bad value");
  };

  const assign = (tbl: TomlTable, path: string[], v: TomlValue) => {
    let t = tbl;
    for (const p of path.slice(0, -1)) {
      const next = t[p];
      if (next === undefined) t = t[p] = {};
      else if (typeof next === "object" && !Array.isArray(next)) t = next;
      else fail("key redefined");
    }
    const last = path[path.length - 1]!;
    if (last in t) fail("key redefined");
    t[last] = v;
  };

  /** Walk to a table header's table, creating it (and, for [[x]], a new element). */
  const openTable = (path: string[], arrayOfTables: boolean): TomlTable => {
    let t = root;
    for (let n = 0; n < path.length; n++) {
      const p = path[n]!;
      const lastPart = n === path.length - 1;
      let next = t[p];
      if (lastPart && arrayOfTables) {
        if (next === undefined) next = t[p] = [];
        if (!Array.isArray(next)) fail("not an array of tables");
        const el: TomlTable = {};
        (next as TomlValue[]).push(el);
        return el;
      }
      if (next === undefined) next = t[p] = {};
      // An intermediate [[x]] resolves to its LAST element, as TOML specifies.
      if (Array.isArray(next)) next = next[next.length - 1] as TomlValue;
      if (typeof next !== "object" || next === null || Array.isArray(next)) fail("not a table");
      t = next as TomlTable;
    }
    return t;
  };

  while (i < text.length) {
    skipAll();
    if (i >= text.length) break;
    if (text[i] === "[") {
      const aot = text[i + 1] === "[";
      i += aot ? 2 : 1;
      const path = key();
      if (text[i] !== "]" || (aot && text[i + 1] !== "]")) fail("bad table header");
      i += aot ? 2 : 1;
      current = openTable(path, aot);
      endOfLine();
      continue;
    }
    const k = key();
    if (text[i] !== "=") fail("expected =");
    i++;
    assign(current, k, value());
    endOfLine();
  }
  return root;
}

// ── the check ──────────────────────────────────────────────────────────────

const isTable = (v: TomlValue | undefined): v is TomlTable =>
  typeof v === "object" && v !== null && !Array.isArray(v);
const table = (v: TomlValue | undefined): TomlTable => (isTable(v) ? v : {});
const tables = (v: TomlValue | undefined): TomlTable[] =>
  Array.isArray(v) ? (v.filter(isTable) as TomlTable[]) : [];
const str = (v: TomlValue | undefined): string | null => (typeof v === "string" ? v : null);

/** Flags that are defaults at the template's date, and that workerd refuses when listed (notme-430ad1). */
export const REFUSED_FLAGS = ["nodejs_compat", "nodejs_compat_v2"];

/**
 * Every way `live` lags `template`, as messages that name keys and never a
 * live value. Empty when there is no drift.
 */
export function configDrift(template: TomlTable, live: TomlTable): string[] {
  const out: string[] = [];
  const tEnvStaging = table(table(template.env).staging);
  const lEnvStaging = table(table(live.env).staging);

  // 1. compatibility_date. ISO dates compare correctly as text.
  const tDate = str(template.compatibility_date);
  const lDate = str(live.compatibility_date);
  if (tDate !== null) {
    if (lDate === null) out.push(`compatibility_date: missing (template: ${tDate})`);
    else if (!/^\d{4}-\d{2}-\d{2}$/.test(lDate)) out.push("compatibility_date: not a YYYY-MM-DD date");
    else if (lDate < tDate) out.push(`compatibility_date: older than the template's (${tDate})`);
  }
  // An environment may not override the date in the template's design; a
  // stale override in live would take effect for staging, so check it too.
  const lStagingDate = str(lEnvStaging.compatibility_date);
  if (tDate !== null && lStagingDate !== null && lStagingDate < tDate) {
    out.push(`env.staging.compatibility_date: older than the template's (${tDate})`);
  }

  // 2. version_metadata, top level and staging (bindings are not inherited).
  for (const [where, t, l] of [
    ["version_metadata", template.version_metadata, live.version_metadata],
    ["env.staging.version_metadata", tEnvStaging.version_metadata, lEnvStaging.version_metadata],
  ] as const) {
    const want = str(table(t).binding);
    if (want === null) continue;
    if (!isTable(l)) out.push(`${where}: missing (template binds ${want})`);
    else if (str(l.binding) !== want) out.push(`${where}.binding: not ${want}`);
  }

  // 3. ratelimits: every binding the template declares, by name and namespace.
  for (const [where, t, l] of [
    ["ratelimits", template.ratelimits, live.ratelimits],
    ["env.staging.ratelimits", tEnvStaging.ratelimits, lEnvStaging.ratelimits],
  ] as const) {
    const liveByName = new Map<string, TomlTable>();
    for (const r of tables(l)) {
      const n = str(r.name);
      if (n !== null) liveByName.set(n, r);
    }
    for (const r of tables(t)) {
      const name = str(r.name);
      if (name === null) continue;
      const got = liveByName.get(name);
      if (!got) {
        out.push(`${where}: ${name} missing`);
        continue;
      }
      // namespace_id may be a string or a number; compare as text.
      if (r.namespace_id !== undefined && String(got.namespace_id) !== String(r.namespace_id)) {
        out.push(`${where}: ${name} namespace_id differs from the template's (${String(r.namespace_id)})`);
      }
    }
  }

  // 4. staging REKOR_URL: the staging Rekor, never the public one by default.
  const tVars = table(tEnvStaging.vars);
  const lVars = table(lEnvStaging.vars);
  const tRekor = str(tVars.REKOR_URL);
  if (tRekor !== null) {
    const lRekor = str(lVars.REKOR_URL);
    const norm = (u: string) => u.trim().replace(/\/+$/, "");
    if (lRekor === null) out.push(`env.staging.vars.REKOR_URL: missing (want ${tRekor})`);
    else if (norm(lRekor) !== norm(tRekor)) out.push(`env.staging.vars.REKOR_URL: not ${tRekor}`);
  }

  // 5. refused compatibility flags, anywhere they can be declared.
  for (const [where, flags] of [
    ["compatibility_flags", live.compatibility_flags],
    ["env.staging.compatibility_flags", lEnvStaging.compatibility_flags],
  ] as const) {
    if (!Array.isArray(flags)) continue;
    for (const f of REFUSED_FLAGS) {
      if (flags.includes(f)) out.push(`${where}: lists ${f} (a default at this date; workerd refuses it)`);
    }
  }

  // 6. staging vars the template declares and live lacks. REKOR_URL is
  // reported once, above.
  for (const k of Object.keys(tVars)) {
    if (k === "REKOR_URL") continue;
    if (!(k in lVars)) out.push(`env.staging.vars.${k}: missing`);
  }

  // 7. production SIGNET_AUTHORITY_URL. The authority surface is selected
  // from it, and the public-Rekor guard (rekor-revocation.ts) refuses an
  // authority whose URL is unset, so production without it would keep every
  // revocation pending.
  if ("SIGNET_AUTHORITY_URL" in table(template.vars) && !("SIGNET_AUTHORITY_URL" in table(live.vars))) {
    out.push("vars.SIGNET_AUTHORITY_URL: missing");
  }

  // 8. head_sampling_rate: never below the template's. Unset means 1.
  for (const [where, t, l] of [
    ["observability.head_sampling_rate", table(template.observability), table(live.observability)],
    ["env.staging.observability.head_sampling_rate", table(tEnvStaging.observability), table(lEnvStaging.observability)],
  ] as const) {
    const want = t.head_sampling_rate;
    if (typeof want !== "number") continue;
    const got = l.head_sampling_rate === undefined ? 1 : l.head_sampling_rate;
    if (typeof got !== "number" || got < want) out.push(`${where}: below the template's (${want})`);
    // wrangler also accepts the rate under [observability.logs], for logs
    // alone; a lower one there drops the same events.
    const logs = table(l.logs).head_sampling_rate;
    if (logs !== undefined && (typeof logs !== "number" || logs < want)) {
      out.push(`${where.replace(/head_sampling_rate$/, "logs.head_sampling_rate")}: below the template's (${want})`);
    }
  }

  return out;
}

// ── CLI ────────────────────────────────────────────────────────────────────

export interface RunResult {
  code: 0 | 1;
  lines: string[];
}

export function run(opts: { template: string; live: string; strict: boolean }): RunResult {
  if (!existsSync(opts.live)) {
    const msg = `config-drift: ${opts.live} not present — nothing to compare`;
    return opts.strict
      ? { code: 1, lines: [`${msg}, and STRICT=1 requires it`] }
      : { code: 0, lines: [`${msg}; skipped (CI builds its config from the template). STRICT=1 to require it.`] };
  }
  let template: TomlTable;
  let live: TomlTable;
  try {
    template = parseToml(readFileSync(opts.template, "utf8"));
  } catch (err) {
    return { code: 1, lines: [`config-drift: cannot parse the template: ${(err as Error).message}`] };
  }
  try {
    live = parseToml(readFileSync(opts.live, "utf8"));
  } catch (err) {
    // TomlError messages carry a line number only, never the line.
    const why = err instanceof TomlError ? err.message : "unreadable";
    return { code: 1, lines: [`config-drift: cannot parse ${opts.live}: ${why}`] };
  }
  const drift = configDrift(template, live);
  if (drift.length === 0) {
    return { code: 0, lines: [`config-drift: ${opts.live} is in line with ${opts.template}`] };
  }
  return {
    code: 1,
    lines: [
      `config-drift: ${opts.live} lags ${opts.template} (${drift.length}):`,
      ...drift.map((d) => `  - ${d}`),
      "Bring the live file in line with the template, then deploy. Values are never printed; compare by hand.",
    ],
  };
}

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
  const argv = process.argv.slice(2);
  const flag = (name: string, dflt: string) => {
    const n = argv.indexOf(name);
    return n >= 0 && argv[n + 1] ? argv[n + 1]! : dflt;
  };
  const r = run({
    template: flag("--template", join(repo, "worker", "wrangler.toml.example")),
    live: flag("--live", join(repo, "worker", "wrangler.toml")),
    strict: process.env.STRICT === "1",
  });
  for (const l of r.lines) (r.code === 0 ? console.log : console.error)(l);
  process.exit(r.code);
}
