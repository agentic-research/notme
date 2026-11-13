/**
 * staging-config.ts — build the staging deploy config from the committed
 * template, with EVERY staging var supplied by the operator and no placeholder
 * left standing (notme-6ae724, review H1).
 *
 * ── WHY ──
 * The live worker/wrangler.toml is gitignored, so CI (staging-smoke.yml) has
 * to rebuild it from worker/wrangler.toml.example. `wrangler deploy` makes the
 * config's [vars] authoritative — there is no keep_vars — so whatever this
 * file says is what staging runs with after every merge. The first version of
 * that workflow filled in only the KV id, which would have reset staging to
 * `GHA_ALLOWED_OWNERS = "your-staging-org"`: a GitHub org name anyone can
 * register, whose workflows could then mint certificates under the staging CA.
 *
 * ── THE RULES ──
 *  1. Every key in [env.staging.vars] is REQUIRED from the environment as
 *     STAGING_<KEY>. The list is read from the template, so a var added there
 *     later cannot ride through on its template value.
 *  2. The staging KV id comes from STAGING_KV_NAMESPACE_ID.
 *  3. After substitution, nothing in any [env.staging…] table may still look
 *     like a placeholder (`your-…`, `<…>`, `REPLACE-ME`). Fails closed.
 * Production tables are left untouched: `--env staging` never reads them.
 *
 * Values are written as TOML basic strings via JSON.stringify — no sed, so an
 * id containing `|` or `&` cannot rewrite the program.
 *
 * Usage: tsx scripts/staging-config.ts <template> <out>
 */
import { readFileSync, writeFileSync } from "node:fs";

export const PLACEHOLDER = /your-|<[^>]*>|REPLACE-ME/i;
const KV_PLACEHOLDER = "<your-staging-kv-namespace-id>";

/** Which table a header line opens, e.g. `[[env.staging.routes]]` → `env.staging.routes`. */
function tableOf(line: string): string | null {
  const m = line.match(/^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*(#.*)?$/);
  return m ? m[1] : null;
}

const isStaging = (t: string | null) => t !== null && (t === "env.staging" || t.startsWith("env.staging."));

/** The keys declared in [env.staging.vars], in template order. */
export function stagingVarKeys(template: string): string[] {
  const keys: string[] = [];
  let table: string | null = null;
  for (const line of template.split("\n")) {
    table = tableOf(line) ?? table;
    if (table !== "env.staging.vars") continue;
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=/);
    if (m) keys.push(m[1]);
  }
  return keys;
}

/** Lines of the generated config that still look like placeholders, within staging tables only. */
export function stagingPlaceholders(config: string): string[] {
  const hits: string[] = [];
  let table: string | null = null;
  for (const line of config.split("\n")) {
    const t = tableOf(line);
    if (t !== null) {
      table = t;
      continue;
    }
    if (!isStaging(table)) continue;
    const code = line.replace(/#.*$/, ""); // comments may mention placeholders
    if (code.trim() && PLACEHOLDER.test(code)) hits.push(`[${table}] ${line.trim()}`);
  }
  return hits;
}

/** Host part of a route pattern: `auth.notme.bot/*` → `auth.notme.bot`. */
const routeHost = (pattern: string) => pattern.replace(/^https?:\/\//, "").split("/")[0].toLowerCase();

/** `pattern = "…"` values of every table named exactly `name`. */
function patternsIn(config: string, name: string): string[] {
  const out: string[] = [];
  let table: string | null = null;
  for (const line of config.split("\n")) {
    table = tableOf(line) ?? table;
    if (table !== name) continue;
    const m = line.match(/^\s*pattern\s*=\s*"([^"]*)"/);
    if (m) out.push(m[1]);
  }
  return out;
}

/**
 * wrangler INHERITS top-level `routes` into an environment that declares none
 * (re-review N7). Drop the staging routes from the template and a staging
 * deploy would try to claim notme.bot/* and auth.notme.bot/* — and the
 * placeholder scan would not notice, because those values are not
 * placeholders. So staging must declare its own routes, and none may be a
 * production host or a wildcard that could cover one.
 */
export function stagingRouteProblems(config: string): string[] {
  const staging = patternsIn(config, "env.staging.routes");
  const production = new Set(["notme.bot", "auth.notme.bot", ...patternsIn(config, "routes").map(routeHost)]);
  const problems: string[] = [];
  if (staging.length === 0) problems.push("[env.staging] declares no routes, so it would inherit production's");
  for (const p of staging) {
    const host = routeHost(p);
    if (production.has(host)) problems.push(`staging route "${p}" is a production host`);
    if (host.includes("*")) problems.push(`staging route "${p}" is a wildcard, which can cover production hosts`);
  }
  return problems;
}

export function renderStagingConfig(template: string, env: Record<string, string | undefined>): string {
  const keys = stagingVarKeys(template);
  if (keys.length === 0) throw new Error("template has no [env.staging.vars] — refusing to guess");
  const missing = keys.map((k) => `STAGING_${k}`).filter((n) => !env[n]?.trim());
  if (!env.STAGING_KV_NAMESPACE_ID?.trim()) missing.push("STAGING_KV_NAMESPACE_ID");
  if (missing.length) {
    throw new Error(`missing staging environment vars: ${missing.join(", ")} (set them on the GitHub 'staging' environment)`);
  }

  let table: string | null = null;
  const out = template.split("\n").map((line) => {
    table = tableOf(line) ?? table;
    if (table === "env.staging.vars") {
      const m = line.match(/^(\s*)([A-Z0-9_]+)(\s*=\s*).*$/);
      if (m) return `${m[1]}${m[2]}${m[3]}${JSON.stringify(env[`STAGING_${m[2]}`]!.trim())}`;
    }
    if (isStaging(table) && line.includes(KV_PLACEHOLDER)) {
      // A replacer FUNCTION: a replacement STRING would expand `$&`, `` $` ``
      // and `$'` inside the value (re-review N4).
      return line.replace(`"${KV_PLACEHOLDER}"`, () => JSON.stringify(env.STAGING_KV_NAMESPACE_ID!.trim()));
    }
    return line;
  });
  const config = out.join("\n");

  const routeProblems = stagingRouteProblems(config);
  if (routeProblems.length) {
    throw new Error(`staging routes are unsafe — refusing to deploy:\n  ${routeProblems.join("\n  ")}`);
  }

  const left = stagingPlaceholders(config);
  if (left.length) {
    throw new Error(`placeholders remain in the staging config — refusing to deploy:\n  ${left.join("\n  ")}`);
  }
  return config;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [template, out] = process.argv.slice(2);
  if (!template || !out) {
    console.error("usage: tsx scripts/staging-config.ts <template> <out>");
    process.exit(2);
  }
  try {
    writeFileSync(out, renderStagingConfig(readFileSync(template, "utf8"), process.env));
    console.log(`staging config written to ${out} (${stagingVarKeys(readFileSync(template, "utf8")).length} vars from the environment, no placeholders)`);
  } catch (e) {
    console.error(`✗ ${(e as Error).message}`);
    process.exit(1);
  }
}
