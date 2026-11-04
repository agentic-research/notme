/**
 * shards.ts — which CT log shard a certificate is submitted to (notme-afa9d8).
 *
 * An azul shard accepts only certificates whose notAfter falls in its
 * temporal interval [start_inclusive, end_exclusive), and a production shard
 * spans 3 to 12 months. With one configured shard, rolling to the next loses
 * certificates whichever instant the switch happens at. So the authority holds
 * a SET of shards and picks, per certificate, the one whose interval holds
 * that certificate's notAfter; a certificate no shard covers is never
 * submitted (it is backlogged, as for any other failure, and the drain picks
 * again by the same rule once the configuration covers it).
 *
 * Configuration, one of:
 *
 *   CT_LOG_SHARDS = JSON array (or an already-parsed array from a wrangler
 *   [vars] table) of
 *     { "path": "/logs/notme", "log_id": "<b64>", "key": "<b64 SPKI DER>",
 *       "temporal_interval": { "start_inclusive": "2026-07-01T00:00:00Z",
 *                              "end_exclusive":   "2027-07-01T00:00:00Z" } }
 *   — the same field names as azul's config.json (`temporal_interval`) and
 *   the log's metadata.json (`log_id`, `key`).
 *
 *   CT_LOG_ID / CT_LOG_KEY (/ CT_LOG_PATH): the single pin, unchanged. One
 *   shard with no interval: every certificate goes to it, as before.
 *
 * Both at once is an error, not a precedence rule: two sources for the one
 * value the pin exists to make unambiguous. Every error is a short reason that
 * becomes health.configError; nothing is submitted while it stands.
 *
 * Pure: no DO or Worker imports. Never throws.
 */
import { DEFAULT_CT_LOG_PATH } from "./log-client";
import { parseLogPin, type LogPin } from "./verify-sct";

export interface CtShard {
  /** Base path behind the CT_LOG binding, e.g. `/logs/notme`. */
  path: string;
  pin: LogPin;
  /** temporal_interval.start_inclusive, ms; -Infinity for the single pin. */
  startMs: number;
  /** temporal_interval.end_exclusive, ms; +Infinity for the single pin. */
  endMs: number;
}

export interface ShardEnv {
  CT_LOG_SHARDS?: string | unknown;
  CT_LOG_ID?: string;
  CT_LOG_KEY?: string;
  CT_LOG_PATH?: string;
}

/** A path segment azul names a log by; no trailing slash, no dot segments. */
const PATH_RE = /^(?:\/[A-Za-z0-9_-]+)+$/;
/** RFC 3339 in UTC only: a local offset would make the boundary ambiguous. */
const UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
/** More than this is a configuration mistake, not a shard plan. */
const MAX_SHARDS = 16;

export async function parseShards(
  env: ShardEnv,
): Promise<{ shards: CtShard[] } | { error: string }> {
  const raw = env.CT_LOG_SHARDS;
  if (raw === undefined || raw === "") {
    const pin = await parseLogPin(env.CT_LOG_ID, env.CT_LOG_KEY);
    if ("error" in pin) return pin;
    return {
      shards: [
        {
          path: env.CT_LOG_PATH || DEFAULT_CT_LOG_PATH,
          pin,
          startMs: Number.NEGATIVE_INFINITY,
          endMs: Number.POSITIVE_INFINITY,
        },
      ],
    };
  }
  const fail = (why: string) => ({ error: `CT_LOG_SHARDS: ${why}` });
  if (env.CT_LOG_ID || env.CT_LOG_KEY || env.CT_LOG_PATH) {
    return fail("set it or CT_LOG_ID / CT_LOG_KEY / CT_LOG_PATH, not both");
  }
  let list: unknown = raw;
  if (typeof raw === "string") {
    try {
      list = JSON.parse(raw);
    } catch {
      return fail("not JSON");
    }
  }
  if (!Array.isArray(list) || list.length === 0) return fail("must be a non-empty array");
  if (list.length > MAX_SHARDS) return fail(`more than ${MAX_SHARDS} shards`);

  const shards: CtShard[] = [];
  for (const [i, v] of list.entries()) {
    const at = (why: string) => fail(`[${i}] ${why}`);
    if (typeof v !== "object" || v === null) return at("is not an object");
    const o = v as Record<string, unknown>;
    if (typeof o.path !== "string" || !PATH_RE.test(o.path)) {
      return at("path must look like /logs/<name> (no trailing slash)");
    }
    const pin = await parseLogPin(
      typeof o.log_id === "string" ? o.log_id : undefined,
      typeof o.key === "string" ? o.key : undefined,
    );
    // parseLogPin names the single-pin variables; here they are log_id / key.
    if ("error" in pin) return at(`log_id / key: ${pin.error}`);
    const ti = o.temporal_interval as Record<string, unknown> | undefined;
    if (typeof ti !== "object" || ti === null) return at("temporal_interval missing");
    const time = (k: "start_inclusive" | "end_exclusive"): number | null =>
      typeof ti[k] === "string" && UTC_RE.test(ti[k]) ? Date.parse(ti[k]) : null;
    const startMs = time("start_inclusive");
    if (startMs === null || Number.isNaN(startMs)) {
      return at("temporal_interval.start_inclusive must be an RFC 3339 UTC time (…Z)");
    }
    const endMs = time("end_exclusive");
    if (endMs === null || Number.isNaN(endMs)) {
      return at("temporal_interval.end_exclusive must be an RFC 3339 UTC time (…Z)");
    }
    if (!(startMs < endMs)) return at("start_inclusive must be before end_exclusive");
    if (shards.some((s) => s.path === o.path)) return at(`path ${o.path} appears twice`);
    if (shards.some((s) => s.pin.id === pin.id)) return at("log_id appears twice");
    shards.push({ path: o.path, pin, startMs, endMs });
  }
  const sorted = [...shards].sort((a, b) => a.startMs - b.startMs);
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i]!.startMs < sorted[i - 1]!.endMs) {
      return fail(`${sorted[i - 1]!.path} and ${sorted[i]!.path} overlap`);
    }
  }
  return { shards: sorted };
}

/**
 * Alert threshold for the newest shard's close (notme-a806d0). 60 days because
 * rolling is several reviewed steps with lead time — add the shard to
 * config.notme.json, provision it (R2, KV, two secrets), deploy it, record its
 * key through review plus a release, then deploy notme through the canary
 * with both shards — and an alert read on a monthly operator review must
 * still leave a full cycle of slack. It is under azul's minimum production
 * shard span (3 months), so a newly added shard does not alert on arrival,
 * and over the 24 h longest tier TTL that is the hard deadline.
 */
export const SHARD_WARN_DAYS = 60;

const DAY_MS = 24 * 60 * 60 * 1000;

export interface ShardEndHealth {
  /** end_exclusive of the shard that ends LAST; null for the single pin. */
  shardEndsAt: string | null;
  /** Whole days until then, floored; zero or negative once it has closed. */
  shardEndsInDays: number | null;
  /** True inside SHARD_WARN_DAYS of that end, and after it. */
  shardClosingSoon: boolean;
}

/** When certificates stop having a shard to go to, measured from `nowMs`. */
export function shardEndHealth(shards: CtShard[], nowMs: number): ShardEndHealth {
  const end = Math.max(...shards.map((s) => s.endMs));
  if (!Number.isFinite(end)) {
    return { shardEndsAt: null, shardEndsInDays: null, shardClosingSoon: false };
  }
  return {
    shardEndsAt: new Date(end).toISOString(),
    shardEndsInDays: Math.floor((end - nowMs) / DAY_MS),
    shardClosingSoon: end - nowMs < SHARD_WARN_DAYS * DAY_MS,
  };
}

/** The shard whose [start, end) holds `notAfterMs`, or null. */
export function selectShard(shards: CtShard[], notAfterMs: number): CtShard | null {
  if (Number.isNaN(notAfterMs)) return null;
  return shards.find((s) => s.startMs <= notAfterMs && notAfterMs < s.endMs) ?? null;
}
