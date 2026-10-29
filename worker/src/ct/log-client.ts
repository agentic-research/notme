/**
 * log-client.ts — a bounded, fail-open client for notme's Static CT log
 * (notme-1b46a8).
 *
 * Minting must never wait on, or fail because of, the log. Every failure mode
 * (timeout, network error, non-200, stalled body, unparseable SCT) collapses
 * to `null` / `false` and never throws, so the caller can mint without an SCT
 * and queue a backlog row. The deadline covers the fetch AND the body read.
 */
import type { SctResponse } from "./sct";

export const DEFAULT_CT_LOG_PATH = "/logs/notme";
export const DEFAULT_TIMEOUT_MS = 2000;

/** A service binding ignores the host; only the path routes. */
const BASE = "https://ct-log";
/** An SCT response is a few hundred bytes; refuse to buffer more than this. */
const MAX_BODY_BYTES = 64 * 1024;

const B64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/** Strict canonical base64 -> bytes, or null. */
function strictB64(v: unknown): Uint8Array | null {
  if (typeof v !== "string" || !B64_RE.test(v)) return null;
  try {
    return Uint8Array.from(atob(v), (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

/** Validate and return a normalised copy holding only the five fields. */
export function parseSct(v: unknown): SctResponse | null {
  if (typeof v !== "object" || v === null) return null;
  const o = v as Record<string, unknown>;
  if (o.sct_version !== 0) return null;
  const id = strictB64(o.id);
  if (!id || id.length !== 32) return null;
  const t = o.timestamp;
  if (typeof t !== "number" || !Number.isSafeInteger(t) || t < 0) return null;
  const ext = strictB64(o.extensions);
  if (!ext) return null;
  // DigitallySigned: hash alg(1) ‖ sig alg(1) ‖ uint16 length ‖ signature.
  const sig = strictB64(o.signature);
  if (!sig || sig.length < 4) return null;
  const declared = (sig[2] << 8) | sig[3];
  if (declared === 0 || declared !== sig.length - 4) return null;
  return {
    sct_version: 0,
    id: o.id as string,
    timestamp: t,
    extensions: o.extensions as string,
    signature: o.signature as string,
  };
}

/** Read a body to text, bounded in size; the reader is exposed for cancel. */
async function readText(
  body: ReadableStream<Uint8Array>,
  hold: { reader?: ReadableStreamDefaultReader<Uint8Array> },
): Promise<string | null> {
  const reader = (hold.reader = body.getReader());
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    all.set(c, at);
    at += c.length;
  }
  return new TextDecoder().decode(all);
}

/**
 * POST { chain } and return a validated SCT, or null on any failure. One
 * deadline bounds the fetch and the body read. The abort signal is passed to
 * fetch AND raced, so a binding that ignores abort cannot hold a mint, and a
 * late or stalled response is cancelled rather than left dangling.
 */
async function call(
  log: Fetcher,
  path: string,
  chainB64: string[],
  timeoutMs: number,
): Promise<SctResponse | null> {
  try {
    const ms = Number.isFinite(timeoutMs) ? Math.max(1, timeoutMs) : DEFAULT_TIMEOUT_MS;
    const signal = AbortSignal.timeout(ms);
    const hold: { res?: Response; reader?: ReadableStreamDefaultReader<Uint8Array> } = {};
    let expired = false;
    const cancelAll = () => {
      hold.reader?.cancel().catch(() => {});
      if (!hold.reader) hold.res?.body?.cancel().catch(() => {});
    };
    const deadline = new Promise<null>((resolve) =>
      signal.addEventListener(
        "abort",
        () => {
          expired = true;
          cancelAll();
          resolve(null);
        },
        { once: true },
      ),
    );
    const work = (async (): Promise<SctResponse | null> => {
      try {
        const res = await log.fetch(`${BASE}${path}`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ chain: chainB64 }),
          signal,
        });
        hold.res = res;
        if (expired || res.status !== 200 || !res.body) {
          await res.body?.cancel().catch(() => {});
          return null;
        }
        const text = await readText(res.body, hold);
        return text === null ? null : parseSct(JSON.parse(text));
      } catch {
        return null;
      }
    })();
    return await Promise.race([work, deadline]);
  } catch {
    return null;
  }
}

export async function submitPreChain(
  log: Fetcher,
  chainB64: string[],
  timeoutMs = DEFAULT_TIMEOUT_MS,
  pathPrefix = DEFAULT_CT_LOG_PATH,
): Promise<SctResponse | null> {
  return call(log, `${pathPrefix}/ct/v1/add-pre-chain`, chainB64, timeoutMs);
}

/** add-chain also returns an SCT; true only when a valid one comes back. */
export async function submitChain(
  log: Fetcher,
  chainB64: string[],
  timeoutMs = DEFAULT_TIMEOUT_MS,
  pathPrefix = DEFAULT_CT_LOG_PATH,
): Promise<boolean> {
  return (await call(log, `${pathPrefix}/ct/v1/add-chain`, chainB64, timeoutMs)) !== null;
}
