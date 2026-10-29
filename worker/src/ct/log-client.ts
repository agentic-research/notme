/**
 * log-client.ts — a bounded, fail-open client for notme's Static CT log
 * (notme-1b46a8).
 *
 * Minting must never wait on, or fail because of, the log. Every failure mode
 * (timeout, network error, non-200, unparseable body) collapses to `null` /
 * `false` and never throws, so the caller can mint without an SCT and queue a
 * backlog row.
 */
import type { SctResponse } from "./sct";

export const DEFAULT_CT_LOG_PATH = "/logs/notme";
export const DEFAULT_TIMEOUT_MS = 2000;

/** A service binding ignores the host; only the path routes. */
const BASE = "https://ct-log";

const isB64 = (v: unknown): v is string => {
  if (typeof v !== "string") return false;
  try {
    atob(v);
    return true;
  } catch {
    return false;
  }
};

function isSctResponse(v: unknown): v is SctResponse {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    o.sct_version === 0 &&
    isB64(o.id) &&
    atob(o.id).length === 32 &&
    typeof o.timestamp === "number" &&
    Number.isFinite(o.timestamp) &&
    isB64(o.extensions) &&
    isB64(o.signature)
  );
}

/** POST { chain }; resolves to the 200 Response, or null on any failure. */
async function post(
  log: Fetcher,
  path: string,
  chainB64: string[],
  timeoutMs: number,
): Promise<Response | null> {
  const signal = AbortSignal.timeout(timeoutMs);
  // Race the signal too: a binding that ignores abort must not hold the mint.
  const aborted = new Promise<null>((resolve) =>
    signal.addEventListener("abort", () => resolve(null), { once: true }),
  );
  const request = (async () => {
    try {
      const res = await log.fetch(`${BASE}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ chain: chainB64 }),
        signal,
      });
      return res.status === 200 ? res : null;
    } catch {
      return null;
    }
  })();
  return Promise.race([request, aborted]);
}

export async function submitPreChain(
  log: Fetcher,
  chainB64: string[],
  timeoutMs = DEFAULT_TIMEOUT_MS,
  pathPrefix = DEFAULT_CT_LOG_PATH,
): Promise<SctResponse | null> {
  const res = await post(log, `${pathPrefix}/ct/v1/add-pre-chain`, chainB64, timeoutMs);
  if (!res) return null;
  try {
    const body: unknown = await res.json();
    return isSctResponse(body) ? body : null;
  } catch {
    return null;
  }
}

export async function submitChain(
  log: Fetcher,
  chainB64: string[],
  timeoutMs = DEFAULT_TIMEOUT_MS,
  pathPrefix = DEFAULT_CT_LOG_PATH,
): Promise<boolean> {
  return (await post(log, `${pathPrefix}/ct/v1/add-chain`, chainB64, timeoutMs)) !== null;
}
