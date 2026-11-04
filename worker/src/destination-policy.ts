// proxy() destination policy: cloud-metadata denylist (notme-bad2e5), then
// the configured allowlist at the bottom of this file (notme-baea8c), which
// is what decides: a destination must pass both. Dependency-free and
// importable without `cloudflare:workers` so it can be unit-tested directly.

// Cloud metadata endpoints — hard-denied, not configurable
export const DENIED_HOSTS = new Set([
  "169.254.169.254", // AWS/GCP metadata
  "metadata.google.internal", // GCP metadata
  "100.100.100.200", // Alibaba metadata
]);

/** Parse dotted-quad IPv4 into 4 bytes, or null. */
function parseIPv4(s: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const b = m.slice(1).map(Number);
  return b.every((n) => n <= 255) ? b : null;
}

/**
 * Parse an IPv6 literal (no brackets) into its 16 bytes, expanding `::`.
 * Accepts a trailing dotted-quad. Returns null if malformed.
 */
function parseIPv6(s: string): number[] | null {
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const toGroups = (part: string): number[] | null => {
    if (part === "") return [];
    const out: number[] = [];
    const toks = part.split(":");
    for (let i = 0; i < toks.length; i++) {
      const t = toks[i];
      if (i === toks.length - 1 && t.includes(".")) {
        const v4 = parseIPv4(t);
        if (!v4) return null;
        out.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
      } else if (/^[0-9a-f]{1,4}$/.test(t)) {
        out.push(parseInt(t, 16));
      } else {
        return null;
      }
    }
    return out;
  };
  const head = toGroups(halves[0]);
  const tail = halves.length === 2 ? toGroups(halves[1]) : [];
  if (!head || !tail) return null;
  let groups: number[];
  if (halves.length === 2) {
    const fill = 8 - head.length - tail.length;
    if (fill < 1) return null;
    groups = [...head, ...new Array<number>(fill).fill(0), ...tail];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;
  return groups.flatMap((g) => [g >> 8, g & 0xff]);
}

function isDeniedIPv4(b: number[]): boolean {
  if (b[0] === 169 && b[1] === 254) return true; // link-local 169.254.0.0/16
  return DENIED_HOSTS.has(b.join("."));
}

function isDeniedIPv6(b: number[]): boolean {
  if ((b[0] & 0xfe) === 0xfc) return true; // fc00::/7 unique-local
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return true; // fe80::/10 link-local
  // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d): judge the
  // embedded IPv4 by the IPv4 rules.
  const zeros10 = b.slice(0, 10).every((x) => x === 0);
  const mapped = zeros10 && b[10] === 0xff && b[11] === 0xff;
  const compat = zeros10 && b[10] === 0 && b[11] === 0;
  if (mapped || compat) return isDeniedIPv4(b.slice(12));
  return false;
}

export function isDeniedDestination(url: string): boolean {
  try {
    // WHATWG URL keeps IPv6 brackets in `hostname`; strip them.
    let host = new URL(url).hostname.toLowerCase();
    if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
    if (DENIED_HOSTS.has(host)) return true;
    if (host.includes(":")) {
      const bytes = parseIPv6(host);
      return bytes === null ? true : isDeniedIPv6(bytes); // malformed = denied
    }
    const v4 = parseIPv4(host);
    return v4 !== null && isDeniedIPv4(v4);
  } catch {
    return true; // unparseable URL = denied
  }
}

// ── Destination ALLOWLIST (notme-baea8c) ────────────────────────────────────
//
// ADR-009 promised proxy() an allowlist "configured at startup via
// environment variable" and shipped only the denylist above, so every host
// not on it was reachable. PROXY_ALLOWED_DESTINATIONS is that variable: a
// comma-separated list of hosts. UNSET OR EMPTY ALLOWS NOTHING — an authority
// that has not said where its agents may go sends them nowhere, as an unset
// GHA_ALLOWED_OWNERS trusts no one (notme-1532eb).
//
// An entry is an exact host (`api.github.com`) or `*.` plus a suffix
// (`*.notme.bot`), which matches strictly-deeper names and NOT the apex. It
// is compared with the URL's `host` — hostname plus any non-default port —
// so `api.github.com` does not admit `api.github.com:8443`; list
// `api.github.com:8443` to allow it. Only https is proxied. A bare `*`, or a
// `*` anywhere but the leading label, is not an entry: the first would turn
// the allowlist back into the denylist, the second has no agreed meaning.
// The denylist still runs first, so listing a metadata address does nothing.

/** Parse PROXY_ALLOWED_DESTINATIONS. Invalid entries are dropped, not guessed at. */
export function parseDestinationAllowlist(raw: unknown): Set<string> {
  const out = new Set<string>();
  if (typeof raw !== "string") return out;
  for (const part of raw.split(",")) {
    const entry = part.trim().toLowerCase();
    if (!entry) continue;
    const body = entry.startsWith("*.") ? entry.slice(2) : entry;
    if (!body || /[*/@\s]/.test(body)) continue;
    out.add(entry);
  }
  return out;
}

/** True only for an https URL whose host matches an allowlist entry. */
export function isAllowedDestination(url: string, allowlist: Set<string>): boolean {
  if (allowlist.size === 0) return false;
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  if (u.protocol !== "https:") return false;
  const host = u.host.toLowerCase();
  if (allowlist.has(host)) return true;
  for (const entry of allowlist) {
    // "*.notme.bot" → suffix ".notme.bot"; the host must be longer than the
    // suffix, so the apex "notme.bot" and a bare ".notme.bot" never match.
    if (entry.startsWith("*.")) {
      const suffix = entry.slice(1);
      if (host.length > suffix.length && host.endsWith(suffix)) return true;
    }
  }
  return false;
}
