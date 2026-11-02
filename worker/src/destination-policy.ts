// proxy() destination policy: cloud-metadata denylist (notme-bad2e5).
//
// Not an allowlist — anything not denied is permitted. Dependency-free and
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
