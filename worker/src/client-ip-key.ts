/**
 * The bucket a source address is charged to by an IP-keyed rate limit
 * (notme-ed6114, review F4). Pure, so it is unit-testable.
 *
 * - IPv4: the address. CGNAT and office NAT put many people behind one,
 *   which is the availability cost recorded in THREAT_MODEL §4.
 * - IPv6: the /64. A subscriber is routinely handed a whole /64, so per-/128
 *   keying gave one attacker about 2^64 buckets — no limit at all.
 * - IPv4-mapped IPv6: its IPv4 address.
 * - No address: "none". Behind Cloudflare the header is always set; it is
 *   absent for a service binding or a self-hosted workerd. They share one
 *   bucket of their own, rather than one with a literal "unknown" value.
 * - Anything unparseable: "raw:" + the value, kept verbatim, never guessed
 *   into some other caller's bucket.
 */
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const HEXTET = /^[0-9a-f]{1,4}$/;

export function clientIpBucket(ip: string | null | undefined): string {
  const v = (ip ?? "").trim().toLowerCase();
  if (!v) return "none";
  if (IPV4.test(v)) return v;
  if (!v.includes(":")) return `raw:${v}`;

  const mapped = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(v);
  if (mapped) return mapped[1]!;

  const halves = v.split("::");
  if (halves.length > 2) return `raw:${v}`;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  let hextets: string[];
  if (halves.length === 2) {
    const fill = 8 - head.length - tail.length;
    if (fill < 1) return `raw:${v}`;
    hextets = [...head, ...Array(fill).fill("0"), ...tail];
  } else {
    hextets = head;
  }
  if (hextets.length !== 8 || !hextets.every((h) => HEXTET.test(h))) return `raw:${v}`;
  return `${hextets.slice(0, 4).map((h) => parseInt(h, 16).toString(16)).join(":")}::/64`;
}

/**
 * The NETWORK a source address belongs to, for a cap on rows held per source
 * rather than on requests per second (notme-a36d10, review H1): IPv4 by its
 * /24, IPv6 by its /48. Coarser than clientIpBucket on purpose: a cap one
 * host can multiply by renting neighbouring addresses (on IPv6, 65,536 /64s
 * out of one /48) is no cap. The cost is that hosts sharing a /24 share the
 * allowance, which a per-source cap set well above one operator's in-flight
 * needs absorbs.
 *
 * "none" and "raw:" buckets pass through unchanged, as in clientIpBucket.
 */
export function clientNetworkBucket(ip: string | null | undefined): string {
  const b = clientIpBucket(ip);
  const v4 = IPV4.exec(b);
  if (v4) return `${v4[1]}.${v4[2]}.${v4[3]}.0/24`;
  if (b.endsWith("::/64")) return `${b.split(":").slice(0, 3).join(":")}::/48`;
  return b;
}
