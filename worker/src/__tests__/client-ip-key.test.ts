/**
 * client-ip-key.test.ts — the bucket a source address is charged to before
 * the authority is asked anything (notme-ed6114, review F4).
 */
import { describe, expect, it } from "vitest";
import { clientIpBucket } from "../client-ip-key";

describe("clientIpBucket", () => {
  it("keeps an IPv4 address as is", () => {
    expect(clientIpBucket("203.0.113.9")).toBe("203.0.113.9");
  });

  it("charges an IPv6 address to its /64: one subscriber holds the whole prefix", () => {
    const a = clientIpBucket("2001:db8:1:2:aaaa:bbbb:cccc:dddd");
    const b = clientIpBucket("2001:0db8:0001:0002:0000:0000:0000:0001");
    const c = clientIpBucket("2001:db8:1:2::ffff");
    expect(a).toBe("2001:db8:1:2::/64");
    expect(b).toBe(a);
    expect(c).toBe(a);
  });

  it("different /64s are different buckets", () => {
    expect(clientIpBucket("2001:db8:1:3::1")).not.toBe(clientIpBucket("2001:db8:1:2::1"));
  });

  it("expands :: correctly wherever it falls", () => {
    expect(clientIpBucket("2001:db8::1")).toBe("2001:db8:0:0::/64");
    expect(clientIpBucket("::1")).toBe("0:0:0:0::/64");
    expect(clientIpBucket("fe80::")).toBe("fe80:0:0:0::/64");
  });

  it("an IPv4-mapped IPv6 address is its IPv4 address", () => {
    expect(clientIpBucket("::ffff:203.0.113.9")).toBe("203.0.113.9");
  });

  it("no address is its own bucket, not one shared with a literal 'unknown' string", () => {
    expect(clientIpBucket(null)).toBe("none");
    expect(clientIpBucket("")).toBe("none");
    expect(clientIpBucket("   ")).toBe("none");
  });

  it("a malformed value is kept verbatim rather than guessed at", () => {
    expect(clientIpBucket("not-an-ip")).toBe("raw:not-an-ip");
    expect(clientIpBucket("1:2:3")).toBe("raw:1:2:3");
  });
});
