import { describe, expect, it } from "vitest";
import { isDeniedDestination } from "../destination-policy";

// proxy() destination policy (notme-bad2e5). WHATWG URL keeps IPv6 brackets in
// `hostname` and normalises IPv4-mapped literals to hex, so string-prefix
// checks silently miss them.
const DENIED = [
  "http://169.254.169.254/",
  "http://169.254.1.1/",
  "http://metadata.google.internal/",
  "http://100.100.100.200/",
  "http://[fd00:ec2::254]/",
  "http://[FD00:EC2::254]/",
  "http://[::ffff:169.254.169.254]/",
  "http://[::ffff:a9fe:a9fe]/",
  "http://[fe80::1]/",
  "http://[febf::1]/",
  "http://[fc00::1]/",
  "http://[fdff::1]/",
  "http://[::ffff:100.100.100.200]/",
  "http://[::169.254.169.254]/", // IPv4-compatible
  "not a url",
];
// [::1] (loopback) is allowed: it is not a cloud-metadata endpoint, and this
// policy is a metadata denylist, not an SSRF allowlist (see 009, "Not yet: no
// destination allowlist").
const ALLOWED = [
  "https://example.com/",
  "http://1.1.1.1/",
  "http://[2606:4700::1111]/",
  "http://[::1]/",
  "http://[2001:db8::1]/",
  "http://[fec0::1]/", // just outside fe80::/10
  "http://[fe00::1]/", // just outside fc00::/7
  "http://[::ffff:1.1.1.1]/",
  "http://169.253.1.1/",
];

describe("isDeniedDestination", () => {
  it.each(DENIED)("denies %s", (u) => {
    expect(isDeniedDestination(u)).toBe(true);
  });
  it.each(ALLOWED)("allows %s", (u) => {
    expect(isDeniedDestination(u)).toBe(false);
  });
});
