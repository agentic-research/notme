/**
 * dpop-nonce.test.ts — server-issued DPoP nonces (RFC 9449 §8/§9).
 *
 * The nonce exists to make proof freshness server-controlled instead of
 * client-clock-controlled, so the tests that matter are the ones proving a
 * client cannot manufacture or extend one: forged MAC, foreign secret,
 * expired timestamp, and timestamp tampering.
 */

import { describe, expect, it } from "vitest";
import {
  dpopNonceRequired,
  issueDpopNonce,
  NONCE_TTL_SECONDS,
  nonceHeaders,
  verifyDpopNonce,
} from "../auth/dpop-nonce";

const SECRET = "test-authority-session-secret-0123456789";
const OTHER_SECRET = "a-different-authority-secret-9876543210";

describe("issueDpopNonce / verifyDpopNonce", () => {
  it("round-trips a freshly issued nonce", async () => {
    const nonce = await issueDpopNonce(SECRET);
    expect(await verifyDpopNonce(nonce, SECRET)).toBe(true);
  });

  it("issues a distinct nonce per second", async () => {
    const now = 1_800_000_000;
    const a = await issueDpopNonce(SECRET, now);
    const b = await issueDpopNonce(SECRET, now + 1);
    expect(a).not.toBe(b);
    expect(await verifyDpopNonce(a, SECRET, now)).toBe(true);
    expect(await verifyDpopNonce(b, SECRET, now + 1)).toBe(true);
  });

  it("rejects a nonce minted under a different secret", async () => {
    // The whole point. If this passes, any deployment sharing the wire
    // format could mint nonces for any other.
    const nonce = await issueDpopNonce(OTHER_SECRET);
    expect(await verifyDpopNonce(nonce, SECRET)).toBe(false);
  });

  it("rejects a tampered timestamp", async () => {
    // The timestamp is inside the MAC, not merely alongside it — moving it
    // forward to extend the lifetime must invalidate the nonce rather than
    // producing a longer-lived valid one.
    const now = 1_800_000_000;
    const nonce = await issueDpopNonce(SECRET, now);
    const [, mac] = nonce.split(".");
    const extended = `${now + NONCE_TTL_SECONDS * 10}.${mac}`;
    expect(await verifyDpopNonce(extended, SECRET, now)).toBe(false);
  });

  it("rejects a tampered MAC", async () => {
    const now = 1_800_000_000;
    const nonce = await issueDpopNonce(SECRET, now);
    const [ts, mac] = nonce.split(".");
    // Flip one character; keep the length so this exercises MAC comparison
    // rather than the decode guard.
    const flipped = (mac[0] === "A" ? "B" : "A") + mac.slice(1);
    expect(await verifyDpopNonce(`${ts}.${flipped}`, SECRET, now)).toBe(false);
  });

  it("rejects a nonce past its TTL", async () => {
    const now = 1_800_000_000;
    const nonce = await issueDpopNonce(SECRET, now);
    expect(await verifyDpopNonce(nonce, SECRET, now + NONCE_TTL_SECONDS - 1))
      .toBe(true);
    expect(await verifyDpopNonce(nonce, SECRET, now + NONCE_TTL_SECONDS + 1))
      .toBe(false);
  });

  it("rejects a nonce dated beyond the future skew", async () => {
    // This server writes the timestamp, so a far-future one is either clock
    // chaos or forgery. Accepting it would silently extend the TTL.
    const now = 1_800_000_000;
    const nonce = await issueDpopNonce(SECRET, now + 600);
    expect(await verifyDpopNonce(nonce, SECRET, now)).toBe(false);
  });

  it("rejects malformed input without throwing", async () => {
    // These arrive from parsed client JSON, so the claim may be any type.
    // A throw here would surface as a 500 on the token endpoint.
    for (const bad of [
      undefined,
      null,
      42,
      {},
      [],
      "",
      ".",
      "no-separator",
      ".mac-only",
      "123.",
      "0x10.AAAA", // non-decimal timestamp
      " 123.AAAA", // leading whitespace Number() would tolerate
      "1e3.AAAA", // exponent form Number() would tolerate
      "99999999999999999999.AAAA", // beyond safe-integer range
    ]) {
      expect(await verifyDpopNonce(bad, SECRET)).toBe(false);
    }
  });
});

describe("nonceHeaders", () => {
  it("exposes DPoP-Nonce to cross-origin JS", async () => {
    // Without Access-Control-Expose-Headers, a browser client gets the 400
    // challenge but cannot READ the nonce it is told to retry with — the
    // header is simply absent from the Headers object — so it retries
    // without one and is challenged forever. Browsers are the entire
    // residual scope of the DPoP path (ADR-006), so this is the case that
    // matters, and the failure is invisible from the JS side.
    const nonce = await issueDpopNonce(SECRET);
    const headers = nonceHeaders(nonce);

    expect(headers["DPoP-Nonce"]).toBe(nonce);
    expect(headers["Access-Control-Expose-Headers"]).toBe("DPoP-Nonce");
  });

  it("names the header it exposes", () => {
    // Guards the rename footgun: changing the header name in one string and
    // not the other yields a response that looks correct server-side and is
    // unreadable client-side.
    const headers = nonceHeaders("v");
    const exposed = headers["Access-Control-Expose-Headers"]
      .split(",")
      .map((h) => h.trim());
    for (const name of Object.keys(headers)) {
      if (name.toLowerCase().startsWith("access-control")) continue;
      expect(exposed).toContain(name);
    }
  });
});

describe("dpopNonceRequired", () => {
  it("defaults to off", () => {
    // Off is the safe default: on rejects the first request of every client
    // that has never seen a challenge.
    expect(dpopNonceRequired({})).toBe(false);
    expect(dpopNonceRequired({ DPOP_REQUIRE_NONCE: undefined })).toBe(false);
  });

  it("accepts true/1 in any casing or padding", () => {
    for (const raw of ["true", "TRUE", " True ", "1", " 1 "]) {
      expect(dpopNonceRequired({ DPOP_REQUIRE_NONCE: raw })).toBe(true);
    }
  });

  it("treats an unparseable value as off, not on", () => {
    // A typo must not enable a rejection path. "yes"/"on" are the plausible
    // typos and are deliberately NOT accepted — one spelling, not five.
    for (const raw of ["false", "0", "", "yes", "on", "enabled", "maybe"]) {
      expect(dpopNonceRequired({ DPOP_REQUIRE_NONCE: raw })).toBe(false);
    }
  });
});
