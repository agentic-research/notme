/**
 * join-nonce.test.ts — the /join challenge nonce (ADR-023 D2, notme-e3dede).
 *
 * The DPoP nonce construction, with its own domain and the MAC bound to the
 * invite: a challenge issued for one invite must not verify for another, a
 * DPoP nonce must not pass as a join nonce (or the reverse), and the
 * challenge audience must parse only under this deployment's authority URL.
 */
import { describe, expect, it } from "vitest";
import {
  JOIN_NONCE_TTL_SECONDS,
  issueJoinNonce,
  joinChallengeAudience,
  parseJoinChallengeAudience,
  plainAudienceAllowed,
  verifyJoinNonce,
} from "../auth/join-nonce";
import { issueDpopNonce, verifyDpopNonce } from "../auth/dpop-nonce";

const SECRET = "test-session-secret-0123456789abcdef";
const T = 1_800_000_000;
const AUTH = "https://auth.example.test";

describe("join nonce (ADR-023 D2)", () => {
  it("join.nonce.round-trip — verifies for the invite it was issued for", async () => {
    const n = await issueJoinNonce(SECRET, "invite-a", T);
    expect(await verifyJoinNonce(n, SECRET, "invite-a", T + 10)).toBe(true);
  });

  it("join.nonce.other-invite — does not verify for a different invite", async () => {
    const n = await issueJoinNonce(SECRET, "invite-a", T);
    expect(await verifyJoinNonce(n, SECRET, "invite-b", T + 10)).toBe(false);
  });

  it("join.nonce.expiry — valid at the TTL, refused one second after", async () => {
    const n = await issueJoinNonce(SECRET, "invite-a", T);
    expect(await verifyJoinNonce(n, SECRET, "invite-a", T + JOIN_NONCE_TTL_SECONDS)).toBe(true);
    expect(await verifyJoinNonce(n, SECRET, "invite-a", T + JOIN_NONCE_TTL_SECONDS + 1)).toBe(false);
  });

  it("join.nonce.future — refused when issued more than 5 s in the future", async () => {
    const n = await issueJoinNonce(SECRET, "invite-a", T + 6);
    expect(await verifyJoinNonce(n, SECRET, "invite-a", T)).toBe(false);
  });

  it("join.nonce.other-secret — refused under another deployment's secret", async () => {
    const n = await issueJoinNonce(SECRET, "invite-a", T);
    expect(await verifyJoinNonce(n, SECRET + "x", "invite-a", T)).toBe(false);
  });

  it("join.nonce.tampered — a changed timestamp or MAC is refused", async () => {
    const n = await issueJoinNonce(SECRET, "invite-a", T);
    const [ts, mac] = n.split(".") as [string, string];
    expect(await verifyJoinNonce(`${Number(ts) + 1}.${mac}`, SECRET, "invite-a", T)).toBe(false);
    const flipped = (mac[0] === "A" ? "B" : "A") + mac.slice(1);
    expect(await verifyJoinNonce(`${ts}.${flipped}`, SECRET, "invite-a", T)).toBe(false);
    for (const junk of [undefined, 42, "", ".", "abc", `${ts}.`, `x${ts}.${mac}`]) {
      expect(await verifyJoinNonce(junk, SECRET, "invite-a", T)).toBe(false);
    }
  });

  it("join.nonce.domain — a DPoP nonce is not a join nonce, and a join nonce is not a DPoP nonce", async () => {
    const dpop = await issueDpopNonce(SECRET, T);
    expect(await verifyJoinNonce(dpop, SECRET, "invite-a", T)).toBe(false);
    const join = await issueJoinNonce(SECRET, "invite-a", T);
    expect(await verifyDpopNonce(join, SECRET, T)).toBe(false);
    // Control: each verifies in its own domain.
    expect(await verifyDpopNonce(dpop, SECRET, T)).toBe(true);
  });
});

describe("challenge audience (ADR-023 D1)", () => {
  it("join.audience.round-trip — the audience is <authority>/join/<nonce> and parses back", async () => {
    const n = await issueJoinNonce(SECRET, "invite-a", T);
    const aud = joinChallengeAudience(AUTH, n);
    expect(aud).toBe(`${AUTH}/join/${n}`);
    expect(parseJoinChallengeAudience(aud, AUTH)).toBe(n);
    // A trailing slash on the configured URL does not change the audience.
    expect(joinChallengeAudience(`${AUTH}/`, n)).toBe(aud);
  });

  it("join.audience.other-deployment — another authority's challenge audience is not ours (F3)", async () => {
    const n = await issueJoinNonce(SECRET, "invite-a", T);
    expect(parseJoinChallengeAudience(joinChallengeAudience("https://staging.example.test", n), AUTH)).toBeNull();
  });

  it("join.audience.not-a-challenge — plain notme.bot, extra path, and non-strings are not challenges", () => {
    for (const aud of ["notme.bot", `${AUTH}/join/`, `${AUTH}/join/a/b`, `${AUTH}/joinx/a`, `${AUTH}/join/a?x=1`, 7, null, ["x"]]) {
      expect(parseJoinChallengeAudience(aud, AUTH)).toBeNull();
    }
  });
});

describe("plain notme.bot under JOIN_REQUIRE_NONCE (ADR-023 D5, D6)", () => {
  it("join.plain.policy — allowed while the flag is off; refused when on, except for Google", () => {
    expect(plainAudienceAllowed("https://token.actions.githubusercontent.com", false)).toBe(true);
    expect(plainAudienceAllowed("https://token.actions.githubusercontent.com", true)).toBe(false);
    expect(plainAudienceAllowed("https://auth.notme.bot", true)).toBe(false);
    // Google's audience is the deployment's client id; it cannot carry a nonce (D6).
    expect(plainAudienceAllowed("https://accounts.google.com", true)).toBe(true);
  });
});
