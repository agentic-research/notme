/**
 * invite-link-pages.test.ts — the public pages keep the invite token out of
 * request URLs (notme-3dfe15 part 2).
 *
 * The server half is in invite-join.do.test.ts (POST /invites hands back a
 * /join#t=<token> link). These pin the two pages that produce and consume
 * that link, because either could quietly put the token back into a query
 * string — which the Workers invocation log records.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const publicDir = fileURLToPath(new URL("../../public/", import.meta.url).href);
const invitePage = readFileSync(`${publicDir}/_invite.html`, "utf8");
const loginPage = readFileSync(`${publicDir}/_login.html`, "utf8");

describe("invite links carry the token in the fragment", () => {
  it("_invite.html shows the server's link and builds no query string of its own", () => {
    expect(invitePage).toMatch(/body\.url/);
    expect(invitePage).not.toMatch(/searchParams\.set/);
  });

  it("_login.html reads the invite token from location.hash", () => {
    expect(loginPage).toMatch(/location\.hash/);
  });

  // Review M3: a ?t= link is one whose token was already written to a log.
  // Honouring it kept that population usable from the page; the server has
  // never read it since part 2. A logged token can still be PASTED, which is
  // why liveInvite also kills any invite that outlives the 7-day ceiling.
  it("_login.html no longer accepts a legacy ?t= token", () => {
    expect(loginPage).not.toMatch(/urlParams\.get\(\s*['"]t['"]\s*\)/);
  });
});
