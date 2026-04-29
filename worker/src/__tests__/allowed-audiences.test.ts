/**
 * allowed-audiences.test.ts — getAllowedAudiences env override behavior.
 *
 * Closes notme-aefa94 L3. The set was hardcoded; resource-server config
 * for staging vs prod required a code change. Now it overrides via
 * env.ALLOWED_AUDIENCES (CSV) with a default fallback.
 */

import { describe, expect, it } from "vitest";
import { getAllowedAudiences } from "../allowed-audiences";

describe("getAllowedAudiences", () => {
  it("falls back to defaults when env.ALLOWED_AUDIENCES is missing", () => {
    const set = getAllowedAudiences({});
    expect(set.has("https://rosary.bot")).toBe(true);
    expect(set.has("https://notme.bot")).toBe(true);
    expect(set.has("https://auth.notme.bot")).toBe(true);
  });

  it("falls back to defaults when env.ALLOWED_AUDIENCES is empty", () => {
    const set = getAllowedAudiences({ ALLOWED_AUDIENCES: "" });
    expect(set.size).toBeGreaterThan(0);
    expect(set.has("https://rosary.bot")).toBe(true);
  });

  it("falls back to defaults when env.ALLOWED_AUDIENCES is whitespace-only", () => {
    const set = getAllowedAudiences({ ALLOWED_AUDIENCES: "   " });
    expect(set.has("https://rosary.bot")).toBe(true);
  });

  it("parses a single env value", () => {
    const set = getAllowedAudiences({ ALLOWED_AUDIENCES: "https://staging.example" });
    expect([...set]).toEqual(["https://staging.example"]);
    // Default values are NOT merged in — env fully replaces the default set.
    // The behavior is deliberate: an operator should declare exactly what
    // their deployment trusts, no implicit production audiences.
    expect(set.has("https://rosary.bot")).toBe(false);
  });

  it("parses CSV with whitespace tolerance", () => {
    const set = getAllowedAudiences({
      ALLOWED_AUDIENCES: "https://a.example, https://b.example ,https://c.example",
    });
    expect(set.size).toBe(3);
    expect(set.has("https://a.example")).toBe(true);
    expect(set.has("https://b.example")).toBe(true);
    expect(set.has("https://c.example")).toBe(true);
  });

  it("filters empty entries from sloppy CSV", () => {
    const set = getAllowedAudiences({
      ALLOWED_AUDIENCES: ",,https://a.example,,",
    });
    expect(set.size).toBe(1);
    expect(set.has("https://a.example")).toBe(true);
    expect(set.has("")).toBe(false);
  });
});
