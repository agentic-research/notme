/**
 * verify-chain.test.ts — the D5 namespace predicate, adversarially.
 *
 * identityExtends(parent, child) is the confinement rule ADR-019 D5 decided:
 * a child identity must SEGMENT-prefix-extend its parent's — RFC 3820's rule
 * on WIMSE URIs. Segments compare RAW (percent-encoded), never decoded:
 * decoding before comparison is how "%2F" becomes a path separator and a
 * string-prefix check becomes an escape hatch (the correlation-key lesson).
 */
import { describe, expect, it } from "vitest";
import { identityExtends } from "../auth/verify-chain";

const M = "wimse://notme.bot/passkey/alice";

describe("identityExtends — D5 prefix confinement", () => {
  it("accepts a strict segment extension", () => {
    expect(identityExtends(M, `${M}/task-1`)).toBe(true);
    expect(identityExtends(M, `${M}/task-1/step-2`)).toBe(true);
  });

  it("REJECTS equality — a task claiming to BE the machine is impersonation-shaped", () => {
    expect(identityExtends(M, M)).toBe(false);
  });

  it("REJECTS another principal's subtree", () => {
    expect(identityExtends(M, "wimse://notme.bot/passkey/bob/task-1")).toBe(false);
  });

  it("REJECTS a STRING prefix that is not a SEGMENT prefix", () => {
    // "alice-evil" starts with "alice" as a string; it is a different principal.
    expect(identityExtends(M, "wimse://notme.bot/passkey/alice-evil/task-1")).toBe(false);
  });

  it("REJECTS a different host or scheme — the trust domain is part of the name", () => {
    expect(identityExtends(M, "wimse://evil.example/passkey/alice/task-1")).toBe(false);
    expect(identityExtends(M, "https://notme.bot/passkey/alice/task-1")).toBe(false);
  });

  it("compares raw segments — percent-encoding does not create separators", () => {
    // An encoded slash inside one segment must NOT read as two segments.
    expect(
      identityExtends(M, "wimse://notme.bot/passkey/alice%2Ftask-1"),
    ).toBe(false);
    // And an encoded parent segment does not match its decoded form.
    expect(
      identityExtends("wimse://notme.bot/oidc%3Aissuer/alice", "wimse://notme.bot/oidc:issuer/alice/t"),
    ).toBe(false);
  });

  it("REJECTS empty and garbage inputs rather than guessing", () => {
    expect(identityExtends("", `${M}/t`)).toBe(false);
    expect(identityExtends(M, "")).toBe(false);
    expect(identityExtends("not a uri", "not a uri/more")).toBe(false);
    expect(identityExtends(M, `${M}//`)).toBe(false); // empty appended segment
  });
});
