/**
 * kek-entropy.test.ts — the KEK entropy floor ADR-007 specifies and the code
 * never enforced (notme-bed754 audit).
 *
 * WHAT WAS SPECIFIED. `docs/design/007-secretless-local-proxy.md:169`:
 *
 *   "If keyStorage === 'encrypted', validate that NOTME_KEK_SECRET is at least
 *    32 hex characters (128 bits of entropy). If it is shorter, REFUSE TO
 *    START with: FATAL: NOTME_KEK_SECRET must be at least 128 bits (32 hex
 *    chars)."
 *
 * `007-secretless-plan.md:149` even specified this test — "accepts valid KEK
 * secret (32+ hex chars)". Both the rule and its test were written down and
 * neither shipped.
 *
 * WHY IT MATTERS MORE THAN A MISSING VALIDATION USUALLY WOULD. The KEK seals
 * the CA master key at rest. `deriveKek` refuses only an EMPTY secret, so
 * `NOTME_KEK_SECRET=weak` derives a perfectly usable AES-GCM key and the
 * authority boots reporting encrypted storage. An operator who set a
 * four-character secret gets the *appearance* of sealing with none of the
 * strength — and PBKDF2 over a four-character input is brute-forceable
 * offline by anyone who obtains the ciphertext.
 *
 * That makes this the inverse of every other finding in this audit: the
 * document is RIGHT and the implementation regressed. Everywhere else the code
 * was correct and the docs overclaimed.
 *
 * THE FLOOR IS ON LENGTH, NOT ON CONTENT. A secret is rejected for being too
 * short, never for "looking weak" — an entropy heuristic over an operator's
 * passphrase is a guess, and one that rejects a legitimate high-entropy secret
 * is worse than no check, because the operator's fix is to pick a WORSE secret
 * that happens to satisfy the heuristic.
 */

import { describe, expect, it } from "vitest";
import { validateKeyStorageConfig } from "../platform";

const OK = "a".repeat(32);

describe("KEK entropy floor (ADR-007 §169)", () => {
  it("refuses a secret shorter than 32 characters", () => {
    // The case that boots today: four characters, sealing the CA master key.
    expect(() => validateKeyStorageConfig("encrypted", "weak")).toThrow(
      /at least 128 bits/i,
    );
  });

  it("refuses one character short — the boundary, not a vibe", () => {
    expect(() =>
      validateKeyStorageConfig("encrypted", "a".repeat(31)),
    ).toThrow(/at least 128 bits/i);
  });

  it("accepts exactly 32", () => {
    expect(() => validateKeyStorageConfig("encrypted", OK)).not.toThrow();
  });

  it("accepts longer than 32", () => {
    expect(() =>
      validateKeyStorageConfig("encrypted", "a".repeat(64)),
    ).not.toThrow();
  });

  it("does not count surrounding whitespace toward the floor", () => {
    // `wrangler secret put` from a file or a shell heredoc trivially picks up
    // a trailing newline. Counting it would let a 31-char secret pass because
    // of an invisible character, which is the least debuggable way to fail
    // an entropy check.
    expect(() =>
      validateKeyStorageConfig("encrypted", "  " + "a".repeat(30) + "\n"),
    ).toThrow(/at least 128 bits/i);
  });

  it("still refuses an unset secret, with the ORIGINAL message", () => {
    // The pre-existing check must survive. Its message names a different fix
    // (set the secret, or change the mode) than the length one (pick a longer
    // secret), and collapsing them would misdirect the operator.
    expect(() => validateKeyStorageConfig("encrypted")).toThrow(
      /NOTME_KEK_SECRET is unset/,
    );
  });

  it("leaves non-encrypted modes alone", () => {
    // ephemeral and cf-managed do not use a KEK at all. Rejecting a short
    // secret there would brick a local dev boot over a value nothing reads —
    // the exact failure the comment above validateKeyStorageConfig records
    // from the previous over-eager throw.
    for (const mode of ["ephemeral", "cf-managed"] as const) {
      expect(() => validateKeyStorageConfig(mode, "weak")).not.toThrow();
      expect(() => validateKeyStorageConfig(mode)).not.toThrow();
    }
  });
});
