/**
 * gitignore-secrets.test.ts — local-secret files must never be committable.
 *
 * `.gitignore` re-includes whole subtrees with negations like `!worker/**`,
 * and git applies the LAST matching rule. So a broad negation silently opts
 * secret files back in, which is what had happened: `worker/.dev.vars` —
 * wrangler's standard LOCAL SECRETS file, exactly where an operator is told to
 * put things that must never be committed — resolved to
 *
 *     .gitignore:74:!worker/**   worker/.dev.vars
 *
 * along with .env, *.pem and *.key anywhere under worker/, vault/, action/ and
 * packages/. Found by cloister while looking for somewhere to put
 * DELEGATED_JWT_ISSUERS; they declined to write the file rather than commit a
 * secret into this tree.
 *
 * A comment in .gitignore saying "keep this last" is not a control — the next
 * negation appended below it wins silently and nothing complains. This asserts
 * the property instead of the convention.
 *
 * Runs `git check-ignore`, so it tests what git ACTUALLY does with the real
 * file, not a reimplementation of its precedence rules.
 */

import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";

const REPO = new URL("../../..", import.meta.url).pathname;

function isIgnored(path: string): boolean {
  try {
    execFileSync("git", ["check-ignore", "-q", path], {
      cwd: REPO,
      stdio: "ignore",
    });
    return true;
  } catch {
    return false;
  }
}

describe("secret files are not committable", () => {
  // Every subtree a negation re-includes. Adding a negation without adding
  // its paths here is the gap this closes.
  const SECRET_PATHS = [
    "worker/.dev.vars",
    "worker/.dev.vars.local",
    "worker/.env",
    "worker/.env.local",
    "worker/key.pem",
    "worker/ca.key",
    "worker/src/leaked.pem",
    "vault/.dev.vars",
    "vault/.env",
    "action/.env",
    "action/private.key",
    "packages/dpop/.env",
    ".dev.vars",
    ".env.local",
  ];

  for (const p of SECRET_PATHS) {
    it(`ignores ${p}`, () => {
      expect(
        isIgnored(p),
        `${p} is COMMITTABLE. A negation in .gitignore has re-included it — ` +
          `git applies the last matching rule, so the secrets block must stay ` +
          `at the end of the file.`,
      ).toBe(true);
    });
  }
});

describe("the secrets block did not over-reach", () => {
  // The failure mode in the other direction: a rule broad enough to catch
  // secrets silently drops real sources, and nothing notices until something
  // is missing from a build.
  const MUST_BE_TRACKED = [
    "worker/worker.ts",
    "worker/src/signing-authority.ts",
    "docs/design/015-delegated-jwt-signing.md",
    "packages/melange.rsa.pub", // .pub, not .key — signing verification, public
    "gen/ts/identity.ts",
    "worker/wrangler.toml.example",
  ];

  for (const p of MUST_BE_TRACKED) {
    it(`still tracks ${p}`, () => {
      expect(
        isIgnored(p),
        `${p} became ignored — a secrets rule is too broad.`,
      ).toBe(false);
    });
  }
});
