/**
 * build-version.test.ts — the deployed Worker must be able to say WHICH BUILD
 * it is (notme-9f2f79, and signet's "no positive evidence" objection).
 *
 * THE PROBLEM THIS SOLVES, stated by a consumer rather than invented here:
 * signet observed that notme's deploys are manual, so "the tree doesn't settle
 * what's deployed — but there's no positive evidence it's fixed either." That
 * is exactly right, and it is unanswerable today: `/health` returns the string
 * `ok`, and nothing else the Worker serves is derived from the build. A
 * consumer waiting on a fix has no way to confirm it shipped except to ask.
 *
 * IT IS ALSO THE MISSING PIECE OF THE CANARY GATE. notme-9f2f79 records that
 * pre-promotion version targeting failed twice, silently reporting the OLD
 * version's behaviour. An earlier attempt to build a discriminator picked the
 * JWKS `kid` and failed for a structural reason worth restating: `kid` is
 * STORED DURABLE OBJECT STATE, not recomputed per deploy, so two different
 * builds serve the identical value and it cannot distinguish versions even in
 * principle. **The discriminator has to be derived from the BUILD, not from
 * data the build happens to read.**
 *
 * WHY "unknown" RATHER THAN OMITTING THE FIELD when the stamp is absent: this
 * repo has repeatedly shipped artifacts asserting properties of their own
 * provenance that nothing verified. A version endpoint that silently omits an
 * unset value invites the reader to assume the deploy predates stamping; one
 * that reports `"unknown"` states the truth — this build was not stamped, and
 * you cannot tell what it is from here.
 */

import { describe, expect, it } from "vitest";
import { buildInfo } from "../build-version";

describe("build version reporting (notme-9f2f79)", () => {
  it("reports the stamped commit when the build set one", () => {
    const sha = "a".repeat(40);
    expect(buildInfo({ BUILD_SHA: sha })).toEqual({
      commit: sha,
      stamped: true,
    });
  });

  it('reports "unknown" and stamped:false when nothing stamped the build', () => {
    // Fail honest. An absent stamp is a fact about the deploy, not a reason
    // to omit the field and let the reader guess.
    expect(buildInfo({})).toEqual({ commit: "unknown", stamped: false });
  });

  it("treats an empty or whitespace stamp as unstamped", () => {
    // `--var BUILD_SHA:` with an empty value is the shape a broken CI
    // substitution produces, and it must not read as a real build id.
    for (const v of ["", "   ", "\n"]) {
      expect(buildInfo({ BUILD_SHA: v }), `value ${JSON.stringify(v)}`).toEqual({
        commit: "unknown",
        stamped: false,
      });
    }
  });

  it("refuses a value that is not a full 40-char commit sha", () => {
    // A short sha is ambiguous across repos and grows collisions over time;
    // an arbitrary string means the stamping step did something unintended.
    // Either way, reporting it as a commit would be a claim the value does
    // not support.
    for (const v of ["abc123", "a".repeat(39), "a".repeat(41), "z".repeat(40)]) {
      expect(buildInfo({ BUILD_SHA: v }), `value ${v}`).toEqual({
        commit: "unknown",
        stamped: false,
      });
    }
  });

  it("accepts an uppercase sha, normalised to lowercase", () => {
    // git emits lowercase, but a CI expression could upcase it. The value is
    // the same commit; only its rendering differs, so normalise rather than
    // reject and force a consumer to case-fold before comparing.
    expect(buildInfo({ BUILD_SHA: "A".repeat(40) })).toEqual({
      commit: "a".repeat(40),
      stamped: true,
    });
  });
});
