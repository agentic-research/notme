/**
 * bootstrap-policy.test.ts — the full decision matrix for attested first
 * boot (notme-addef9, criterion E).
 *
 * WHY A PURE PREDICATE HAS ITS OWN FILE. The DO reads
 * BOOTSTRAP_GHA_SUBJECT from its own env, which the workers pool fixes for
 * the whole run — so the UNCONFIGURED branch was unreachable from any
 * route-level test. A mutation making an unset variable mean "accept any
 * attested subject" passed all eight DO tests. Whatever a test cannot vary,
 * it cannot defend.
 */
import { describe, expect, it } from "vitest";
import {
  bootstrapAttestedSubject,
  mayBootstrapFromAttestation,
} from "../auth/bootstrap-policy";

const SUB = "repo:agentic-research/notme:ref:refs/heads/main";

describe("bootstrapAttestedSubject", () => {
  it("treats unset, empty and whitespace as UNCONFIGURED", () => {
    expect(bootstrapAttestedSubject({})).toBeNull();
    expect(bootstrapAttestedSubject({ BOOTSTRAP_GHA_SUBJECT: "" })).toBeNull();
    expect(bootstrapAttestedSubject({ BOOTSTRAP_GHA_SUBJECT: "   " })).toBeNull();
  });

  it("trims, so a copy-pasted value with a stray newline still works", () => {
    expect(bootstrapAttestedSubject({ BOOTSTRAP_GHA_SUBJECT: ` ${SUB}\n` })).toBe(SUB);
  });
});

describe("mayBootstrapFromAttestation — the whole matrix", () => {
  const base = {
    configuredSubject: SUB,
    subjectsMatch: true,
    authorityIsGovernable: false,
  };

  it("permits only the exact configured subject on an ungoverned authority", () => {
    expect(mayBootstrapFromAttestation(base)).toBe(true);
  });

  it("UNSET means OFF — never 'anyone the owner allowlist already admitted'", () => {
    // The mutation that survived eight DO tests: falling back to the attested
    // subject when nothing is configured. Any workflow under an allowlisted
    // owner would then become the administrator.
    expect(
      mayBootstrapFromAttestation({ ...base, configuredSubject: null }),
    ).toBe(false);
    // …and unset stays off even when everything else looks inviting.
    expect(
      mayBootstrapFromAttestation({
        configuredSubject: null,
        subjectsMatch: true,
        authorityIsGovernable: false,
      }),
    ).toBe(false);
  });

  it("refuses a subject that does not match", () => {
    expect(mayBootstrapFromAttestation({ ...base, subjectsMatch: false })).toBe(false);
  });

  it("refuses once the authority is governable — a one-time door", () => {
    expect(
      mayBootstrapFromAttestation({ ...base, authorityIsGovernable: true }),
    ).toBe(false);
  });

  it("requires ALL THREE — no two of them suffice", () => {
    const combos = [
      { configuredSubject: null, subjectsMatch: true, authorityIsGovernable: false },
      { configuredSubject: SUB, subjectsMatch: false, authorityIsGovernable: false },
      { configuredSubject: SUB, subjectsMatch: true, authorityIsGovernable: true },
      { configuredSubject: null, subjectsMatch: false, authorityIsGovernable: true },
    ];
    for (const c of combos) {
      expect(mayBootstrapFromAttestation(c), JSON.stringify(c)).toBe(false);
    }
  });
});
