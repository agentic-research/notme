// gha-identity-outputs.test.ts — the reusable workflow may only advertise
// outputs the action actually emits.
//
// This exists because the workflow advertised `notme_token` and `expires_in`
// for weeks while action/ emitted neither (it emits a cert pair and
// `expires_at`). Both resolved to the empty string for every caller. Nothing
// caught it: the only caller is test-identity.yml, which is
// workflow_dispatch-only and asserts nothing, and it last ran green before
// the action's output shape changed.
//
// A reusable workflow's outputs are a PUBLIC INTERFACE — other repos wire
// them into `needs.<job>.outputs.<name>` — and an output that silently
// resolves to "" is worse than a missing one: the consumer's expression is
// valid, the job succeeds, and the caller proceeds with an empty credential.
// GitHub validates none of this, so it has to be checked here.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";
import { describe, expect, it } from "vitest";

function loadYaml(relPath: string): any {
  return parse(
    readFileSync(fileURLToPath(new URL(relPath, import.meta.url)), "utf8"),
  );
}

const workflow = loadYaml("../../../.github/workflows/gha-identity.yml");
const action = loadYaml("../../../action/action.yml");

// `on:` parses as the boolean true in YAML 1.1 unless quoted — GitHub accepts
// both, so read whichever key is present rather than assuming.
const on = workflow.on ?? workflow[true];
const workflowCallOutputs: Record<string, { value?: string }> =
  on.workflow_call.outputs;
const jobOutputs: Record<string, string> = workflow.jobs.exchange.outputs;
const actionOutputs = Object.keys(action.outputs);

describe("gha-identity.yml output contract", () => {
  it("every workflow_call output is wired to a job output", () => {
    for (const [name, spec] of Object.entries(workflowCallOutputs)) {
      // e.g. ${{ jobs.exchange.outputs.notme_cert }}
      const ref = spec.value?.match(/jobs\.exchange\.outputs\.(\w+)/)?.[1];
      expect(ref, `workflow output '${name}' does not reference a job output`)
        .toBeDefined();
      expect(
        Object.keys(jobOutputs),
        `workflow output '${name}' references job output '${ref}', which the job does not define`,
      ).toContain(ref!);
    }
  });

  it("every job output the action feeds is an output the action emits", () => {
    for (const [name, expr] of Object.entries(jobOutputs)) {
      const ref = expr.match(/steps\.signet\.outputs\.(\w+)/)?.[1];
      if (!ref) continue; // octo-sts and other steps are checked below
      expect(
        actionOutputs,
        `job output '${name}' reads steps.signet.outputs.${ref}, but action/action.yml emits none such — it would resolve to the empty string`,
      ).toContain(ref);
    }
  });

  it("action.yml declares NOTHING the action source fails to set", () => {
    // The converse of the assertion below, and the direction that was
    // missing: action.yml declared `github_token`, which src never sets —
    // the same always-empty-output defect as the notme_token bug this file
    // was written for, one file over. An external consumer wiring
    // steps.<id>.outputs.github_token would silently get "".
    const src = readFileSync(
      fileURLToPath(new URL("../../../action/src/index.ts", import.meta.url)),
      "utf8",
    );
    const setOutputs = new Set(
      [...src.matchAll(/core\.setOutput\(\s*["'](\w+)["']/g)].map((m) => m[1]!),
    );
    for (const declared of actionOutputs) {
      expect(
        setOutputs,
        `action.yml declares '${declared}' but action/src/index.ts never sets it — it would always resolve to the empty string`,
      ).toContain(declared);
    }
  });

  it("action.yml declares every output the action source sets", () => {
    const src = readFileSync(
      fileURLToPath(new URL("../../../action/src/index.ts", import.meta.url)),
      "utf8",
    );
    const setOutputs = [
      ...src.matchAll(/core\.setOutput\(\s*["'](\w+)["']/g),
    ].map((m) => m[1]!);
    expect(setOutputs.length).toBeGreaterThan(0);
    for (const name of setOutputs) {
      expect(
        actionOutputs,
        `action/src/index.ts sets '${name}' but action.yml does not declare it`,
      ).toContain(name);
    }
  });
});
