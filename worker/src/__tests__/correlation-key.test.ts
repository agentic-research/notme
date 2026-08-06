/**
 * correlation-key.test.ts — the delegation-shaped correlation key
 * (notme-9f84e6).
 *
 * The key answers "show me everything that happened under X" by PREFIX MATCH,
 * for X at any level of the delegation chain:
 *
 *   <principal>              every machine session and task that principal ever had
 *   <principal>/<bridge>     one machine session
 *   <principal>/<bridge>/<task>  one task
 *
 * SHAPE PER THE FORMAL REVIEW. An earlier proposal keyed this on certificate
 * SERIALS (`<root-kid>/<bridge-serial>/<task-serial>`) and was unsound:
 * serials name certificate INSTANCES, so a renewal forks the subtree and
 * "everything under this machine" silently splits. The principal URI is
 * stable across rotation, so it goes at the top. And `mintBridgeCertPair`
 * issues TWO certs with two independent serials, so no single serial names
 * "the bridge" at all — the pair is already identified by
 * `binding = SHA-256(P-256 SPKI || Ed25519 SPKI)`, which is what belongs in
 * the middle.
 *
 * ── THE PART THE REVIEW DID NOT COVER, AND WHY THESE TESTS EXIST ──
 * `<principal>/<bridge>/<task>` is not directly implementable as written,
 * because the principal is a WIMSE URI that ALREADY CONTAINS SLASHES
 * (`wimse://notme.bot/passkey/<uuid>`). Joining on "/" therefore produces a
 * key whose structure cannot be recovered and whose prefixes do not line up
 * with delegation levels. Two distinct failures follow, and both are tested
 * below:
 *
 *   1. PHANTOM LEVELS — the principal's own slashes read as extra levels, so
 *      a prefix query for "one machine session" can match a substring of a
 *      principal URI instead.
 *   2. STRING-PREFIX IS NOT SEGMENT-PREFIX — "a/b" is a string prefix of
 *      "a/bb", so a query for principal `wimse://x/a` would match principal
 *      `wimse://x/ab`. This is the same class of defect as the identity-URI
 *      parsing hazard already documented in gen/go/verify/identity.go.
 *
 * Both are silent and both over-match, which for a correlation key means
 * attributing one principal's activity to another. That is why the encoding
 * is asserted here rather than left to the caller.
 */

import { describe, expect, it } from "vitest";
import {
  correlationKey,
  correlationPrefix,
  parseCorrelationKey,
} from "../auth/correlation-key";

const ALICE = "wimse://notme.bot/passkey/11111111-1111-1111-1111-111111111111";
const BOB = "wimse://notme.bot/passkey/22222222-2222-2222-2222-222222222222";
const BINDING_A = "a".repeat(64);
const BINDING_B = "b".repeat(64);

describe("correlation key (notme-9f84e6)", () => {
  it("nests: each level's prefix contains the level below it", () => {
    const principal = correlationPrefix({ principal: ALICE });
    const bridge = correlationPrefix({ principal: ALICE, binding: BINDING_A });
    const task = correlationKey({
      principal: ALICE,
      binding: BINDING_A,
      task: "task-1",
    });

    expect(bridge.startsWith(principal)).toBe(true);
    expect(task.startsWith(bridge)).toBe(true);
  });

  it("keeps two machine sessions of the SAME principal under one prefix", () => {
    // Renewal generates fresh keypairs, so the binding changes. The point of
    // putting the principal on top is that this does NOT fork the principal's
    // history the way a serial-keyed scheme would.
    const principal = correlationPrefix({ principal: ALICE });
    for (const binding of [BINDING_A, BINDING_B]) {
      expect(
        correlationKey({ principal: ALICE, binding, task: "t" }).startsWith(
          principal,
        ),
      ).toBe(true);
    }
  });

  it("never matches a DIFFERENT principal", () => {
    expect(
      correlationKey({
        principal: BOB,
        binding: BINDING_A,
        task: "t",
      }).startsWith(correlationPrefix({ principal: ALICE })),
    ).toBe(false);
  });

  it("does not let one principal's prefix match a LONGER principal's key", () => {
    // The string-prefix-is-not-segment-prefix defect. `wimse://x/a` must not
    // match `wimse://x/ab`. Without a terminator on each segment this passes
    // silently and one principal's query returns another's activity.
    const short = "wimse://notme.bot/passkey/a";
    const longer = "wimse://notme.bot/passkey/ab";

    expect(
      correlationKey({
        principal: longer,
        binding: BINDING_A,
        task: "t",
      }).startsWith(correlationPrefix({ principal: short })),
    ).toBe(false);
  });

  it("does not let the principal's own slashes create phantom levels", () => {
    // A principal URI has three slashes of its own. If they survive into the
    // key unescaped, a prefix aimed at the BRIDGE level lands inside the
    // principal instead, and the key stops meaning what it says.
    const key = correlationKey({
      principal: ALICE,
      binding: BINDING_A,
      task: "t",
    });
    const parsed = parseCorrelationKey(key);

    expect(parsed).not.toBeNull();
    expect(parsed!.principal).toBe(ALICE);
    expect(parsed!.binding).toBe(BINDING_A);
    expect(parsed!.task).toBe("t");
  });

  it("survives a task id containing the delimiter", () => {
    // Task ids are not notme's to constrain — whatever labels a unit of work
    // upstream ends up here. A delimiter inside one must not restructure the
    // key.
    const hostile = "job/42/step/7";
    const parsed = parseCorrelationKey(
      correlationKey({ principal: ALICE, binding: BINDING_A, task: hostile }),
    );
    expect(parsed!.task).toBe(hostile);
    expect(parsed!.principal).toBe(ALICE);
  });

  it("refuses a principal that is not an absolute URI", () => {
    // The top level is the stable identity; accepting a bare string here
    // would let a caller invent a principal namespace by convention.
    expect(() =>
      correlationKey({ principal: "alice", binding: BINDING_A, task: "t" }),
    ).toThrow(/principal/i);
  });

  it("refuses a binding that is not a SHA-256 hex digest", () => {
    // The binding is SHA-256(P-256 SPKI || Ed25519 SPKI) from the cert. A
    // short or non-hex value would make the middle level variable-length,
    // reintroducing the prefix-collision this encoding exists to prevent.
    expect(() =>
      correlationKey({ principal: ALICE, binding: "abc", task: "t" }),
    ).toThrow(/binding/i);
  });
});
