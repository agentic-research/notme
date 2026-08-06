/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * bootstrap-trigger.do.test.ts — an unauthenticated stranger must not be able
 * to make the authority MINT a credential (notme-addef9).
 *
 * WHAT THE AUDIT FOUND. On a fresh authority the first unauthenticated POST to
 * /auth/passkey/register/options caused `getOrCreateBootstrapCode()` to mint an
 * admin bootstrap code and `console.log` it, then answered 401 "check Worker
 * logs". Three things are wrong with that, in increasing order of severity:
 *
 *   1. THE TRIGGER IS NOT THE DEPLOYER. Any stranger who hits the endpoint
 *      first causes the mint. The code goes to the logs regardless of who
 *      asked, so an attacker chooses the MOMENT a credential appears — and
 *      since notme-976385 made regeneration possible while no authenticator
 *      exists, they can cause it repeatedly.
 *   2. SECRETS BY LOG-SCRAPING is the exact posture this repo exists to
 *      eliminate everywhere else. The whole thesis is no long-lived secret on
 *      disk, attestation instead of stored credentials — and then first boot
 *      says "go read a secret out of the logs".
 *   3. THE LOGS ARE NOT RELIABLY READABLE. Verified in production this cycle:
 *      `wrangler tail` produced nothing for a failing request AND for a
 *      known-good 200 issued in the same window. So the documented recovery
 *      path can simply fail to work.
 *
 * The security review judged (1) acceptable because the code never crosses the
 * HTTP boundary — the caller gets a 401 with no code — so a network-only
 * attacker gains nothing, and the exposure is to whoever can read Workers
 * Logs. That reasoning holds and is why this is not a P0. It is still a side
 * channel serving as the PRIMARY onboarding path.
 *
 * WHAT THIS TEST PINS. The read must be a READ. Asking the authority whether
 * it needs bootstrapping must not cause it to create anything, so the answer
 * is stable under repetition and an attacker cannot drive credential creation
 * at a time of their choosing. Minting moves behind an explicit operator
 * action — a secret only whoever controls the deployment can set.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { SigningAuthority } from "./signing-authority";

function authority(name: string) {
  return env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(name));
}

/** Read the bootstrap table directly — the DO's own view, not the API's. */
async function storedCodeCount(stub: ReturnType<typeof authority>) {
  return runInDurableObject(stub, (auth) => {
    const sql = (auth as unknown as { ctx: { storage: { sql: any } } }).ctx
      .storage.sql;
    try {
      return [...sql.exec("SELECT COUNT(*) AS n FROM bootstrap")][0].n as number;
    } catch {
      // Table absent is the strongest possible form of "nothing was minted".
      return 0;
    }
  });
}

describe("bootstrap trigger (notme-addef9)", () => {
  it("does not mint anything when asked about bootstrap state", async () => {
    const stub = authority("bootstrap-trigger-read");
    const state = await runInDurableObject(stub, (auth) =>
      (auth as SigningAuthority).getBootstrapState(),
    );

    expect(state.status).toBeDefined();
    expect(
      await storedCodeCount(stub),
      "reading bootstrap state created a stored credential",
    ).toBe(0);
  });

  it("gives the same answer under repetition — no attacker-chosen re-arming", async () => {
    // The property that makes it a read. If repeated calls could each produce
    // a fresh credential, an attacker picks the moment one appears and can do
    // it as often as they like.
    const stub = authority("bootstrap-trigger-repeat");
    const reads = [];
    for (let i = 0; i < 3; i++) {
      reads.push(
        await runInDurableObject(stub, (auth) =>
          (auth as SigningAuthority).getBootstrapState(),
        ),
      );
    }
    expect(reads[1]).toEqual(reads[0]);
    expect(reads[2]).toEqual(reads[0]);
    expect(await storedCodeCount(stub)).toBe(0);
  });

  it('reports "unconfigured" when the operator has set no bootstrap secret', async () => {
    // Fail closed AND fail informative. An authority nobody can bootstrap is
    // a recoverable operator error; one that silently mints a credential into
    // a log the operator may not be able to read is not.
    const stub = authority("bootstrap-trigger-unconfigured");
    const state = await runInDurableObject(stub, (auth) =>
      (auth as SigningAuthority).getBootstrapState(),
    );
    expect(state).toEqual({ status: "unconfigured" });
  });

  it("refuses any code while unconfigured, including the empty string", async () => {
    // The dangerous shape: if an unset secret compared equal to an absent or
    // empty submitted code, an unconfigured authority would hand admin to the
    // first caller who sent nothing at all.
    const stub = authority("bootstrap-trigger-unconfigured-consume");
    for (const attempt of ["", "anything", "undefined", "null"]) {
      expect(
        await runInDurableObject(stub, (auth) =>
          (auth as SigningAuthority).consumeBootstrapCode(attempt),
        ),
        `accepted ${JSON.stringify(attempt)} on an unconfigured authority`,
      ).toBe(false);
    }
  });
});
