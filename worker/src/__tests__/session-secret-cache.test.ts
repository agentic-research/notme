/**
 * session-secret-cache.test.ts — a secret fetch that STARTED before a reset
 * must not vouch for a cookie the reset revoked (notme-a34dad, review L3).
 *
 * Two shapes:
 *  - the reset happens elsewhere (another isolate, or the DO directly) while
 *    this isolate has a fetch in flight. A request arriving after the reset
 *    joins that fetch and gets the PRE-reset secret. It must not treat that
 *    as fresh: it confirms against the live secret, which refuses the cookie.
 *  - this isolate performs the reset (invalidateSessionSecret) mid-fetch. The
 *    in-flight fetch is abandoned: later requests do not join it, and its
 *    pre-reset result is never cached.
 */
import { beforeEach, describe, expect, it } from "vitest";
import { createSessionCookie } from "../auth/session";
import {
  __resetSessionSecretCacheForTests,
  invalidateSessionSecret,
  verifySessionCached,
} from "../auth/session-secret-cache";

const OLD = "b2xkLXNlY3JldC1vbGQtc2VjcmV0LW9sZC1zZWNyZXQ=";
const NEW = "bmV3LXNlY3JldC1uZXctc2VjcmV0LW5ldy1zZWNyZXQ=";

const cookieUnder = async (secret: string, principalId = "p") =>
  (await createSessionCookie({ principalId, scopes: ["bridgeCert"], authMethod: "passkey" }, secret))
    .split(";")[0]!
    .slice("notme_session=".length);

/**
 * A SigningAuthority whose FIRST getSessionSecret call is held open and then
 * answers with whatever the secret was when the DO read it (`firstReads`);
 * every later call answers with the current secret at once.
 */
function heldAuthority(firstReads: string) {
  let current = firstReads;
  let release!: () => void;
  let calls = 0;
  return {
    get calls() {
      return calls;
    },
    rotate(to: string) {
      current = to;
    },
    release: () => release(),
    authority: {
      getSessionSecret: () => {
        calls++;
        if (calls === 1) return new Promise<string>((r) => (release = () => r(firstReads)));
        return Promise.resolve(current);
      },
    },
  };
}

const tick = () => new Promise((r) => setTimeout(r, 0));

beforeEach(() => __resetSessionSecretCacheForTests());

describe("session.secret.reset-mid-fetch — an in-flight pre-reset fetch does not vouch for a revoked cookie", () => {
  it("a reset ELSEWHERE mid-fetch: a request arriving after it, carrying the old cookie, is refused", async () => {
    const old = await cookieUnder(OLD);
    const h = heldAuthority(OLD);
    const a = verifySessionCached(old, h.authority); // starts the fetch; the DO reads OLD
    await tick();
    h.rotate(NEW); // resetPasskeyData, in another isolate
    const b = verifySessionCached(old, h.authority); // arrives after the reset
    await tick();
    h.release();
    expect((await a).ok).toBe(true); // it arrived before the reset: accepting it is linearisable
    expect(await b).toEqual({ ok: false, limited: false });
  });

  it("a reset IN THIS ISOLATE mid-fetch abandons the fetch: the old cookie is refused, and the old secret is never cached", async () => {
    const old = await cookieUnder(OLD);
    const fresh = await cookieUnder(NEW);
    const h = heldAuthority(OLD);
    const a = verifySessionCached(old, h.authority);
    await tick();
    h.rotate(NEW);
    invalidateSessionSecret(); // what /auth/passkey/reset does after resetPasskeyData
    const b = verifySessionCached(old, h.authority);
    await tick();
    h.release(); // the abandoned fetch now resolves, with OLD
    expect(await b).toEqual({ ok: false, limited: false });
    await a;
    // The abandoned fetch resolved with OLD after the reset. Had it been
    // cached, this NEW cookie would be refused locally for up to the TTL.
    const c = await verifySessionCached(fresh, h.authority);
    expect(c.ok).toBe(true);
  });

  it("an abandoned fetch that lands with nothing after it is still not cached", async () => {
    // No request in between to overwrite it: only the generation check keeps
    // the pre-reset secret out of the cache, where it would refuse every
    // post-reset cookie locally, for up to the TTL, in the isolate that reset.
    const old = await cookieUnder(OLD);
    const fresh = await cookieUnder(NEW);
    const h = heldAuthority(OLD);
    const a = verifySessionCached(old, h.authority);
    await tick();
    h.rotate(NEW);
    invalidateSessionSecret();
    h.release();
    await a;
    const callsBefore = h.calls;
    const c = await verifySessionCached(fresh, h.authority);
    expect(c.ok).toBe(true);
    // It got there by fetching the live secret, not from a cached OLD one.
    expect(h.calls).toBe(callsBefore + 1);
  });
});
