/// <reference types="@cloudflare/vitest-plugin/types" />
/**
 * rotate-publishes-bundle.do.test.ts — a rotation is visible in the KV
 * CABundle at once, not at the next alarm (notme-ed6114, re-review NEW-1).
 *
 * The trust-anchor gates (scripts/refresh-trust-anchor.ts, release.yml)
 * judge the served root against /internal/ca-bundle's keyId. rotate() never
 * republished it — only alarm() and revokeEpoch() did — so for up to the
 * bundle's staleness window after a rotate the bundle still named the OLD
 * key, agreed with the stale edge root, and the release could sign it.
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../worker";

const ORIGIN = "http://localhost:8788";
const LOCAL_ENV = { SITE_URL: ORIGIN, SIGNET_AUTHORITY_URL: ORIGIN };
// `no-cache`, as the trust-anchor gates send it: the route keeps a short-lived
// copy per isolate and per colo (notme-a34dad), and a read straight after a
// rotation must not be answered from it.
const bundle = async () => {
  const res = await worker.fetch(
    new Request(`${ORIGIN}/internal/ca-bundle`, { headers: { "cache-control": "no-cache" } }),
    { ...env, ...LOCAL_ENV } as never,
  );
  expect(res.status).toBe(200);
  return (await res.json()) as { keyId: string; keys: Record<string, string>; prevKeyId?: string };
};

describe("rotate() republishes the CA bundle", () => {
  it("/internal/ca-bundle names the new key straight after rotate(), without an alarm", async () => {
    const before = await bundle(); // publishes and caches the pre-rotation bundle
    const stub = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
    const { newKeyId } = await stub.rotate();
    expect(newKeyId).not.toBe(before.keyId);
    const after = await bundle();
    expect(after.keyId).toBe(newKeyId);
    // The grace window still publishes the outgoing key beside it.
    expect(after.prevKeyId).toBe(before.keyId);
    expect(after.keys[before.keyId]).toBe(before.keys[before.keyId]);
  });

  it("publishes bundle:current with NO KV TTL: the read-time staleness check is the bound (notme-05324c)", async () => {
    // A TTL would turn a stale bundle into an ABSENT one, and checkRevocation
    // treats the two oppositely: stale fails closed (bundle_stale), absent
    // fails open (the bootstrap case). So if the alarm stopped, a TTL would
    // move every verifier from refusing to accepting once it expired.
    // revocation.do.test.ts pins both halves of that asymmetry.
    const stub = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
    await stub.rotate(); // publishes through #publishBundle
    const { keys } = await env.CA_BUNDLE_CACHE.list({ prefix: "bundle:current" });
    const entry = keys.find((k) => k.name === "bundle:current");
    expect(entry, "rotate() published the bundle").toBeDefined();
    expect(entry!.expiration, "bundle:current must not expire out of KV").toBeUndefined();
  });
});
