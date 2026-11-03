/// <reference types="@cloudflare/vitest-pool-workers/types" />
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
const bundle = async () => {
  const res = await worker.fetch(new Request(`${ORIGIN}/internal/ca-bundle`), { ...env, ...LOCAL_ENV } as never);
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
});
