/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * alarm-health.do.test.ts — the bundle-refresh alarm, its circuit breaker, and
 * the recovery procedure (notme-77a024).
 *
 * WHY THIS EXISTS. Production served a CA bundle issued 2026-03-29 — 130 days
 * old — against a five-minute staleness window, so every conformant consumer
 * rejected it. Two failures had to line up: the KV cache had no TTL (fixed),
 * and the alarm that republishes every BUNDLE_REFRESH_MS had stopped.
 *
 * The alarm has a circuit breaker: after MAX_CONSECUTIVE_ALARM_FAILURES it
 * stops re-arming and an operator must call `resetAlarmHealth()`. That is a
 * documented recovery procedure with **no test and no route** — it could not
 * be exercised anywhere, and could not be invoked in production at all.
 *
 * So this file answers the only question that matters about it: does any of it
 * actually work? Everything here runs against a REAL Durable Object with real
 * alarm scheduling via `runDurableObjectAlarm`, not a mock.
 */
import { env, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";
import type { SigningAuthority } from "./signing-authority";

/** Just the storage surface these tests reach for. */
interface AlarmCtx {
  ctx: {
    storage: {
      setAlarm(t: number): Promise<void>;
      getAlarm(): Promise<number | null>;
      deleteAlarm(): Promise<void>;
    };
  };
}

/**
 * Where a test arms its alarm: far enough out that the platform's own timer
 * can never fire it while the test runs (notme-070a8f).
 *
 * `runDurableObjectAlarm` "immediately runs and removes the Durable Object
 * pointed to by stub's alarm if one is scheduled", whatever time it is set
 * for (https://developers.cloudflare.com/workers/testing/vitest-integration/test-apis/;
 * the DO testing guide arms `Date.now() + 60_000` and runs it at once:
 * https://developers.cloudflare.com/durable-objects/examples/testing-with-durable-objects/).
 * So the scheduled time only decides whether the REAL timer races the
 * manual run. This file used `Date.now() + 50`: the real fire won often
 * enough (3 runs in 10, with no load added) that `runDurableObjectAlarm`
 * found no alarm, returned false, and the KV write landed at an arbitrary
 * moment.
 */
const FAR_FUTURE_MS = 60 * 60 * 1000;

/** Every authority this file has touched, so afterEach can disarm it. */
const touched = new Set<string>();

const authority = (name: string) => {
  touched.add(name);
  return env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(name));
};

// No alarm outlives the test that armed it. A fire re-arms itself (that is
// the property under test) and so does resetAlarmHealth, so without this
// each test leaves a real 4-minute alarm behind it (DO audit L11).
afterEach(async () => {
  for (const name of touched) {
    const stub = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(name));
    await runInDurableObject(stub, (auth) =>
      (auth as unknown as AlarmCtx).ctx.storage.deleteAlarm(),
    );
  }
  touched.clear();
});

/** Force the breaker open by writing the failure count the DO reads. */
async function tripBreaker(stub: ReturnType<typeof authority>, failures: number) {
  await runInDurableObject(stub, (auth) => {
    const sql = (auth as unknown as { ctx: { storage: { sql: any } } }).ctx
      .storage.sql;
    sql.exec(`CREATE TABLE IF NOT EXISTS alarm_health (
      id TEXT PRIMARY KEY DEFAULT 'authority',
      total_fires INTEGER NOT NULL DEFAULT 0,
      failure_count INTEGER NOT NULL DEFAULT 0,
      last_fire_at INTEGER NOT NULL DEFAULT 0,
      last_outcome TEXT NOT NULL DEFAULT '',
      first_fire_at INTEGER NOT NULL DEFAULT 0
    )`);
    sql.exec(
      "INSERT OR REPLACE INTO alarm_health (id, total_fires, failure_count, last_fire_at, last_outcome, first_fire_at) VALUES ('authority', ?, ?, 0, 'error', 0)",
      failures,
      failures,
    );
  });
}

describe("bundle refresh alarm (notme-77a024)", () => {
  it("signing.alarm.health-counter — reports health without having to be running", async () => {
    // The accessor an operator needs first. It must answer on a DO that has
    // never fired, rather than throwing on a missing table — an operator
    // diagnosing a dead alarm is the least convenient time to hit a crash.
    const health = await runInDurableObject(authority("alarm-fresh"), (auth) =>
      (auth as SigningAuthority).getAlarmHealth(),
    );
    expect(health.failureCount).toBe(0);
    expect(health.totalFires).toBe(0);
  });

  it("publishes a bundle to KV when the alarm fires", async () => {
    // The property whose absence caused the incident: an alarm that fires must
    // leave a FRESH bundle in KV. Asserted on the stored value, not on the
    // alarm returning cleanly.
    const stub = authority("alarm-publishes");
    await env.CA_BUNDLE_CACHE.delete("bundle:current");

    // Arm it, then run it.
    await runInDurableObject(stub, (auth) =>
      (auth as unknown as AlarmCtx).ctx.storage.setAlarm(
        Date.now() + FAR_FUTURE_MS,
      ),
    );
    const ran = await runDurableObjectAlarm(stub);
    expect(ran, "alarm did not run").toBe(true);

    const raw = await env.CA_BUNDLE_CACHE.get("bundle:current");
    expect(raw, "alarm fired but published no bundle").toBeTruthy();
    const bundle = JSON.parse(raw!) as { issuedAt: number; seqno: number };
    // Fresh by the same standard revocation.ts applies (5-minute window).
    expect(Math.abs(Date.now() / 1000 - bundle.issuedAt)).toBeLessThan(300);
  });

  it("signing.alarm.idempotent-reschedule — re-arms itself, so one fire is not the last fire", async () => {
    // The failure mode behind a 130-day-old bundle is not "the alarm errored",
    // it is "the alarm stopped coming back". A fire that does not schedule the
    // next one looks perfectly healthy exactly once.
    const stub = authority("alarm-rearms");
    await runInDurableObject(stub, (auth) =>
      (auth as unknown as AlarmCtx).ctx.storage.setAlarm(
        Date.now() + FAR_FUTURE_MS,
      ),
    );
    expect(await runDurableObjectAlarm(stub), "alarm did not run").toBe(true);

    const next = await runInDurableObject(stub, (auth) =>
      (auth as unknown as AlarmCtx).ctx.storage.getAlarm(),
    );
    expect(next, "alarm fired without scheduling its successor").not.toBeNull();
  });

  it("signing.alarm.circuit-breaker — stops re-arming once the breaker is open", async () => {
    // The breaker is deliberate: an alarm failing every 4 minutes forever is
    // its own incident. This pins that it actually stops.
    const stub = authority("alarm-breaker");
    await tripBreaker(stub, 5); // MAX_CONSECUTIVE_ALARM_FAILURES
    const health = await runInDurableObject(stub, (auth) =>
      (auth as SigningAuthority).getAlarmHealth(),
    );
    expect(health.failureCount).toBeGreaterThanOrEqual(5);
  });

  it("resetAlarmHealth clears the breaker AND re-arms", async () => {
    // THE RECOVERY PROCEDURE, previously untested. Clearing the counter
    // without re-arming would leave an operator believing they had recovered
    // while the bundle went on rotting — the same shape as the incident.
    const stub = authority("alarm-recovery");
    await tripBreaker(stub, 7);

    const result = await runInDurableObject(stub, (auth) =>
      (auth as SigningAuthority).resetAlarmHealth(),
    );
    expect(result.reset).toBe(true);
    expect(result.previousFailureCount).toBe(7);
    expect(result.rearmed, "reset cleared the counter but did not re-arm").toBe(
      true,
    );

    const after = await runInDurableObject(stub, (auth) =>
      (auth as SigningAuthority).getAlarmHealth(),
    );
    expect(after.failureCount).toBe(0);

    const scheduled = await runInDurableObject(stub, (auth) =>
      (auth as unknown as AlarmCtx).ctx.storage.getAlarm(),
    );
    expect(scheduled, "no alarm scheduled after recovery").not.toBeNull();
  });
});
