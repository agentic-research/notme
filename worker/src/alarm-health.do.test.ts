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
import { withPinnedClock } from "./__tests__/helpers/pinned-clock";
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

/** Write the alarm_health row the DO reads, creating the table as the DO does. */
async function seedHealth(
  stub: ReturnType<typeof authority>,
  row: { totalFires: number; failureCount: number; firstFireAt?: number },
) {
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
      "INSERT OR REPLACE INTO alarm_health (id, total_fires, failure_count, last_fire_at, last_outcome, first_fire_at) VALUES ('authority', ?, ?, 0, 'error', ?)",
      row.totalFires,
      row.failureCount,
      row.firstFireAt ?? 0,
    );
  });
}

/** Force the breaker open by writing the failure count the DO reads. */
const tripBreaker = (stub: ReturnType<typeof authority>, failures: number) =>
  seedHealth(stub, { totalFires: failures, failureCount: failures });

/** The alarm timestamp, or null when none is pending. */
const alarmOf = (stub: ReturnType<typeof authority>) =>
  runInDurableObject(stub, (auth) =>
    (auth as unknown as AlarmCtx).ctx.storage.getAlarm(),
  );

const armAlarmAt = (stub: ReturnType<typeof authority>, at: number) =>
  runInDurableObject(stub, (auth) =>
    (auth as unknown as AlarmCtx).ctx.storage.setAlarm(at),
  );

/**
 * Make every KV publish from this authority fail (or succeed again), and count
 * the attempts. The bundle refresh is the alarm's one real unit of work, and a
 * KV put that throws is the "KV unavailable" failure THREAT_MODEL §3 names.
 * Patched on the DO's own env, so no other test's KV binding is touched.
 */
async function controlKv(stub: ReturnType<typeof authority>) {
  const state = { failing: true, puts: 0 };
  let restore: () => void = () => {};
  await runInDurableObject(stub, (auth) => {
    const e = (auth as unknown as { env: Record<string, unknown> }).env;
    const original = e.CA_BUNDLE_CACHE;
    Object.defineProperty(e, "CA_BUNDLE_CACHE", {
      configurable: true,
      value: {
        put: async () => {
          state.puts++;
          if (state.failing) throw new Error("kv unavailable (test)");
        },
      },
    });
    restore = () =>
      Object.defineProperty(e, "CA_BUNDLE_CACHE", {
        configurable: true,
        value: original,
      });
  });
  return { state, restore: () => restore() };
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
    // Nothing has fired, so there is no rate to compare: zero, not NaN or Infinity.
    expect(health.firesPerHour).toBe(0);
    expect(health.driftRatio).toBe(0);
    expect(health.warmupComplete).toBe(false);
    expect(health.circuitBreakerOpen).toBe(false);
  });

  it("signing.alarm.health-counter — expectedFiresPerHour is the cadence the alarm is armed with", async () => {
    // 4-minute BUNDLE_REFRESH_MS = 15 fires an hour. driftRatio's denominator;
    // if the cadence constant moves and this does not follow, the ratio lies.
    const health = await runInDurableObject(authority("alarm-expected"), (auth) =>
      (auth as SigningAuthority).getAlarmHealth(),
    );
    expect(health.expectedFiresPerHour).toBe(15);
  });

  it("signing.alarm.health-counter — warmupComplete flips at exactly 3 fires", async () => {
    // driftRatio over fewer fires is noise; consumers gate on this flag.
    const flag = async (name: string, totalFires: number) => {
      const stub = authority(name);
      await seedHealth(stub, { totalFires, failureCount: 0, firstFireAt: Date.now() - 60_000 });
      return (await runInDurableObject(stub, (auth) =>
        (auth as SigningAuthority).getAlarmHealth(),
      )).warmupComplete;
    };
    expect(await flag("alarm-warm-2", 2)).toBe(false);
    expect(await flag("alarm-warm-3", 3)).toBe(true);
  });

  it("signing.alarm.health-counter — driftRatio is ~1 on cadence and large when the alarm runs away", async () => {
    // 6 fires over 0.4 h is 15/h, exactly the cadence: ratio 1. The same 0.4 h
    // with 60 fires is 150/h, ten times the cadence: the runaway the row
    // exists to detect. Date is pinned so the elapsed time is exact.
    await withPinnedClock(async () => {
      const onCadence = authority("alarm-drift-ok");
      await seedHealth(onCadence, { totalFires: 6, failureCount: 0, firstFireAt: Date.now() - 1_440_000 });
      const ok = await runInDurableObject(onCadence, (auth) =>
        (auth as SigningAuthority).getAlarmHealth(),
      );
      expect(ok.firesPerHour).toBeCloseTo(15, 9);
      expect(ok.driftRatio).toBeCloseTo(1, 9);

      const runaway = authority("alarm-drift-runaway");
      await seedHealth(runaway, { totalFires: 60, failureCount: 0, firstFireAt: Date.now() - 1_440_000 });
      const bad = await runInDurableObject(runaway, (auth) =>
        (auth as SigningAuthority).getAlarmHealth(),
      );
      expect(bad.driftRatio).toBeCloseTo(10, 9);
      expect(bad.warmupComplete).toBe(true);
      // The documented alert threshold (~1.2) separates the two.
      expect(ok.driftRatio).toBeLessThan(1.2);
      expect(bad.driftRatio).toBeGreaterThan(1.2);
    });
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

  it("signing.alarm.idempotent-reschedule — scheduleNextRefresh leaves a pending alarm alone", async () => {
    // THE getAlarm-before-setAlarm guard, observed. The pending alarm is an
    // hour out; a call that re-armed would move it to now + 4 min. Same
    // timestamp afterwards is the only way it can look if setAlarm never ran.
    const stub = authority("alarm-noop");
    const pending = Date.now() + FAR_FUTURE_MS;
    await armAlarmAt(stub, pending);

    for (let i = 0; i < 3; i++) {
      await runInDurableObject(stub, (auth) =>
        (auth as SigningAuthority).scheduleNextRefresh(),
      );
    }
    expect(await alarmOf(stub), "a pending alarm was rescheduled").toBe(pending);
  });

  it("signing.alarm.idempotent-reschedule — with no alarm pending, scheduleNextRefresh arms exactly one, one cadence out", async () => {
    const stub = authority("alarm-arms-once");
    expect(await alarmOf(stub)).toBeNull();
    await runInDurableObject(stub, (auth) =>
      (auth as SigningAuthority).scheduleNextRefresh(),
    );
    const first = await alarmOf(stub);
    expect(first).not.toBeNull();
    const fromNow = first! - Date.now();
    expect(fromNow).toBeGreaterThan(3 * 60_000);
    expect(fromNow).toBeLessThanOrEqual(4 * 60_000);

    // A second call must not move it.
    await runInDurableObject(stub, (auth) =>
      (auth as SigningAuthority).scheduleNextRefresh(),
    );
    expect(await alarmOf(stub)).toBe(first);
  });

  it("signing.alarm.idempotent-reschedule — every warm request leaves the pending alarm untouched", async () => {
    // The warm path calls scheduleNextRefresh on EVERY request that reaches
    // the signing key (notme-4896d8). N requests must not become N alarms or
    // push the one alarm back. Pending is an hour out, as above.
    const stub = authority("alarm-warm-noop");
    await runInDurableObject(stub, (auth) => (auth as SigningAuthority).getPublicKeyPem());
    const pending = Date.now() + FAR_FUTURE_MS;
    await armAlarmAt(stub, pending);
    for (let i = 0; i < 3; i++) {
      await runInDurableObject(stub, (auth) => (auth as SigningAuthority).getPublicKeyPem());
    }
    expect(await alarmOf(stub)).toBe(pending);
  });

  it("signing.alarm.circuit-breaker — counts real failures to 5 and opens on the 5th", async () => {
    // Real failures, not a seeded count: KV rejects every publish and the
    // platform runs the alarm (consuming it). Fires 1-4 leave the breaker
    // closed and a successor armed; the 5th opens it ON THAT FIRE.
    const stub = authority("alarm-breaker-real");
    const kv = await controlKv(stub);
    try {
      await armAlarmAt(stub, Date.now() + FAR_FUTURE_MS);
      for (let fire = 1; fire <= 5; fire++) {
        expect(await runDurableObjectAlarm(stub), `fire ${fire} did not run`).toBe(true);
        const h = await runInDurableObject(stub, (auth) =>
          (auth as SigningAuthority).getAlarmHealth(),
        );
        expect(h.failureCount, `after fire ${fire}`).toBe(fire);
        expect(h.totalFires).toBe(fire);
        expect(h.lastOutcome).toMatch(/^error: kv unavailable/);
        if (fire < 5) {
          expect(h.circuitBreakerOpen, `breaker opened early, at fire ${fire}`).toBe(false);
          expect(await alarmOf(stub), `fire ${fire} did not re-arm`).not.toBeNull();
        } else {
          // That the 5th fire leaves no alarm behind is its own test below
          // (notme-5c2511).
          expect(h.circuitBreakerOpen).toBe(true);
        }
      }
      expect(kv.state.puts, "each of the 5 fires should have tried to publish").toBe(5);
    } finally {
      kv.restore();
    }
  });

  it("signing.alarm.circuit-breaker — alarm() against an open breaker declines to work and to re-arm", async () => {
    // Open the breaker for real (5 failing fires), then deliver a 6th alarm
    // anyway, as a stray timer or a manual run would. It must not publish,
    // must not re-arm, and must still be counted (post-mortem: how many fires
    // arrived after the trip).
    const stub = authority("alarm-breaker-open");
    const kv = await controlKv(stub);
    try {
      await armAlarmAt(stub, Date.now() + FAR_FUTURE_MS);
      for (let fire = 1; fire <= 5; fire++) await runDurableObjectAlarm(stub);
      const putsAtTrip = kv.state.puts;
      kv.state.failing = false; // even a healthy KV must not be touched now

      await armAlarmAt(stub, Date.now() + FAR_FUTURE_MS);
      expect(await runDurableObjectAlarm(stub), "6th alarm did not run").toBe(true);

      const h = await runInDurableObject(stub, (auth) =>
        (auth as SigningAuthority).getAlarmHealth(),
      );
      expect(h.lastOutcome).toBe("skipped: circuit breaker open");
      expect(h.totalFires, "the skipped fire was not counted").toBe(6);
      expect(h.failureCount, "an open breaker must stay open").toBe(5);
      expect(kv.state.puts, "an open breaker still did bundle work").toBe(putsAtTrip);
      expect(await alarmOf(stub), "an open breaker re-armed").toBeNull();
    } finally {
      kv.restore();
    }
  });

  it("signing.alarm.circuit-breaker — a success resets the consecutive-failure count", async () => {
    // "Consecutive" is the contract: 4 failures then a success must not leave
    // the breaker one strike from open.
    const stub = authority("alarm-breaker-consecutive");
    const kv = await controlKv(stub);
    try {
      await armAlarmAt(stub, Date.now() + FAR_FUTURE_MS);
      for (let fire = 1; fire <= 4; fire++) await runDurableObjectAlarm(stub);
      kv.state.failing = false;
      expect(await runDurableObjectAlarm(stub)).toBe(true);
      const h = await runInDurableObject(stub, (auth) =>
        (auth as SigningAuthority).getAlarmHealth(),
      );
      expect(h.failureCount).toBe(0);
      expect(h.lastOutcome).toBe("success");
      expect(await alarmOf(stub), "a success must re-arm").not.toBeNull();
    } finally {
      kv.restore();
    }
  });

  // notme-5c2511 (found by the strengthened tests above). The breaker used to
  // leave the alarm armed in two ways, both because the warm path of
  // #getOrCreateSigningKey calls scheduleNextRefresh():
  //   1. the tripping fire: #publishBundle -> generateBundle -> warm path armed
  //      a successor while failure_count was still one short, so alarm()
  //      "returned without re-arming" with an alarm pending anyway;
  //   2. any later request that reached the signing key re-armed it again.
  // Both were pinned as `it.fails` until the fix: scheduleNextRefresh() now
  // declines behind an open breaker, and the tripping fire deletes whatever
  // its own bundle work armed. Only resetAlarmHealth() re-arms.
  it("signing.alarm.circuit-breaker — the tripping fire leaves no alarm behind (notme-5c2511)", async () => {
    const stub = authority("alarm-breaker-trip-rearm");
    const kv = await controlKv(stub);
    try {
      await armAlarmAt(stub, Date.now() + FAR_FUTURE_MS);
      for (let fire = 1; fire <= 5; fire++) await runDurableObjectAlarm(stub);
      expect(await alarmOf(stub), "the 5th failure left an alarm armed").toBeNull();
    } finally {
      kv.restore();
    }
  });

  it("signing.alarm.circuit-breaker — an open breaker stays un-armed when a request touches the signing key (notme-5c2511)", async () => {
    const stub = authority("alarm-breaker-warm");
    await tripBreaker(stub, 5);
    await runInDurableObject(stub, (auth) => (auth as SigningAuthority).getPublicKeyPem());
    expect(await alarmOf(stub), "a request re-armed the alarm behind an open breaker").toBeNull();
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
