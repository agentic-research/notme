/**
 * pinned-clock.ts — run a boundary assertion against ONE clock (notme-070a8f).
 *
 * A test that asserts a window edge ("121 s ahead is refused", "3599 s old is
 * accepted") computes the iat from Date.now() and the authority judges it
 * against ITS Date.now(), read later, after signing and a request. If the
 * second ticks in between, `now + 121` arrives as `now + 120` and is accepted:
 * the assertion races the wall clock, and loses more often under load. That
 * is how tier-generation's "an iat beyond the skew ahead…" and tier-renewal's
 * "refuses a stale proof" flaked.
 *
 * vitest-pool-workers runs main-Worker Durable Objects in the test runner's
 * isolate, so faking Date in the test pins the authority's clock too (checked
 * directly: a runInDurableObject read of Date.now() returns the faked value).
 * Only Date is faked; timers, I/O and the event loop stay real, so nothing
 * that awaits a timeout can hang.
 */
import { vi } from "vitest";

export async function withPinnedClock<T>(fn: () => Promise<T>): Promise<T> {
  vi.useFakeTimers({ toFake: ["Date"], now: Date.now() });
  try {
    return await fn();
  } finally {
    vi.useRealTimers();
  }
}
