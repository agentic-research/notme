/**
 * ct-config.test.ts — the production log's sequencing settings stay inside
 * notme's own CT time bound (notme-1b46a8, 2026-11-03 cost estimate).
 *
 * azul answers add-[pre-]chain only after the entry is sequenced, and an idle
 * log writes a checkpoint every (max_sequence_skips + 1) × interval, which is
 * also the worst wait in the pool. Cheaper idle means slower inclusion; past
 * DEFAULT_TIMEOUT_MS every mint is backlogged with no embedded SCT. See
 * ct/README.md, "Sequencing: cost against inclusion latency".
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { DEFAULT_TIMEOUT_MS } from "../ct/log-client";

const config = JSON.parse(
  readFileSync(join(__dirname, "..", "..", "..", "ct", "config.notme.json"), "utf8"),
) as { logs: Record<string, Record<string, unknown>> };

/** azul's default batch_timeout_millis, added before the entry reaches the pool. */
const BATCH_MS = 100;
/** Room for the service-binding round trip, signing and the R2 writes. */
const MARGIN_MS = 300;

describe("ct/config.notme.json sequencing", () => {
  for (const name of ["notme", "notmedev"]) {
    it(`${name}: empty intervals skip the checkpoint, and the worst wait fits the mint's CT bound`, () => {
      const log = config.logs[name]!;
      const interval = log.sequence_interval_millis;
      const skips = log.max_sequence_skips;
      expect(Number.isInteger(interval) && (interval as number) >= 100, "azul's schema minimum").toBe(true);
      expect(skips, "0 writes a checkpoint every tick, idle or not").toBeGreaterThanOrEqual(1);
      const worst = (skips as number + 1) * (interval as number) + BATCH_MS + MARGIN_MS;
      expect(worst, `worst-case add-pre-chain ${worst} ms vs ${DEFAULT_TIMEOUT_MS} ms`).toBeLessThan(
        DEFAULT_TIMEOUT_MS,
      );
      expect(log.sequence_skip_threshold_millis, "forces a checkpoint every idle tick").toBeUndefined();
    });
  }
});
