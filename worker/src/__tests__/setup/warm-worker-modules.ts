/**
 * warm-worker-modules.ts — load the Worker's module graph once per test file,
 * BEFORE any test's timer starts (notme-070a8f).
 *
 * WHY. vitest-pool-workers boots a fresh runtime per test file, and the
 * Worker reaches most of its code through dynamic `await import(...)` (the
 * cert authority, @peculiar/x509, the OIDC and passkey paths). Each of those
 * is fetched and transformed by the Vite server the FIRST time a test hits
 * it, so the first heavy test in every file paid the whole module-graph cost
 * inside its own 5 s timeout. When the machine is idle that costs a couple
 * of seconds and nobody notices. On a loaded machine (many runtimes sharing
 * one Vite server and the CPU) it went past 5 s, and the first mint-path test
 * in many files timed out at once. That was the bead's "one flake cascades
 * across eight files". The files never shared state (pool-workers gives each
 * file its own Miniflare and storage); what they shared was a cold start.
 *
 * Measured under the same background load, with the same four files: the
 * first test took 5004 ms (timed out) without this file and 25-40 ms with it.
 * The whole suite runs about 10% slower, because modules a file never uses
 * are loaded too.
 *
 * Setup files run before the file's tests are collected, and their time is
 * not charged to any test's timeout. The one-time cost lands here, so a test
 * timeout goes back to measuring the test. The timeout itself is unchanged.
 */
import.meta.glob(
  [
    "../../../worker.ts",
    "../../**/*.ts",
    "!../../**/*.test.ts",
    "!../../__tests__/**",
    "!../../**/*.d.ts",
  ],
  { eager: true },
);
await import("@peculiar/x509");
await import("@agentic-research/dpop");
