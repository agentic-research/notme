/**
 * await-convergence.ts — block until the deployed Worker reports the expected
 * build on N CONSECUTIVE samples (notme-9f2f79).
 *
 * ── WHY THIS EXISTS ──
 * Promotion is not immediate. Measured against production 2026-08-06: after
 * `wrangler versions deploy <id>@100%` returned success and the API reported
 * `Version(s): (100%) <id>`, live traffic ALTERNATED between the old and new
 * build for roughly a minute —
 *
 *     t+10s OLD   t+20s OLD   t+30s NEW   t+40s NEW   t+50s OLD   t+60s NEW
 *
 * — and only then settled (30/30 new thereafter). The control plane reports
 * INTENT; the data plane arrives later.
 *
 * `task worker:verify` retries 5 times at 2s intervals — about 10 seconds,
 * SHORTER than that window. So a verify run immediately after promotion can
 * pass against the OLD build and report success for a deploy that has not
 * landed. `ship-prod` does exactly that: worker:deploy → worker:verify with
 * nothing in between.
 *
 * That is the same defect class as the canary which sampled the wrong version
 * for 85 consecutive requests while reporting a healthy 10/90 split.
 *
 * ── WHY N CONSECUTIVE, NOT ONE MATCH ──
 * Because traffic ALTERNATES. During convergence a single successful sample
 * proves nothing — both builds are serving, and one hit is as likely as not.
 * Only an unbroken run is evidence that the old build has stopped answering.
 * A reset streak is itself the signal that convergence is still in progress,
 * so resets are counted and reported.
 *
 * ── WHY IT FAILS RATHER THAN WARNS ──
 * A verify against an unknown build is worse than no verify: it produces a
 * green signal for a property nothing checked. This repo has found five
 * artifacts of that shape in one cycle.
 */

const AUTH_BASE = process.env.AUTH_BASE ?? "https://auth.notme.bot";
const EXPECT = process.env.EXPECT ?? "";
const SAMPLES = Number(process.env.SAMPLES ?? "5");
const INTERVAL_S = Number(process.env.INTERVAL ?? "3");
const TIMEOUT_S = Number(process.env.TIMEOUT ?? "180");

/** What the live endpoint reports, normalised to one comparable token. */
type Observed =
  | { kind: "commit"; value: string }
  /** Endpoint answered but the build carries no stamp — deployed without --var. */
  | { kind: "unstamped" }
  /** No such route: the live build PREDATES /.well-known/version entirely. */
  | { kind: "no-endpoint" }
  /** Network/timeout. Distinct from the above so a flaky probe is not read as an old build. */
  | { kind: "unreachable"; detail: string };

function describe(o: Observed): string {
  switch (o.kind) {
    case "commit":
      return o.value.slice(0, 12);
    case "unstamped":
      return "unstamped build";
    case "no-endpoint":
      return "no /.well-known/version (build predates it)";
    case "unreachable":
      return `unreachable: ${o.detail}`;
  }
}

async function probe(url: string): Promise<Observed> {
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(10_000),
      // Defeat any intermediary cache: a cached answer would report a build
      // that stopped serving, which is the exact error being guarded against.
      headers: { "Cache-Control": "no-cache" },
    });
    if (res.status === 404) return { kind: "no-endpoint" };
    if (!res.ok) return { kind: "unreachable", detail: `HTTP ${res.status}` };
    const body = (await res.json()) as { commit?: string; stamped?: boolean };
    if (!body.stamped || !body.commit) return { kind: "unstamped" };
    return { kind: "commit", value: body.commit };
  } catch (e) {
    return { kind: "unreachable", detail: (e as Error).message };
  }
}

const sleep = (s: number) => new Promise((r) => setTimeout(r, s * 1000));

async function main() {
  let expect = EXPECT.trim();
  if (!expect) {
    const { execSync } = await import("node:child_process");
    expect = execSync("git rev-parse HEAD", { encoding: "utf8" }).trim();
  }
  const url = `${AUTH_BASE}/.well-known/version`;

  console.log(`awaiting convergence on ${expect}`);
  console.log(
    `  ${url}  (${SAMPLES} consecutive, ${INTERVAL_S}s apart, ${TIMEOUT_S}s budget)`,
  );

  const deadline = Date.now() + TIMEOUT_S * 1000;
  let streak = 0;
  let resets = 0;
  let last: Observed = { kind: "unreachable", detail: "not yet probed" };

  for (;;) {
    const got = await probe(url);
    last = got;

    if (got.kind === "commit" && got.value === expect) {
      streak++;
      console.log(`  [${streak}/${SAMPLES}] ${describe(got)}`);
      if (streak >= SAMPLES) {
        console.log(`converged on ${expect}`);
        return;
      }
    } else {
      if (streak > 0) resets++;
      streak = 0;
      console.log(`  ... serving ${describe(got)}`);
    }

    if (Date.now() >= deadline) {
      console.error("");
      console.error(`NOT CONVERGED after ${TIMEOUT_S}s.`);
      console.error(`  expected:  ${expect}`);
      console.error(`  last seen: ${describe(last)}`);
      // A nonzero reset count means both builds were still answering, which is
      // a different operator action from "a different build entirely".
      console.error(`  streak resets (traffic still split): ${resets}`);
      if (last.kind === "no-endpoint") {
        console.error("  → the live build predates /.well-known/version.");
      } else if (last.kind === "unstamped") {
        console.error("  → deployed without --var BUILD_SHA. Redeploy via task.");
      } else if (resets > 0) {
        console.error("  → still converging; consider a longer TIMEOUT.");
      } else {
        console.error("  → a different build is serving. task worker:versions");
      }
      process.exit(1);
    }
    await sleep(INTERVAL_S);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
