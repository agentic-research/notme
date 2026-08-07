/**
 * build-version.ts — let the deployed Worker say which build it is
 * (notme-9f2f79).
 *
 * WHY THIS EXISTS. Deploys here are manual, so the git tree does not settle
 * what is running. A consumer waiting on a fix — signet, waiting on the PoP
 * pre-image change — had no way to confirm it shipped other than asking, and
 * "no positive evidence" was a fair description of the situation. `/health`
 * returned the string `ok` and nothing else served was derived from the build.
 *
 * IT IS ALSO THE MISSING PIECE OF ADR-018'S CANARY GATE. That gate failed
 * twice, silently reporting the OLD version's behaviour while claiming to
 * probe the new one. An earlier attempt at a discriminator used the JWKS `kid`
 * and could not work in principle: `kid` is STORED DURABLE OBJECT STATE, not
 * recomputed per deploy, so two different builds serve the identical value.
 * The discriminator has to come from the BUILD, not from data the build reads.
 *
 * HOW IT IS STAMPED. `wrangler versions upload --var BUILD_SHA:<sha>`, set by
 * the Taskfile from `git rev-parse HEAD`. A binding rather than a generated
 * source file, deliberately: a generated file would change on every commit and
 * make `action:bundle-check`-style reproducibility gates meaningless, and
 * would need gitignoring, which puts the value outside review.
 *
 * FAIL HONEST. An unstamped or malformed value reports `unknown`, never a
 * guess and never an omitted field. This repo has repeatedly shipped artifacts
 * asserting properties of their own provenance that nothing verified; a
 * version endpoint that quietly omitted an unset value would be another. If
 * the reader cannot tell what is deployed, the endpoint should say so.
 */

/** A full git commit sha. Short shas are ambiguous and are refused. */
const COMMIT_SHA_RE = /^[0-9a-f]{40}$/;

export interface BuildInfo {
  /** The 40-char commit this Worker was built from, or `"unknown"`. */
  commit: string;
  /**
   * Whether `commit` is a real build stamp.
   *
   * Separate from `commit === "unknown"` so a consumer can branch on the fact
   * rather than on a magic string — and so that adding future stamp sources
   * does not require every caller to learn a new sentinel.
   */
  stamped: boolean;
}

const UNSTAMPED: BuildInfo = { commit: "unknown", stamped: false };

/**
 * Derive build identity from the environment.
 *
 * @param env - Worker bindings; `BUILD_SHA` is set at upload time.
 */
export function buildInfo(env: { BUILD_SHA?: string }): BuildInfo {
  const raw = env.BUILD_SHA?.trim().toLowerCase();
  // Covers absent, empty, whitespace-only, short, over-long, and non-hex in
  // one check. A value that is not a commit is not evidence of a build, and
  // reporting it as one would be a claim it cannot support.
  if (!raw || !COMMIT_SHA_RE.test(raw)) return UNSTAMPED;
  return { commit: raw, stamped: true };
}
