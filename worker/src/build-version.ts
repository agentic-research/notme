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

/** A Cloudflare Worker version id (a UUID). */
const VERSION_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * The Cloudflare VERSION serving this request, from the version-metadata
 * binding (`[version_metadata] binding = "CF_VERSION_METADATA"`), or
 * `"unknown"` when the binding is absent or malformed (notme-325916, review M5).
 *
 * WHY BOTH THIS AND THE COMMIT. Two versions can share a commit — a config- or
 * secret-only re-upload, the same commit uploaded twice — so a pinned probe that
 * Cloudflare silently routed to the OLD version could still report the
 * expected commit. The version id cannot collide that way: Cloudflare mints a
 * new one per upload. `worker-verify.sh` compares it whenever it is known.
 *
 * Same fail-honest rule as `buildInfo`: never a guess, never an omitted field.
 */
export function versionId(env: { CF_VERSION_METADATA?: { id?: unknown } }): string {
  const id = env.CF_VERSION_METADATA?.id;
  return typeof id === "string" && VERSION_ID_RE.test(id.toLowerCase()) ? id.toLowerCase() : "unknown";
}

/**
 * The version id to PUBLISH on this request, or undefined to omit it
 * (notme-325916, re-review N2).
 *
 * Cloudflare honours `Cloudflare-Workers-Version-Overrides` for any client.
 * Version ids are random UUIDs, so before this endpoint served one an outsider
 * could not pin; serving it unconditionally would let anyone collect both ids
 * during a canary and pin themselves to either — including staying on the OLD
 * build through the canary of a security fix. So the id is served only when
 * the request's own override header already names it: the caller proves it
 * knows the id, and learns only that its pin landed. worker-verify.sh always
 * sends the pin, so verification is unaffected.
 *
 * This is the one deliberate exception to "never omit a field": an omitted
 * version_id means "not disclosed to you", which the verifier treats as
 * "not proven" rather than as a match.
 */
export function disclosedVersionId(
  env: { CF_VERSION_METADATA?: { id?: unknown } },
  overrideHeader: string | null,
): string | undefined {
  const id = versionId(env);
  if (id === "unknown" || !overrideHeader) return undefined;
  // Dictionary values are quoted strings; compare exact values, not substrings.
  const named = [...overrideHeader.matchAll(/=\s*"([^"]*)"/g)].map((m) => m[1].toLowerCase());
  return named.includes(id) ? id : undefined;
}
