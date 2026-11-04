#!/usr/bin/env bash
# worker-promote.sh — route 100% of an environment's traffic to ONE version,
# only if that exact version has passed a pinned verify (notme-16b2d5).
#
# Invoked by `task worker:promote NEW=<version-id> ENV=<production|staging>`,
# which passes its values as ARGUMENTS:
#   worker-promote.sh --env <production|staging> --new <id>
#                     [--allow-unverified '<reason>' --expect <sha>]
#
# ── WHY IT IS A GATE AND NOT A ONE-LINER ──
# It used to be `wrangler versions deploy NEW@100% --yes` behind a single
# precondition: that NEW was a non-empty string. Cloudflare keeps every
# uploaded version, so the reachable set was every artifact ever pushed to the
# account — including ones uploaded before any gate existed, by someone else,
# from a branch that never passed staging. And ENV defaulted to production when
# omitted, so a staging rehearsal with a dropped `ENV=staging` promoted prod.
#
# ── WHAT COUNTS AS EVIDENCE ──
# A record at $NOTME_EVIDENCE_DIR/<env>/<version-id>.json, written ONLY by
# scripts/worker-verify.sh when it ran PINNED to that version (Cloudflare's
# version-override header), every pinned check was answered by that version's
# own build, and Cloudflare listed the version as serving (notme-325916). A
# sampled, unpinned verify never writes one. The record must be:
#   - for exactly this version, environment and host, result=pass, pinned;
#   - younger than EVIDENCE_TTL_HOURS (24). A soak says the version worked
#     against the DO state, secrets and dependencies of that day. After a day,
#     any of those may have moved — a rotated key, a changed secret, a
#     dependency's new behaviour — so the record is re-earned by a fresh pinned
#     soak rather than trusted indefinitely (review M4). 24h fits the
#     soak-then-promote day this is for; rollbacks to older versions use
#     `task worker:rollback`.
# A failed post-promote check deletes NEW's record, so the same broken version
# cannot walk back through the gate on its old pass.
#
# TRUST MODEL, stated plainly: the record is a local file. This gate stops the
# accident-shaped failures (wrong id, wrong env, never-verified or stale
# artifact); it does not stop an operator who forges a JSON file.
#
# ── THE OVERRIDE ──
# --allow-unverified '<reason>' skips the evidence check for emergencies. It
# requires a real reason (>= 12 chars), an explicit --expect <40-hex build sha>
# (there is no record to read it from, and the post-promote verify needs to
# know which build should answer), and appends to $NOTME_EVIDENCE_DIR/overrides.log.
#
# ── SELECTORS COME FROM THE COMMAND LINE ──
# A value equal to an exported shell variable of the same name (ENV, NEW,
# EXPECT, ALLOW_UNVERIFIED) is refused: Task fills template variables from the
# environment, so a stale `export ENV=production` would otherwise satisfy
# "ENV is required" (review M6). See scripts/lib/selectors.sh.
#
# ── FAILURE ACTION ──
# The rollback target (PREV) is resolved BEFORE deploying, as the highest-
# percentage version that is not NEW. If it cannot be resolved, nothing is
# deployed (review M2, M3). After the deploy: await convergence on the expected
# build, then verify pinned to NEW. If either fails — or the run is interrupted
# (INT/TERM/HUP, review L3, re-review N3) — PREV is promoted back and the script exits non-zero.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/selectors.sh
. "$ROOT/scripts/lib/selectors.sh"
EVIDENCE_DIR="${NOTME_EVIDENCE_DIR:-$ROOT/.release-evidence}"
EVIDENCE_TTL_HOURS=24

die() { echo "✗ worker:promote: $*" >&2; exit 1; }

NEW="" ENV_NAME="" ALLOW_UNVERIFIED="" EXPECT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --env) ENV_NAME="${2:-}"; shift 2 ;;
    --new) NEW="${2:-}"; shift 2 ;;
    --allow-unverified) ALLOW_UNVERIFIED="${2:-}"; shift 2 ;;
    --expect) EXPECT="${2:-}"; shift 2 ;;
    *) die "unknown argument '$1'" ;;
  esac
done
refuse_exported ENV "$ENV_NAME"
refuse_exported NEW "$NEW"
refuse_exported EXPECT "$EXPECT"
refuse_exported ALLOW_UNVERIFIED "$ALLOW_UNVERIFIED"

# Test seams. Loud when set, because each one replaces a safety step.
VERIFY_CMD="${NOTME_PROMOTE_VERIFY_CMD:-bash $ROOT/scripts/worker-verify.sh}"
CONVERGE_CMD="${NOTME_PROMOTE_CONVERGE_CMD:-pnpm exec tsx $ROOT/scripts/await-convergence.ts}"
[ -n "${NOTME_PROMOTE_VERIFY_CMD:-}" ] && echo "⚠ NOTME_PROMOTE_VERIFY_CMD overrides the post-promote verify: $VERIFY_CMD" >&2
[ -n "${NOTME_PROMOTE_CONVERGE_CMD:-}" ] && echo "⚠ NOTME_PROMOTE_CONVERGE_CMD overrides convergence: $CONVERGE_CMD" >&2

# ── target: explicit, never defaulted (bead comment, Finding D) ──
case "$ENV_NAME" in
  production)
    ENV_FLAGS=()
    AUTH_BASE="https://auth.notme.bot"
    SITE_BASE="https://notme.bot"
    ;;
  staging)
    ENV_FLAGS=(--env staging)
    AUTH_BASE="https://auth-staging.notme.bot"
    SITE_BASE="https://staging.notme.bot"
    ;;
  "") die "ENV=production or ENV=staging is required on the task command line — neither environment is reachable by omission" ;;
  *) die "ENV must be 'production' or 'staging' (got '$ENV_NAME')" ;;
esac

UUID_RE='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
[[ "$NEW" =~ $UUID_RE ]] || die "NEW=<version-id> must be a full version id (task worker:versions ENV=$ENV_NAME to list); got '$NEW'"

wrangler() { (cd "$ROOT/worker" && pnpm exec wrangler "$@"); }

# ── the gate ──
RECORD="$EVIDENCE_DIR/$ENV_NAME/$NEW.json"
if [ -n "$ALLOW_UNVERIFIED" ]; then
  [ "${#ALLOW_UNVERIFIED}" -ge 12 ] || die "ALLOW_UNVERIFIED must state the reason (>= 12 chars), not just be set"
  [[ "$EXPECT" =~ ^[0-9a-f]{40}$ ]] || die "an unverified promotion needs EXPECT=<40-hex build sha> of $NEW (wrangler versions view $NEW shows BUILD_SHA)"
  mkdir -p "$EVIDENCE_DIR"
  printf '%s\t%s\t%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(id -un 2>/dev/null || echo unknown)" "$ENV_NAME" "$NEW" "$ALLOW_UNVERIFIED" >> "$EVIDENCE_DIR/overrides.log"
  {
    echo "!!! UNVERIFIED PROMOTION of $NEW to $ENV_NAME — no pinned verify evidence checked"
    echo "!!! reason: $ALLOW_UNVERIFIED"
    echo "!!! logged to $EVIDENCE_DIR/overrides.log"
  } >&2
else
  [ -f "$RECORD" ] || die "no verify evidence for $NEW in $ENV_NAME ($RECORD).
  Produce it with a pinned soak while $NEW is in the deployment:
    task worker:canary NEW=$NEW OLD=<current-id> ENV=$ENV_NAME
    task worker:verify VERSION=$NEW ENV=$ENV_NAME
  Emergency only: ALLOW_UNVERIFIED='<reason>' EXPECT=<sha>"
  # Every field is checked, not just existence: a renamed file, a sampled run,
  # a failed run or a stale one must not read as a pass.
  EXPECT="$(node -e '
    const [file, version, env, authBase, ttlH] = process.argv.slice(1);
    const r = JSON.parse(require("fs").readFileSync(file, "utf8"));
    const bad = [];
    if (r.schema !== "notme.release-evidence/v1") bad.push("schema");
    if (r.result !== "pass") bad.push("result=" + r.result);
    if (r.pinned !== true) bad.push("not pinned (a sampled verify is not evidence about one version)");
    if (r.version !== version) bad.push("version=" + r.version);
    if (r.env !== env) bad.push("env=" + r.env);
    // A pass against a stub or a local Worker is not a pass against this env.
    if (r.auth_base !== authBase) bad.push("auth_base=" + r.auth_base);
    if (!/^[0-9a-f]{40}$/.test(r.commit || "")) bad.push("commit");
    const age = Date.now() - Date.parse(r.checked_at);
    if (!(age >= 0 && age <= Number(ttlH) * 3600_000)) bad.push("checked_at " + r.checked_at + " is older than " + ttlH + "h (or unreadable) — re-run the pinned soak");
    if (bad.length) { console.error("evidence record rejected: " + bad.join(", ")); process.exit(1); }
    if (r.version_id_checked !== true) console.error("⚠ evidence identified the version by build commit + deployment listing only — the Worker served no version_id (add [version_metadata] to wrangler.toml)");
    console.error("evidence: pinned verify passed for " + version + " (" + env + ", build " + r.commit.slice(0, 12) + ") at " + r.checked_at);
    process.stdout.write(r.commit);
  ' "$RECORD" "$NEW" "$ENV_NAME" "$AUTH_BASE" "$EVIDENCE_TTL_HOURS")" || die "evidence record for $NEW is not a fresh pinned pass ($RECORD)"
fi

# ── the rollback target, resolved BEFORE anything changes ──
STATUS="$(wrangler deployments status --json ${ENV_FLAGS[@]+"${ENV_FLAGS[@]}"} 2>/dev/null)" \
  || die "cannot read the current deployment (wrangler deployments status failed) — no rollback target, so nothing was deployed"
PREV="$(printf '%s' "$STATUS" | node -e '
  const newId = process.argv[1];
  let s = ""; process.stdin.on("data", (d) => (s += d)).on("end", () => {
    try {
      const v = (JSON.parse(s).versions || [])
        .filter((x) => x.version_id && x.version_id !== newId)
        .sort((a, b) => b.percentage - a.percentage);
      process.stdout.write(v.length ? v[0].version_id : "");
    } catch { /* unparseable — empty, refused below */ }
  });
' "$NEW")"
[[ "$PREV" =~ $UUID_RE ]] || die "no rollback target: the current $ENV_NAME deployment lists no version other than $NEW — nothing was deployed"

rollback() {
  # Nothing may interrupt a rollback: a second Ctrl-C reaches the whole
  # foreground process group, and killing the rollback's wrangler would leave
  # NEW at 100%. Ignored dispositions are inherited by the child (re-review N3).
  trap '' INT TERM HUP
  # Delete NEW's record FIRST: the version just failed, and if the rollback
  # deploy fails too, `set -e` exits — its old pass must not survive that.
  rm -f "$RECORD"
  echo "▸ rolling back: promoting prior version $PREV to 100% (removed $RECORD)" >&2
  wrangler versions deploy "$PREV@100%" ${ENV_FLAGS[@]+"${ENV_FLAGS[@]}"} --yes
  echo "✗ rolled back to $PREV. Confirm with: task worker:verify ENV=$ENV_NAME" >&2
}

echo "▸ promoting $NEW to 100% of $ENV_NAME (expected build ${EXPECT:0:12}; rollback target: $PREV)"
# From here until the verdict, an interrupt must not leave NEW at 100% unchecked.
# shellcheck disable=SC2317,SC2329  # invoked by the trap
on_interrupt() {
  echo "✗ interrupted after the deploy" >&2
  # Async children ignore SIGINT in a non-interactive shell; stop the checks
  # explicitly so nothing keeps probing after the rollback.
  if [ -n "${CHECK_PID:-}" ]; then
    pkill -TERM -P "$CHECK_PID" 2>/dev/null || true
    kill "$CHECK_PID" 2>/dev/null || true
  fi
  rollback
  exit 130
}
trap on_interrupt INT TERM HUP
wrangler versions deploy "$NEW@100%" ${ENV_FLAGS[@]+"${ENV_FLAGS[@]}"} --yes

post_check() {
  $CONVERGE_CMD --auth-base "$AUTH_BASE" --expect "$EXPECT" &&
    $VERIFY_CMD --env "$ENV_NAME" --auth-base "$AUTH_BASE" --site-base "$SITE_BASE" --version "$NEW" --expect "$EXPECT"
}

# Run the checks in the background and wait: bash defers a trap until the
# foreground child exits, so a Ctrl-C during the multi-minute convergence
# would otherwise do nothing until convergence gave up.
post_check &
CHECK_PID=$!
if wait "$CHECK_PID"; then
  trap - INT TERM HUP
  echo "✓ $NEW is serving 100% of $ENV_NAME and passed pinned verify"
  exit 0
fi
echo "✗ post-promote convergence/verify FAILED for $NEW in $ENV_NAME" >&2
rollback
exit 1
