#!/usr/bin/env bash
# worker-promote.sh — route 100% of an environment's traffic to ONE version,
# only if that exact version has passed a pinned verify (notme-16b2d5).
#
# Invoked by `task worker:promote NEW=<version-id> ENV=<production|staging>`.
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
# version-override header) and every pinned check was answered by that
# version's own build (identity-bracketed against /.well-known/version). A
# sampled, unpinned verify never writes one: at a 10/90 split it is evidence
# about whichever version answered, which was measured to be the OLD one 85
# times out of 85 (notme-325916). The pinned run that produces the record is
# `task worker:verify VERSION=<id> ENV=<env>` during the canary split.
#
# Every version promoted through this gate is re-verified pinned at 100%, which
# refreshes its record — so rolling back to a version that was once promoted
# here passes the gate without the override.
#
# TRUST MODEL, stated plainly: the record is a local file. This gate stops the
# accident-shaped failures (wrong id, wrong env, never-verified artifact); it
# does not stop an operator who forges a JSON file. It is a typed, deliberate
# act either way — which is the property the bead asked for.
#
# ── THE OVERRIDE ──
# ALLOW_UNVERIFIED="<reason>" skips the evidence check for emergencies. It
# requires a real reason (>= 12 chars), an explicit EXPECT=<40-hex build sha>
# (there is no record to read it from, and the post-promote verify needs to
# know which build should answer), and appends to $NOTME_EVIDENCE_DIR/overrides.log.
#
# ── FAILURE ACTION ──
# After the deploy: await convergence on the expected build, then verify pinned
# to NEW. If either fails, the version that held traffic BEFORE the promote is
# promoted back (same mechanism — ADR-018's rollback), and the script exits 1.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVIDENCE_DIR="${NOTME_EVIDENCE_DIR:-$ROOT/.release-evidence}"
NEW="${NEW:-}"
ENV_NAME="${ENV:-}"
ALLOW_UNVERIFIED="${ALLOW_UNVERIFIED:-}"
EXPECT="${EXPECT:-}"

die() { echo "✗ worker:promote: $*" >&2; exit 1; }

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
  "") die "ENV=production or ENV=staging is required — neither environment is reachable by omission" ;;
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
  # or a failed run must not read as a pass.
  EXPECT="$(node -e '
    const [file, version, env, authBase] = process.argv.slice(1);
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
    if (bad.length) { console.error("evidence record rejected: " + bad.join(", ")); process.exit(1); }
    console.error("evidence: pinned verify passed for " + version + " (" + env + ", build " + r.commit.slice(0, 12) + ") at " + r.checked_at);
    process.stdout.write(r.commit);
  ' "$RECORD" "$NEW" "$ENV_NAME" "$AUTH_BASE")" || die "evidence record for $NEW is not a pinned pass ($RECORD)"
fi

# ── who holds traffic now: the rollback target ──
PREV="$(wrangler deployments status --json ${ENV_FLAGS[@]+"${ENV_FLAGS[@]}"} 2>/dev/null | node -e '
  let s = ""; process.stdin.on("data", (d) => (s += d)).on("end", () => {
    try {
      const v = (JSON.parse(s).versions || []).slice().sort((a, b) => b.percentage - a.percentage);
      process.stdout.write(v.length ? v[0].version_id : "");
    } catch { /* unknown — reported below */ }
  });
')" || PREV=""

echo "▸ promoting $NEW to 100% of $ENV_NAME (expected build ${EXPECT:0:12}; prior: ${PREV:-unknown})"
wrangler versions deploy "$NEW@100%" ${ENV_FLAGS[@]+"${ENV_FLAGS[@]}"} --yes

post_check() {
  AUTH_BASE="$AUTH_BASE" EXPECT="$EXPECT" VERSION="$NEW" $CONVERGE_CMD &&
    AUTH_BASE="$AUTH_BASE" SITE_BASE="$SITE_BASE" ENV="$ENV_NAME" VERSION="$NEW" EXPECT="$EXPECT" $VERIFY_CMD
}

if post_check; then
  echo "✓ $NEW is serving 100% of $ENV_NAME and passed pinned verify"
  exit 0
fi

echo "✗ post-promote convergence/verify FAILED for $NEW in $ENV_NAME" >&2
if [ -n "$PREV" ] && [ "$PREV" != "$NEW" ]; then
  echo "▸ rolling back: promoting prior version $PREV to 100%" >&2
  wrangler versions deploy "$PREV@100%" ${ENV_FLAGS[@]+"${ENV_FLAGS[@]}"} --yes
  echo "✗ rolled back to $PREV. Confirm with: task worker:verify ENV=$ENV_NAME" >&2
else
  echo "✗ NOT rolled back — prior version unknown. Run: task worker:versions ENV=$ENV_NAME, then promote the old id" >&2
fi
exit 1
