<!--
@doc-check
@endpoints: POST /token, GET /health, GET /internal/ca-bundle
-->
# ADR-018: Goal Zero release promotion — staging → promote → converge → verify

**Status:** accepted; canary phase deleted 2026-08-27 (`notme-9f2f79`) — see the CORRECTION in Phase 2
**Beads:** notme-cf288e (this plan), notme-bed754 (Goal Zero epic)
**Audits it serves:** notme-c0a37e (runtime/deployment proof), notme-c0a4f6 (release/package verification), notme-c0a4aa (cross-repo convergence)

## Context

Notme releases along **two artifact planes** with different promotable units:

1. **Service plane** — the Worker serving `auth.notme.bot` + `notme.bot`.
   The promotable unit is a **Cloudflare version id**: immutable once
   uploaded, promoted by shifting traffic — never rebuilt between stages.
2. **Artifact plane** — what other repos consume: OCI images
   (`ghcr.io/agentic-research/notme{,-proxy}`), the npm verifier SDK
   (`@agentic-research/dpop`), the GHA action + reusable workflow
   (`gha-identity.yml`), and the `server.json` package-identity manifest.
   The promotable unit is a **git tag** (`v*` / `dpop-v*`); publish jobs
   verify what they push (cosign keyless + SBOM attest, npm provenance).

Before this ADR there was no pre-production runtime and no canary mechanism:
`task ship-prod` went install → check → deploy → verify, entirely against
production. The gap this closes: a staged path where the *same* artifact
gathers evidence before it takes 100% of traffic, with rollback triggers
that name the command to run.

## What shipped with this ADR

- **Staging environment** (`[env.staging]` — committed in
  `worker/wrangler.toml.example`, the template for the gitignored live
  `worker/wrangler.toml`): a fully
  separate Worker `notme-bot-staging` at `staging.notme.bot` +
  `auth-staging.notme.bot` with its **own** SigningAuthority DO (own CA key,
  born in staging), own RevocationAuthority, own KV — and deliberately **no
  `VPC_AUTH` binding**, so staging can never proxy traffic to the production
  signet backend (worker.ts guards `if (env.VPC_AUTH)` and 503s instead).
  > **CORRECTION (2026-11-02, `notme-c16e0d`).** The isolation holds (pinned
  > by `staging-isolation.test.ts`), but the fallthrough is a constant
  > **404** `{"error":"not_found"}`, not a 503. The 503 was removed
  > (`notme-cb0354`) because it made an unmatched path answer differently
  > depending on whether a VPC binding existed, and disclosed deployment
  > state to unauthenticated callers.
- **Config-driven authority host** (`authorityHostFromEnv` in
  `worker/worker.ts`): the authority surface is selected by
  `SIGNET_AUTHORITY_URL`'s host in addition to the hardcoded
  `auth.notme.bot` match, so staging serves the real authority code path.
  Production behavior is unchanged (the var names the host the hardcode
  already matched); pinned by `worker/src/__tests__/authority-host.test.ts`.
- **Shared verify definition**: `task worker:verify` is parameterized by
  `AUTH_BASE`/`SITE_BASE`; `worker:verify-staging` runs the *same* checks
  against staging. One definition of "the service works," two targets.
- **Canary/promote tasks**: `worker:versions`, `worker:canary NEW= OLD=
  ENV= [PCT=10]`, `worker:promote NEW= ENV=` wrap Cloudflare gradual deployments so
  the promotion unit is an explicit version id, and rollback is the same
  command pointed at the old id.

## Promotion phases

### Phase 0 — PR CI (structural gate)

Every PR, no exceptions (`.github/workflows/ci.yml`):

| Gate | Command | Catches |
|---|---|---|
| SHA-pin check | `task pin:check` | mutable action refs (supply chain) |
| Types + tests | `task worker:check` | tsc (src + pool tests) then both vitest suites — the plain suite and the real-Worker/DO pool suite |
| Dependency audit | `task worker:audit` | known-vuln production deps |
| Doc/bead integrity | `task docs:check` | claims citing dead code/beads |
| Package manifest | `task server:check` | server.json schema/version drift |
| Proxy | `task proxy:check` | Rust build/test/clippy |
| Runtime contract | `task worker:contract` | the real Worker booted locally (`wrangler dev`, config derived from `wrangler.toml.example`, real DOs in local storage) answering `worker:verify`'s checks — before this, that contract only ran after a deploy (`notme-6ae724`) |

**Entry:** PR opened. **Exit:** all green. **No rollback concept** — nothing
deployed.

**After merge, optionally:** `.github/workflows/staging-smoke.yml` deploys `main`
to staging and runs `worker:await-convergence` + `worker:verify-staging`. It
is **skipped** (grey, not green, with a warning) until the owner configures
the `staging` GitHub environment, and it never runs on pull requests or off
`main`. Its token can deploy *production* too — Cloudflare API tokens scope to
an account or zone, not to one Worker script — so a deployment-branch policy
of `main` only on that environment is mandatory. Every staging var comes from
the environment (`scripts/staging-config.ts`), and the deploy refuses if any
template placeholder survives in a staging table: `wrangler deploy` makes the
config's vars authoritative, and the template's `GHA_ALLOWED_OWNERS =
"your-staging-org"` names an org anyone could register.

### Phase 1 — Staging

**Entry:** change merged to `main` (or a release branch cut for the tag).
**Command:** `task ship-staging` (install → check → docs → deploy staging →
verify staging).

**Exit criteria (all must hold):**
- `worker:verify-staging` green — same checks as production verify,
  including the config-leak check (staging docs page must render staging
  hosts, not production hosts).
- Staging discovery serves `"issuer": "https://auth-staging.notme.bot"`,
  its own CA bundle (X.509, staging-born key), and its own JWKS kid.
- For identity-critical changes (anything under `worker/src/auth/`,
  `worker/src/signing-authority.ts`, `worker/src/cert-exchange.ts`): a
  manual token-path exercise against staging (`/token` DPoP flow) recorded
  in the PR or bead comment.

**Rollback trigger:** any exit criterion fails → fix forward on the branch;
staging carries no traffic, so rollback is redeploy. Staging state is
disposable by design (its CA is not trusted by anything).

### Phase 2 — Promote, converge, verify (production)

> **CORRECTION (2026-08-27, `notme-9f2f79`).** This phase previously specified
> a bounded-exposure canary: a 10/90 gradual deployment, a 30-minute-to-24-hour
> soak, and pre-promotion smoke tests routed to the new version with the
> `Cloudflare-Workers-Version-Overrides` header. It is deleted, for a measured
> reason and a documented one.
>
> **Measured:** the gate failed twice, independently, and both failures
> reported the OLD version's behaviour while appearing to measure the new one.
> A 10/90 split confirmed active served 85/85 samples from the old version
> (~0.01% by chance, caching ruled out). The override header, adopted as the
> replacement, then routed a pre-promotion probe to the old version wearing
> the new version's label — which read as "the fix doesn't work" for a fix
> that did (production `91b54069`, 2026-08-06).
>
> **Documented:** per Cloudflare's version-overrides documentation, an
> override *"will only be applied if the specified version is in the current
> deployment"*, and when not applied the request *silently falls back to the
> deployment's percentage routing*. An uploaded-but-not-yet-deployed version
> is not in the current deployment, so the exact pre-promotion smoke test this
> phase prescribed was outside the tool's contract — and the tool's documented
> failure mode is indistinguishable from "no change". The 85/85 gradual-split
> sample remains unexplained and is not blamed on plan gating or anything
> else; it is simply recorded.
>
> A gate that cannot prove *which version answered* manufactures confidence
> in whatever is already running. That is worse than no gate, so the phase is
> removed rather than repaired. Nothing may be reintroduced here without first
> demonstrating, by measurement against `/.well-known/version`, that traffic
> splitting on this Worker routes as configured.

> **CORRECTION (2026-11-03, `notme-325916`) — the canary returns as a PINNED
> soak, and the measurement is built into every run.** The deletion's
> condition is met by construction rather than by a one-off demonstration:
> `task worker:verify VERSION=<id> ENV=<env>` sends
> `Cloudflare-Workers-Version-Overrides: <worker>="<id>"` on every probe AND
> brackets every check with a pinned `/.well-known/version` probe that must
> report the build `<id>` was uploaded from. Both documented failure modes
> now fail the run instead of reporting the old version's behaviour:
>
> - the override is ignored because `<id>` is not in the current deployment
>   (the pre-promotion probe of `91b54069`) → the opening bracket reports the
>   old build and the run stops;
> - unpinned sampling never reaches the canary (the 85/85) → irrelevant:
>   nothing in a pinned run is sampled.
>
> So the soak is run **after** `worker:canary` puts the version in the
> deployment, never before. A sampled `worker:verify` during a soak is a
> service-health check and is never evidence about the new version; it writes
> no record. Proven against a stub of Cloudflare's documented routing in
> `worker-verify-pinning.test.ts` (a broken canary fails the pinned soak under
> every routing of unpinned traffic; an ignored override fails closed).
>
> **Same-commit versions (security review M5).** The bracket above compares
> the build *commit*, and two versions can share one — a config- or
> secret-only re-upload, or the same commit uploaded twice. So a pinned run
> also (a) requires `wrangler deployments status` to list the version as
> serving, at the start and again before it writes evidence, and (b) compares
> the `version_id` that `/.well-known/version` now serves from the
> `[version_metadata]` binding, whenever the Worker reports one. The record
> says which (`version_id_checked`). Each pinned run first deletes any earlier
> record for that version, so a failed re-soak leaves no stale pass behind.
>
> **Not yet measured against Cloudflare.** The pinned path has not run against
> a real split since this change. The first run should be a staging
> rehearsal — `task worker:canary NEW=<id> OLD=<cur> ENV=staging`, then
> `task worker:verify VERSION=<id> ENV=staging`, then `task worker:promote
> NEW=<id> ENV=staging` — and until it is green, `ship-prod` remains the
> default production path.

**Entry:** Phase 1 green at the SHA being released.
**Command:** two paths, and only one of them is gated per version.

*Direct path* — `task ship-prod`: preflight → install → check → docs → deploy →
**await-convergence** → verify. The composite task is the gate. It does **not**
roll back by itself (its description used to say it did, and nothing
implemented it — `notme-16b2d5` Finding B); on a failed verify the new build is
still serving 100%, and the exit is `task worker:rollback`.

*Gated path* — promotion by version id:

```
task worker:deploy-preview                                 # upload; stamps BUILD_SHA; prints id
task worker:canary NEW=<id> OLD=<cur> ENV=production       # NEW enters the deployment
task worker:verify VERSION=<id> ENV=production             # pinned soak; writes evidence
task worker:promote NEW=<id> ENV=production                # refuses without that evidence
```

**Gated-path exit criteria.** A green `worker:verify VERSION=<id>` run —
pinned, every check bracketed by `/.well-known/version` reporting the build
`<id>` was uploaded from — taken while `<id>` is in the deployment. Its record
(`.release-evidence/production/<id>.json`) goes in the release evidence bundle.
An unpinned verify during the soak does not count. Run it from the checkout
that uploaded `<id>` (EXPECT defaults to `git rev-parse HEAD`), or pass
`EXPECT=<sha>`.

**The promotion gate (`notme-16b2d5`).** `worker:promote` used to be
`wrangler versions deploy NEW@100%` behind one precondition — that `NEW` was a
non-empty string — so any version in the account's upload history reached 100%
of production in one command, and an omitted `ENV` meant production. Now
(`scripts/worker-promote.sh`, pinned by `promote-gate.test.ts`):

- `ENV=production|staging` is mandatory on canary and promote, and must be
  typed on the task command line: Task fills `{{.ENV}}` from the environment,
  so a value equal to an exported shell variable of the same name is refused
  (`ENV`, `NEW`, `EXPECT`, `ALLOW_UNVERIFIED`; `scripts/lib/selectors.sh`).
  Neither environment is reachable by omission or by a stale `export`.
- promote refuses unless `.release-evidence/<env>/<version-id>.json` records a
  **pinned** verify pass for exactly that version in exactly that environment.
  Only `worker:verify VERSION=<id>` writes one; a sampled verify never does.
  The record **expires after 24 h**: a soak is evidence against that day's DO
  state, secrets and dependencies, any of which can move, so it is re-earned
  rather than trusted indefinitely.
- before deploying it resolves the rollback target — the highest-percentage
  version in the current deployment that is not `NEW` — and **refuses to
  deploy** if there is none or the deployment cannot be read.
- after the deploy it awaits convergence on the recorded build, then verifies
  pinned to `NEW`; if either fails, or the run is interrupted (INT/TERM), it
  **promotes the prior version back**, deletes `NEW`'s pass record so the
  same version cannot walk back through the gate on it, and exits non-zero.
  That is the defined failure action.
- the emergency override is `ALLOW_UNVERIFIED='<reason>' EXPECT=<sha>`: a
  typed reason, an explicit build sha, a loud banner, and a line appended to
  `.release-evidence/overrides.log`.

The record is a local file (the directory is gitignored). The gate stops the
accident-shaped failures — wrong id, wrong environment, never-verified
artifact — not an operator who forges JSON. Paste the record into the release
bead as part of the evidence bundle.

**The ordering is the design.** Identity first, behaviour second: the
convergence gate polls `/.well-known/version` (stamped with `BUILD_SHA` at
upload) until consecutive samples report the released SHA, distinguishing
"still converging" from "a different build is answering". Promotion is not
immediate — measured 2026-08-06, live traffic alternates between old and new
for roughly a minute after the API reports 100%, and `worker:verify` retries
for ~10 seconds, shorter than that window. Every behavioural check before
convergence is a check of an unknown version.

**What replaces bounded exposure.** Nothing pretends to. Production exposure
is bounded instead by: staging exercised with the *identical commands*
(`ENV=staging`), atomic promotion of a version already verified there, and a
rollback that is the same mechanism as promotion. Identity-critical changes
(auth/, signing-authority, cert-exchange, DPoP) take their soak on staging,
where a broken version costs nothing.

**Rollback:** `task worker:promote NEW=<old-id> ENV=production`, which runs
convergence against the OLD sha and a pinned verify itself — the convergence
caveat applies on the way back too, which is exactly when nobody wants to wait
for it. A version that was once promoted through the gate has a record (the
post-promote pinned verify refreshes it), so rolling back to it needs no
override. A version that reached traffic by `ship-prod` has none: use
`task worker:rollback`, or the override with its sha.

**Hard constraint (unchanged):** a version carrying a new `[[migrations]]`
entry promotes atomically anyway — Durable Object migrations do not split —
and deleted-class migrations do not roll back, so the rollback plan for a
migration-carrying release is reviewed *before* deploy.

### Phase 3 — Artifact publish

**Entry:** Phase 2 complete — the version is promoted, converged, and
verified.
**Command:**

```
git tag v<X.Y.Z> && git push --tags   # artifact plane
```

The tag drives `.github/workflows/release.yml`: both OCI images publish
independently (fail-isolated), cosign-signed **by digest** with keyless OIDC
identity, SBOM attested, and **verified in-job** against the exact workflow
identity. `task version:check` makes "publish a version server.json doesn't
declare" structurally impossible. If the DPoP SDK changed:
`git tag dpop-v<X.Y.Z>` → trusted publishing + provenance verification
(`publish-dpop.yml`).

**Exit criteria:** release workflow green on both image legs;
provenance/signature verification steps green (they are part of the
workflows, not manual).

**Rollback:**
- Service: `task worker:promote NEW=<old-id> ENV=production` (or `task worker:rollback`).
- Images: previous tags remain; consumers pin digests (cloister fail-closed
  pinning refuses an unresolvable digest — ADR-0041), so a bad image is
  fixed by cutting `v<X.Y.Z+1>`, never by moving a tag.
- npm: versions are immutable — publish a patch; never unpublish a version
  consumers may have locked.

## Release evidence bundle

Recorded on the release bead (and linked from the PR) at each cut:

1. Git SHA + tag; PR URL; CI run URL (Phase 0).
2. `ship-staging` transcript tail + staging verify output (Phase 1).
3. Version id uploaded; the pinned-verify evidence record (`.release-evidence/<env>/<id>.json`) when the gated path was used; promote command + convergence proof (consecutive `/.well-known/version` samples at the released SHA)
   transcript (Phase 2–3).
4. Release workflow run URL; `cosign verify` / `verify-attestation` output
   (in-job); npm provenance attestation URL when dpop shipped.
5. Post-promotion `worker:verify` output.

## Naming

- **Branches:** `feat/*`, `fix/*`, `chore/*` as today; release-prep PRs
  from `release/v<X.Y.Z>` when a release needs more than one commit.
- **Tags:** `v<X.Y.Z>` = service + images (the `v` is stripped for image
  tags — cloister compatibility, see release.yml header); `dpop-v<X.Y.Z>`
  = npm SDK. rc tags (`v<X.Y.Z>-rcN`) exercise the release workflow
  without consuming a release version.
- **PRs:** titled `[bead-id] type(scope): description` matching commit
  convention (Golden Rule 11).

## Cross-repo compatibility matrix

Verified against consumer source this session (every row cites a real
reference in the consumer repo, not a doc claim). Coupling: **blocking** =
consumer breaks at its own build/runtime if this drifts; **advisory** =
comment/doc contract only, nothing enforces it.

| Surface | Consumer (evidence) | Pin | Coupling |
|---|---|---|---|
| `@agentic-research/dpop` npm | cloister + canonical-hours `package.json` | `0.3.0` exact (npm latest 0.4.0) | blocking (build+runtime) — decoupled by its own `dpop-v*` tag lane |
| `server.json` | cloister `cluster.toml` @v0.2.0 commit + sha256 lock | content-pinned, digest-locked | blocking (deploy) — healthiest coupling in the graph |
| OCI images | cloister `cluster.compose.yaml` | `@sha256:` digests (recipes still tag-pin `notme:0.1.0`) | blocking (runtime) |
| `action/` GH Action | signet `gha-identity.yml` | SHA 88 commits behind HEAD, `action/` unchanged since — functionally current | blocking (CI) |
| HTTP: `/cert/gha`, `/.well-known/ca-bundle.pem`, `/.well-known/jwks.json` | signet `enroll.go`, rig `api.ts`, cloister `bundle-auth.ts`, canonical-hours | hostname only, no version pin | blocking (runtime) |
| CF RPC `JwtSigner` / `ReceiptSigner` entrypoints | cloister `wrangler.toml` | class name only — **no build-time check** | blocking (runtime) |
| `schema/identity.capnp` | cloister vendored copy | no drift today; sync gate is manual | blocking (build) when it drifts |
| `bundleCanonical` CBOR bytes + canonical `kid` derivation | signet `canonical.go`/`sigid`, cloister, LLO `kid.rs` | hand-copied fixture / comment-only | **advisory but should be blocking** — divergence silently breaks cross-implementation signature verification (notme-e9d2b8) |
| `gen/go`, `wasm/`, `packages/schema-bridge`, reusable `gha-identity.yml` workflow | **none** (verified: no `go.mod` requires gen/go; signet copied the workflow locally instead; LLO forked schema-bridge; cloister builds its own wasm) | — | zero-consumer — can move freely |

Release implication: the surfaces that can actually break a consumer on the
next promotion are the two RPC entrypoint class names + signatures
(runtime-only failure, no build check), the `/cert/gha` + `/.well-known/*`
HTTP contracts, `server.json` shape (cloister's resolver: artifact-only mode
+ multi-image `ociBundles` are driven solely by notme), and OCI image
identity. Sequencing rule: a release changing any of those names the
consumer bead/PR that absorbs it *before* Phase 3; everything touching only
zero-consumer surfaces is parallel work.

## Current-state findings (verified this session)

Infrastructure:

- Staging deployed and verified live: `notme-bot-staging` version
  `f6a4ac4b-64e0-41eb-81fa-f3be8ae28b7f`, 12/12 verify checks green,
  discovery issuer/CA/JWKS all staging-local, no VPC binding. Production
  verify green (12/12) with the parameterized task. Custom-domain DNS
  propagates within minutes (negative-cache lag on first lookup expected).
- **The canary → rollback cycle was exercised end-to-end on staging**, via
  the same `ENV=`-parameterized tasks that drive production
  (notme-c0a37e's deploy/rollback evidence clause):
  `wrangler versions upload --env staging` → version
  `d0cc333f` uploaded carrying no traffic → `task worker:canary NEW=d0cc333f
  OLD=f4f2468c PCT=20 ENV=staging` → split confirmed in
  `wrangler deployments list` (20%/80%) with all 12 verify checks green
  *during* the split → `task worker:promote NEW=f4f2468c ENV=staging` →
  100% back on the old id, 12/12 green. Rollback is the promote command
  pointed at the old id, demonstrated, not asserted. Preconditions were
  confirmed to fail safe when a version id is omitted.
- `task node:preflight` closes notme-8bea0d: the release path now fails
  before install with explicit remediation on an unsupported local Node
  (reproduced + fixed on v25.9.0; CI pins Node 22 and is unaffected).

Open defects re-verified against HEAD (all cited file:line evidence lives
on the beads):

- notme-92a1b9 **still present** — `POST /cert` bootstrap burns the
  single-use code without persisting any principal.
- notme-976385 **still present** — a fresh authority can be permanently
  stranded; corrected on the bead: the third consumer is `POST /cert`
  (cert-exchange.ts), not `/auth/oidc/login`. Composes with notme-92a1b9
  into one first-boot failure mode: three routes burn the code, one
  creates an admin, none regenerate.
- notme-ebc9af **still present** — `/cert/passkey` hardcodes
  `authMethod: "passkey"` for any session kind; scope containment holds,
  so provenance defect, not escalation.
- notme-2bba44 **partially fixed** — ADR-013 PKCE path shipped; the
  legacy `?token=` branch stays until rig merges its worktree
  (rig-notme-2bba44-pkce, commit d429224).
- notme-d86ed3 **review complete** — RFC 9449 checks verified present and
  ordered at the token endpoint; review banked on the bead. Two posture
  facts: DPoP nonce is off by default (RFC 9449 §8 freshness is opt-in),
  and `ath` is deliberately a resource-server claim, enforced by the SDK.
- Bootstrap single-use invariant has **no real-DO test** — the four tests
  that appear to cover it simulate locally, one documents behavior the DO
  doesn't have (notme-e9f809).

## New / updated beads (this session)

| Bead | What | Depends on / serialize with |
|---|---|---|
| notme-e68579 | staging + canary implementation (this PR) | — |
| notme-e9d2b8 (P1) | ADR-010 canonical CBOR fixture gate — never built | parallel to identity fixes |
| notme-e9f809 (P1) | real-DO bootstrap-code lifecycle test | serialize with notme-92a1b9, notme-976385 (shared signing-authority.ts scope); write as their regression harness |
| notme-ea3efc (P2) | stale cross-repo doc citations | dedupe ADR-010 half with notme-e9d2b8 |
| notme-ea5c65 (P2) | zero-consumer surface disposition (gen/go, wasm/, schema-bridge, reusable workflow) | parallel — zero-consumer surfaces block nothing |
| notme-ea76bb (P2) | notme.bot contract byte-diff enforcement broken | parallel |
| rig-eb1731 (P2) | rig's third vendored dpop copy → npm package | coordinate with rig PKCE worktree (notme-2bba44) |

Parallelization: notme-92a1b9 + notme-976385 + notme-e9f809 share
`worker/src/signing-authority.ts`/`worker/worker.ts` scope and serialize;
everything else above is dispatchable in parallel.

## GO / NO-GO

**GO for the promotion *mechanism*** — staging + canary + rollback shipped
and exercised this session (staging live-verified 12/12; canary tooling
dry-verified read-only against production).

**NO-GO for cutting `v0.3.0` today** — re-verified P1 identity beads are
open: the bootstrap first-boot failure mode (notme-92a1b9 + notme-976385,
one composed defect), cert provenance honesty (notme-ebc9af), the untested
bootstrap invariant (notme-e9f809), and the cross-implementation canonical
fixture gate (notme-e9d2b8). Goal Zero's exit criteria (notme-bed754)
require each closed, linked to a prerequisite, or deliberately deferred
with rationale. The first release through this pipeline should be cut only
when the epic's audit beads (notme-c0a37e, notme-c0a445, notme-c0a4aa,
notme-c0a4f6) report.
