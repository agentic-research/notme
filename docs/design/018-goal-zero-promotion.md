<!--
@doc-check
@endpoints: POST /token, GET /health, GET /internal/ca-bundle
-->
# ADR-018: Goal Zero release promotion — staging → canary → production

**Status:** accepted (staging environment + canary tasks shipped in this PR)
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
  [PCT=10]`, `worker:promote NEW=` wrap Cloudflare gradual deployments so
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

**Entry:** PR opened. **Exit:** all green. **No rollback concept** — nothing
deployed.

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

### Phase 2 — Beta / canary (production traffic, bounded)

**Entry:** Phase 1 green at the SHA being released.
**Commands:**

```
task ship                      # uploads the version — prints the version id
task worker:versions           # confirm NEW (just uploaded) and OLD (current)
task worker:canary NEW=<id> OLD=<id> PCT=10
```

The same three tasks take `ENV=staging`, so the canary path is **rehearsed
on staging with the identical commands** that promote production — not a
staging rehearsal of a different mechanism.

**Soak:** minimum 30 minutes at 10% for routine changes; 24 hours for
identity-critical changes (auth/, signing-authority, cert-exchange, DPoP).
During soak: `task worker:verify` (may hit either version — both must hold
the contract) and `wrangler tail --env production`/CF invocation logs for
error-rate deltas.

**Exit criteria:** verify green during soak; no new error signatures in
invocation logs; no revocation/DO alarm anomalies.

**Rollback triggers (any one):**
- `worker:verify` failure attributable to the new version
- new 5xx signature or error-rate increase in invocation logs
- any cryptographic-surface anomaly (JWKS/ca-bundle/token mint divergence)

**Rollback command:** `task worker:promote NEW=<old-id>` — the same
mechanism as promotion, no special path, no rebuild.

**Hard constraint:** a version carrying a new `[[migrations]]` entry
**cannot** be split-deployed — Durable Object migrations promote atomically,
and deleted-class migrations do not roll back. Releases that add migrations
skip canary (documented in the release PR) and use `task worker:deploy` +
immediate `worker:verify`, with the rollback plan reviewed *before* deploy.

### Phase 3 — Production promotion + artifact publish

**Entry:** Phase 2 exit criteria met.
**Commands:**

```
task worker:promote NEW=<id>   # 100% traffic to the soaked version id
task worker:verify             # production smoke, post-promotion
git tag v<X.Y.Z> && git push --tags   # artifact plane
```

The tag drives `.github/workflows/release.yml`: both OCI images publish
independently (fail-isolated), cosign-signed **by digest** with keyless OIDC
identity, SBOM attested, and **verified in-job** against the exact workflow
identity. `task version:check` makes "publish a version server.json doesn't
declare" structurally impossible. If the DPoP SDK changed:
`git tag dpop-v<X.Y.Z>` → trusted publishing + provenance verification
(`publish-dpop.yml`).

**Exit criteria:** verify green at 100%; release workflow green on both
image legs; provenance/signature verification steps green (they are part of
the workflows, not manual).

**Rollback:**
- Service: `task worker:promote NEW=<old-id>` (or `task worker:rollback`).
- Images: previous tags remain; consumers pin digests (cloister fail-closed
  pinning refuses an unresolvable digest — ADR-0041), so a bad image is
  fixed by cutting `v<X.Y.Z+1>`, never by moving a tag.
- npm: versions are immutable — publish a patch; never unpublish a version
  consumers may have locked.

## Release evidence bundle

Recorded on the release bead (and linked from the PR) at each cut:

1. Git SHA + tag; PR URL; CI run URL (Phase 0).
2. `ship-staging` transcript tail + staging verify output (Phase 1).
3. Version id uploaded; canary split + soak window + promote command
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
