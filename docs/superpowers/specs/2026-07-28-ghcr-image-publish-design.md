# Publishing notme + notme-proxy to ghcr

**Bead:** notme-83706a
**Date:** 2026-07-28
**Status:** approved

## Problem

notme can build its OCI image but nothing publishes it. `task image` runs
`apko build apko-notme.yaml notme:{{.TAG}} notme.tar` and prints "load with:
`docker load < packages/notme.tar`" — the output is a local tarball.

Cloister declares notme as a hypervisor-tier bundle:

```toml
[[bundles]] name = "notme-identity"
  [bundles.external] image = "notme:0.1.0"
```

That reference is *accurate* — `notme:0.1.0` is exactly what `task image`
produces — but it is not fetchable. An operator deploying the cluster on a
fresh host cannot pull it. Cloister's fail-closed pinning (#214) makes an
unresolvable OCI digest a refusal rather than a warning, so the bare name is
not merely imprecise, it is a hard blocker the moment cloister tries to pin.

`proxy/` (notme-proxy), a separate Rust binary cloister declares as a second
hypervisor-tier bundle, has no image and no build task at all.

ADR-0041 (cloister) states each backend repo publishes its own distroless
image. notme is the outlier.

## Non-goals

- Cloister's `cluster.toml` stays untouched. It registry-qualifies its own
  references *after* this lands. Doing it before would assert a location that
  does not exist, which is worse than the bare name it replaces.
- No MCP surface. notme is an identity authority, not an MCP server.

## Design

### 1. Version convention: strip the `v`

A `v0.1.0` tag publishes `ghcr.io/agentic-research/notme:0.1.0`.

The `v` prefix is a per-repo convention, not a mandate — rosary does
`VERSION="${TAG#v}"` and publishes `0.10.0`; mache and ley-line-open publish
`v0.19.0` / `v0.11.3`. All three are correct because each matches its own
pushed tag.

notme strips it, because cloister's `cluster.toml` already says `notme:0.1.0`
and `notme-proxy:0.1.0`. Stripping means cloister's qualification is a pure
prefix addition with no version rewrite, and it agrees with the `0.1.0`
already in `melange-notme-app.yaml` and `proxy/Cargo.toml`.

### 2. Proxy build: zigbuild cross-compiles, melange packages

Neither existing melange recipe compiles anything. `melange-workerd.yaml`
fetches a prebuilt binary from an npm tarball and `install -Dm755`s it;
`melange-notme-app.yaml` installs a prebuilt `dist/worker.js`. Compiling Rust
inside melange would be the one recipe that breaks that shape, and it would
drag qemu in for the aarch64 leg.

So `cargo-zigbuild` cross-compiles both arches ahead of melange, and the new
recipe installs the prebuilt binary exactly as the workerd recipe does.

Two new files in `packages/`:

| file | builds |
|---|---|
| `melange-notme-proxy.yaml` | `notme-proxy` apk — installs the prebuilt binary to `/usr/bin/notme-proxy`, arch-selected by the same `if: ${{build.arch}}` guard the workerd recipe uses |
| `apko-notme-proxy.yaml` | OCI image — wolfi base + `ca-certificates-bundle`, uid 1000, `/run/cloister-uds` mount point, entrypoint `/usr/bin/notme-proxy` |

Target is `*-unknown-linux-musl` for both arches: the proxy already uses
rustls with `ring` (no OpenSSL), so a static musl binary drops the libc
dependency from the image entirely.

### 3. Taskfile owns every image verb

CI runs no image command the Taskfile doesn't own — the same philosophy
`task pin:check` already encodes.

| task | does |
|---|---|
| `proxy:build:cross` | `cargo zigbuild --release --target {x86_64,aarch64}-unknown-linux-musl` |
| `image:proxy:apk` | melange builds the `notme-proxy` apk for both arches |
| `image:proxy` | apko builds a local tarball (dev loop, mirrors `task image`) |
| `image:publish` | apko publishes both images to ghcr; `PUSH` / `SIGN` vars |
| `version:check` | asserts `server.json` agrees with the version being published |

Existing `image:keygen` / `image:apk` / `image` are unchanged — the local dev
loop keeps working exactly as `packages/README.md` documents it.

### 4. version:check asserts against the *pushed tag*

The assertion is **`server.json` `packages[].version` ↔ the tag the publish
job actually pushes** — not git tag ↔ configs.

This is the failure that shipped in ley-line-open v0.11.2: the guard rejected
a tagged identifier but permitted an absent version, so a broken shape went
out through a guard written to prevent that class. Half a rule enforced.
Cloister's ADR-0041 was corrected (#213) to state it directly:

> version MUST equal the tag the publish job actually pushes — because
> `<identifier>:<version>` has to resolve at the registry.

Checking against the git tag would pass while the registry 404s. So
`version:check` takes `VERSION` — the *same variable* `image:publish` uses to
tag — and `image:publish` calls it internally. Publishing a version
`server.json` does not declare is then structurally impossible, not merely
discouraged.

Both entries are checked **independently**. Cloister declares
`notme-identity` and `notme-proxy` as two separate hypervisor-tier bundles and
ADR-0038 derives each image separately, so a correct notme with a stale
notme-proxy is a reachable state that a single combined assertion would miss.

Implemented as `scripts/check-image-versions.ts`, matching the existing
`check-sha-pins.ts` / `doc-check.ts` convention: small TS run via
`pnpm exec tsx` from a Taskfile target, reading source, no external action.

### 5. Release workflow

`.github/workflows/release.yml`, triggered by `push: tags: ['v*']` plus
`workflow_dispatch` with a tag input (ley-line's shape).

Two jobs, `image-notme` and `image-proxy`, deliberately **independent** — not
chained. Rosary's release.yml documents why: coupling let an unrelated flaky
binary build skip the image publish entirely in v0.5.0.

`permissions: {}` at top level; per-job `contents: read`, `packages: write`,
`id-token: write` for keyless cosign. Every external `uses:` pinned to a
40-char SHA with a `# vX.Y.Z` comment — `task pin:check` fails the PR
otherwise.

### 6. Signing

`apko publish` emits the digest on stdout and the SPDX SBOM to `--sbom-path`.
Then, per image:

```
cosign sign   --yes "$IMAGE@$DIGEST"
cosign attest --yes --type spdxjson --predicate sbom-index.spdx.json "$IMAGE@$DIGEST"
```

Keyless OIDC — no signing secret to store or rotate.

**melange signing key is ephemeral, generated per run.** The apks are consumed
by apko within the same job and never published as an apk repo, so the
signature is an intra-job integrity check with no external consumer. A
persistent key would be a secret to guard and rotate for no gain. The real
supply-chain property is cosign on the image digest.

### 7. server.json

New at repo root. notme exposes no MCP tools (`worker/src/` has none), so this
is purely the ecosystem package-identity manifest cloister reads: `name`,
`repository`, `version`, and **two** `packages[]` entries with
`registryType: "oci"`, plus an `art.cloister/v1` `_meta` block naming the two
bundles and their tiers.

**No `remotes`, and the file says why.** Cloister derives MCP session
behaviour from `remotes[].type` or `packages[].transport.type`; with neither
present it falls through cleanly, which is the correct outcome for a non-MCP
package. Asserting an MCP surface that does not exist would be actively worse
than omitting it — cloister would generate backends for tools that aren't
there.

## Docs to update

| file | what is now false |
|---|---|
| `packages/README.md` | mermaid `GHCR[...(manual publish)]` node and the `TAR -.->\|docker push\|` edge; recipe table needs the two proxy rows; "distribution" section's *"manual `docker push` for now — no CI publish workflow yet"* is the sentence this work retires |
| `README.md:160` | `docker run -p 8788:8788 notme:0.1.0` → registry-qualified |
| `ARCHITECTURE.md:11` | `docker run notme:latest` → registry-qualified |
| `docs/design/007-secretless-local-proxy.md` | items 8 and 6 are checklist lines this closes |
| `scripts/README.md` | new `check-image-versions.ts` row |

## Acceptance

`ghcr.io/agentic-research/notme` and `ghcr.io/agentic-research/notme-proxy`
are both pullable at a tagged version produced by the existing apko machinery,
both declared in `server.json` `packages[].oci`, verified by `docker pull` of
each published tag from a clean host.
