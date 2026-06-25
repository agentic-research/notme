# 012: Retire notme/vault — cloister is the canonical credential vault

**Status:** Accepted
**Date:** 2026-06-25
**Bead:** notme-9af5dd (closes), supersedes notme-6bbec6
**Relates to:** cloister ADR-0010 (the 2026-05-09 vault lift), cloister ADR-0030 §A3 (3-tier KEK scoping)

## Decision

Delete `vault/` from the notme repo. cloister owns and deploys the credential
vault going forward; notme retains no copy.

## Why

The 2026-05-09 lift (cloister ADR-0010) was deliberately **copy-not-move** so the
two copies could diverge during a tolerance window. That window is over — the
copies have diverged and notme's copy is dead weight:

- **notme does not use it.** No `VAULT` binding in `worker/wrangler.toml`; nothing
  in `worker/` or `proxy/` imports `@notme/vault` or fetches a vault URL. The
  package is `"private": true` (never published) with no deploy target in
  `Taskfile.yml`. notme's own threat model already declares it moved:
  `worker/src/__tests__/threat-model.test.ts` — `contract.vault.aad-binding` is an
  `it.todo` reading "moved-to-cloister … covered by cloister/vault".
- **cloister is canonical and ahead.** cloister deploys the vault via its
  hypervisor (`cluster.capnp` holds `VAULT_STORE` + `VAULT_KEK_SOURCE`) and has
  gained 3-tier per-tenant KEK scoping (`cloister/vault/src/kek-scope.ts`, ADR-0030
  §A3) that notme never had. That feature is exactly what notme-6bbec6 asked for —
  so 6bbec6 is resolved by consuming cloister's vault, not by re-implementing here.
- **No license blocker.** notme is Apache-2.0; cloister's vault is AGPL-3.0. notme
  consumes it as a separately-deployed network service (not a linked library), so
  no copyleft obligation attaches to notme's own code. (`vault/NOTICE` further
  records that the single author has already exercised relicensing in both
  directions; there is no third-party-contribution entanglement.)

## What was removed

- `vault/` (the whole package: `src/`, tests, README, NOTICE, wrangler example).
- `"vault"` from `pnpm-workspace.yaml`.
- `../vault/src/**` include/exclude globs from `worker/tsconfig.json`.
- `../vault/src/__tests__/**` glob from `worker/vitest.config.ts`.

## Recovery / archive

The last commit in which `vault/` existed in notme is **`1ccd3b0`**. If notme ever
needs to self-host a vault Worker again, the notme-unique entrypoint
(`vault/src/worker.ts` + `vault/wrangler.toml.example` — never round-tripped to
cloister, per the old `vault/NOTICE`) is recoverable with:

```
git show 1ccd3b0:vault/src/worker.ts
```

For any new vault work, use **cloister/vault**.
