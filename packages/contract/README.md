# `@notme/contract`

Single source of truth for invariants the **consumer** (this repo, `notme`) and the **server** (`notme.bot`) must agree on. Drift here is how confused-deputy bugs slip in between the two halves.

## What's in here

| Constant | Purpose |
|----------|---------|
| `CONTRACT_VERSION` | Bumped on any breaking shape change. Consumer's pinned version gates the upgrade. |
| `SCOPES` / `ALL_SCOPES` | Every scope token that may appear in a session cookie or invite. Case- and spelling-pinned. |
| `OIDC_ALLOWED_ALGS` | JWT algorithms the server's `verifyOIDC` accepts. Adding here ≠ adding to the server; **both** must move. |
| `TRUSTED_ISSUERS` | Canonical baseline OIDC issuer list both sides accept by default. Deployers MAY extend on the server via env (`OIDC_ALLOWED_ISSUERS`); consumer rejects anything outside the baseline. |
| `GHA_REJECTED_EVENTS` | GHA `event_name` values the cert-mint endpoint refuses (`pull_request_target` confused-deputy lane + `pull_request` for defense-in-depth). |
| `ERROR_STATUS` | HTTP status codes the server returns for specific failure classes. Consumer retry/branch logic depends on these. |

## Who consumes this

- `notme/worker/` — workspace dep (`@notme/contract`: `workspace:*`).
- `notme/action/`, `notme/proxy/`, `notme/vault/` — workspace dep if/when they need any of these constants.
- `notme.bot` (separate repo) — currently keeps a **synced mirror** at `src/contract.ts`. A future move to a published `@notme/contract` will replace the mirror with an `npm install`. The mirror is byte-diff'd in CI on the notme.bot side via `src/auth/contract.test.ts`.

## Rules of the road

1. **Never mutate an existing constant value in place.** Add a new one, mark the old as `@deprecated`, then drop it after the consumer migrates.
2. **Bump `CONTRACT_VERSION` on any breaking shape change** (rename, remove, type widening that loses information).
3. **Pure constants only.** No I/O, no runtime types, no imports from anywhere except `type` imports of declared values. This file must be safe to import from any environment (Workers, Node, browser).
4. **No `import` from this package at module top level in a context that runs in tests.** Treat it as a public API — if the value isn't worth shipping, it isn't worth declaring here.
