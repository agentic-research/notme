# vault

Zero-secret credential proxy gated by notme identity.

> **⚠️ Migration notice (2026-05-10):** this directory is moving to
> [`cloister`](https://github.com/agentic-research/cloister). This README will
> be rewritten or replaced at that time. Until the move lands, vault is part
> of the notme repo and inherits notme's Apache-2.0 license. **After the
> move, vault content will be governed by cloister's AGPL-3.0 license** — if
> you're integrating against vault, plan for that license change.

## what this is

`notme-vault` — a separate Cloudflare Worker (`name = "notme-vault"` per
`wrangler.toml.example`) that brokers third-party credentials (e.g. Anthropic
API keys, GitHub PATs) for tools running under a notme bridge cert. Tools
authenticate to the vault with their bridge cert; the vault attaches the
upstream credential and forwards. The credential never enters the tool's
process memory.

## entry points

- **`src/worker.ts`** — Worker fetch handler.
- **`src/vault.ts`** — Vault DO (stores encrypted credentials).
- **`src/crypto.ts`** — Encryption / decryption helpers.
- **`src/handler.ts`** — Per-route logic.
- **`src/__tests__/`** — vitest suite.

## why it's moving

Per the operadic-substrate / cloister-companion line of thinking
(see `notme-e005a8`, `ley-line-3278b4`, cloister ADR-0007), generic
credential-brokerage capabilities belong in cloister alongside the rest of
the substrate. notme stays focused on identity issuance + verification at
the edge; cloister hosts the capabilities that consume that identity.

## license posture across the move

| Phase | License | Why |
|---|---|---|
| Now (in notme) | Apache-2.0 (inherited from notme) | notme is permissively licensed for ecosystem reuse |
| After move (in cloister) | AGPL-3.0 (inherited from cloister) | cloister is copyleft for the substrate |

MIT/Apache → AGPL is a one-way relicensing direction that's legally fine for
the migration (Apache-2.0 code can be incorporated into AGPL projects). It
is NOT reversible without contributor consent. If you write new vault code
between now and the migration, assume it ends up AGPL.

## related

- [`../README.md`](../README.md) — top-level repo overview
- [`../docs/design/007-secretless-local-proxy.md`](../docs/design/007-secretless-local-proxy.md) — local-proxy design (vault is the edge counterpart pattern)
- bead `notme-e005a8` — mTLS-injector chunk-spec ADR (related operadic-substrate work)
- cloister: https://github.com/agentic-research/cloister
