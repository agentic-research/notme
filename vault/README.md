# vault

Zero-secret credential vault Worker (HKDF + AES-GCM envelope encryption) gated by notme identity.

> **🚧 Migration in progress — copy-not-move (lift dated 2026-05-09):**
>
> A copy of this code has been lifted into [`cloister/vault/`](https://github.com/agentic-research/cloister/tree/main/vault) per **cloister ADR-0010** (`cloister/docs/adr/0010-vault-and-bundle-clusters.md`). The lift is **copy-not-move** — both copies coexist for the divergence-tolerance window:
>
> - **`cloister/vault/`** — license **AGPL-3.0-or-later** (cloister's license). SPDX headers per file. NOTICE preserves Apache-2.0 attribution per §4(c). This is the canonical home going forward.
> - **`notme/vault/` (this directory)** — license **Apache-2.0** (notme's license, as of 2026-05-09 relicense). Stays here for the divergence-tolerance window. Tracked under bead [`notme-9af5dd`](https://github.com/agentic-research/notme) (P3, DEFERRED — "Remove notme/vault/ once cloister's copy is proven; no urgency").
>
> The two copies **may diverge** over the window (each repo's tests + reviews stay in their own ecosystem). Don't sync changes manually — pick one as your editing target and let the other catch up via deliberate forward-porting.

## license posture during the migration

| Copy | License | Why |
|---|---|---|
| `notme/vault/` (this) | Apache-2.0 (matches notme repo) | Permissive; ecosystem reuse |
| `cloister/vault/` | AGPL-3.0-or-later (matches cloister repo) | Copyleft for the substrate |

Apache-2.0 → AGPL relicensing is **legally permitted** (Apache 2.0 §4 allows redistribution under different licenses provided notice is preserved). cloister's `vault/NOTICE` discharges that obligation. The relicensing is **one-way**: code that originated in cloister/vault under AGPL cannot be back-ported here without a separate negotiation.

If you're integrating against the vault and want a long-term target, prefer **cloister/vault**. notme/vault is for legacy notme-specific use only and will be removed when `notme-9af5dd` closes.

## what this is

`notme-vault` — a separate Cloudflare Worker (`name = "notme-vault"` per `wrangler.toml.example`). Brokers third-party credentials (e.g. Anthropic API keys, GitHub PATs) for tools running under a notme bridge cert. Tools authenticate to the vault with their bridge cert; the vault attaches the upstream credential and forwards. The credential never enters the tool's process memory.

## entry points

- **`src/worker.ts`** — Worker fetch handler + `CredentialVault` Durable Object.
- **`src/vault.ts`** — Pure vault helpers (proxy req shaping, scope check, validation).
- **`src/crypto.ts`** — Encryption / decryption helpers (HKDF + AES-GCM envelope).
- **`src/handler.ts`** — Per-route logic.
- **`src/kek-source.ts`** — URL-driven KEK resolver (`env://`, `file://`, `keychain://`, `http(s)://`).
- **`src/rate-bucket.ts`** — Per-caller token-bucket math (pure functions over `BucketState`).
- **`src/__tests__/`** — vitest suite (vault, security, adversarial, encryption, kek-source, rate-bucket, worker, worker-do).

## KEK source

The vault DO derives its AES-GCM KEK from a secret resolved via a URL spec in `VAULT_KEK_SOURCE`. Schemes accepted by the current dispatcher (`buildKekSource()` in `src/kek-source.ts`):

| Scheme | Use when | Needs |
|---|---|---|
| `env://NAME` | You're fine with a plaintext workerd binding (CI, dev). | nothing |
| `file:///path` | The secret lives on disk and you've set up a workerd disk service. | `KEK_DISK` binding |
| `keychain://name` | macOS Keychain (cloister's local-dev posture). | `KEK_HELPER` sidecar |
| `http(s)://host/...` | Any HTTP backend (use sparingly — secret in transit). | `KEK_HELPER` sidecar |

Workerd is a sandboxed V8 isolate — no `fs`, no `child_process`. `keychain://` and `http(s)://` go through a separate Node sidecar (`scripts/kek-helper.mjs` in cloister) bound as `KEK_HELPER`. See **cloister ADR-0019** for the helper-binary design rationale and the supply-chain analysis (why we don't shell out to `/usr/bin/security` from a worker).

> **Deferred — helper-backed schemes not yet wired:** `secret-tool://` (Linux libsecret), `op://` (1Password), `apple-password://` (macOS Passwords app), `keyring://` (generic cross-platform) all need wiring through `buildKekSource()`'s `HelperKekSource` dispatcher. Tracked as a follow-up to `rosary-54ad76` (see the bead linked from PR #22). Until that lands, configuring these schemes throws at runtime.

Legacy `VAULT_KEK_SECRET` is supported but **deprecated** — set `VAULT_KEK_SOURCE=env://VAULT_KEK_SECRET` (or another scheme) instead. The DO emits a one-time `console.warn` on first derive if the legacy path is in use.

## rate budget

Every authenticated request charges a per-caller token bucket inside the DO (`consumeBudget(sub, costClass)`). Configured in `src/rate-bucket.ts`:

- Capacity: 100 tokens per caller
- Refill: 10 tokens/sec
- Cost per request: `read` = 1, `write` = 3, `proxy` = 5
- Max in-flight (burst cap): 16

Over-budget callers get **HTTP 429** with a `Retry-After` header derived from the bucket's refill rate. Bucket state lives in DO memory (single-writer per DO) — if the DO is evicted, callers get a full bucket on their next request, the same outcome a long-idle caller would see. Cloister's `dos-friend` pilot (`cloister-211b68`, finding F1) is the load-bearing reason this exists; see that bead for the threat model.

## related

- **cloister ADR-0010** — `cloister/docs/adr/0010-vault-and-bundle-clusters.md` — Vault as scoped slices, bundles as the unit of trust, clusters as the unit of identity. The architectural rationale for the lift.
- **bead `cloister-9ad9eb`** (P1) — "Lift notme/vault → cloister/vault (copy-not-move; notme keeps its copy for now)". The lift execution.
- **bead `notme-9af5dd`** (P3) — "DEFERRED: Remove notme/vault/ once cloister's copy is proven (no urgency)". The eventual removal.
- [`../README.md`](../README.md) — top-level repo overview (notme is Apache-2.0 as of 2026-05-09).
- [`../docs/design/007-secretless-local-proxy.md`](../docs/design/007-secretless-local-proxy.md) — local-proxy design (vault is the edge counterpart pattern).
