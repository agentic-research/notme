# Threads — the cross-repo order of operations

The identity triangle is **notme · signet · cloister**. This lays out how their
open work actually relates, in what order it can proceed, and whose move each
gate is. Derived 2026-08-27 from the beads' own cross-citations, not from
theme vibes. Companion to [`GOAL-ZERO-ROAD.md`](GOAL-ZERO-ROAD.md), which
covered the release that shipped; this is the arc after it.

## The finding that shapes everything else

**222 open beads across the triangle (notme 89 · signet 53 · cloister 80),
and only 55 cite another repo at all.** Three-quarters of the backlog is
repo-local and needs no coordination. The "giant feature matrix" feeling comes
from a handful of hub beads that each fan out to 3–6 foreign beads; remove the
hubs and the graph falls apart into local clusters.

The densest cross-repo edge is not in the triangle: **cloister ↔ ley-line-open
(34 citations from 14 beads)** is cloister's substrate-adoption campaign, and
it proceeds independently of identity work.

## Line A — the delegation spine (the product)

The chain: human → machine → task, every hop verifiable offline. Hop-1 minting
shipped 2026-08-27 (`POST /cert/issuing-ca`). What remains, in dependency
order:

| # | Step | Beads | Gated on | Whose move |
|---|---|---|---|---|
| A1 | ~~Namespace mechanism decision~~ **DECIDED 2026-08-27: URI-SAN segment-prefix confinement** (RFC 3820's rule on WIMSE URIs; cooperative, honestly labeled; `otherName`+PEN upgrade open) | ADR-019 D5 | — | done |
| A2 | ~~Chain-walking verifier~~ **BUILT 2026-08-27** — `auth/verify-chain.ts`: path signatures + pathlen + `scopes ⊆ parent` + prefix confinement, each bound mutation-proven load-bearing; wired at the x509 proof path (`chain` field) | `notme-acc822` | — | done |
| A3 | ~~Grant object~~ **BUILT 2026-08-28** — grants are objects with id, granter, timestamps, revoker (`listGrants`); D3's fuller payload (`parent_grant_id`, `goal_hash`, `delegable`) lands with A5 | ADR-019 req #1 | — | done |
| A4 | ~~Revocation unit = the grant~~ **BUILT 2026-08-28** — `POST /principals/:id/revoke`; every authority gate reads the grant store live; passkey users are principals with grants (criterion C met) | `notme-77a024` | — | done |
| A5 | ~~Task-credential producer~~ **BUILT 2026-08-28** — `mintTaskCertPair` (offline, tier-signed; enforces namespace-by-construction, scope narrowing, tier-bounded TTL, possession, task scope at `OID_TASK_SCOPE`); `taskCorrelationKey` derives the third segment from the certs; walker now checks issuer-NAME chaining (found the fixtures lying) | `notme-9f84e6` | — | done |
| A6 | **Delegation in receipts end-to-end** — the ninth commitment key becomes reachable | `notme-c0db9b` + `cloister-c10ff2` | A5 + cloister adoption | both |
| A7 | Naming follow-through in signet docs (`id-kp-signet-bridge-delegate` is now a misnomer) | `signet-9dfb44` consequence | nothing | signet |

A1 resolved 2026-08-27 — **no decisions remain on this line; everything after
is work.** A2–A5 all shipped 2026-08-27/28. The line's only remaining step is
A6, which is gated on cloister adopting the ninth key — notme's half is
reachable now.

## Line B — transparency (the Fulcio/Rekor answer, operationalized)

Sigstore's one structural advantage over notme is Rekor. The beads already
encode the order:

| # | Step | Beads | Gated on |
|---|---|---|---|
| B1 | ~~Issuance log — compose-decision~~ **DECIDED 2026-08-28: a Static CT API log, composed from Cloudflare's `azul`** (Workers + DO + R2). Real SCTs, so signet's `--ctfe` path is buildable; public Rekor would record issuance but cannot satisfy SCT verification. Checkpoint key pinned out of band (B2) | `notme-907299` | decided |
| B1a | ~~Ed25519 precondition~~ — azul refused every Ed25519 chain at `add-chain`; **PR submitted upstream 2026-08-28: [cloudflare/azul#281](https://github.com/cloudflare/azul/pull/281)**, patch kept at `docs/design/azul-ed25519.patch` for vendoring if it stalls | `notme-1b46a8` | awaiting review |
| B1b | **Build `notme-ct`** — scaffold from `ct_worker` with the production root as `roots.notme.pem`, R2 + KV + signing/witness secrets; SCTs at every mint path, plus a submission client for the offline task producer | `notme-1b46a8` | next |
| B2 | External trust anchor — pipeline-signed trust material, out-of-band pinning discipline | `notme-8e8836` | parallel to B1 |
| B3 | **SCT enforcement at signet's verifier** — the flag flip that makes B1 compulsory; signet has it measured and filed | `signet-c0d32e` | blocked on B1's build (`notme-1b46a8`) |
| B4 | **Monitor + mirror** — checkpoints verified against the out-of-band key, alerts on unexpected issuance; tiles mirrored for offline audit. The ids signet's bead cited (`ad4eac`/`ad7b5a`) were never filed; these replace them | `cloister-1b5fa2`, `cloister-1b7013` | B1's build |

## Line C — the receipts seam (notme ⇄ cloister)

notme's half is **done, as RPC**: receipt signing is the `ReceiptSigner`
service-binding entrypoint, deliberately not an HTTP route (ADR-014). Two
corrections keep this line honest:

- `cloister-35ccf7` (Interlace-Receipt signing) is **unblocked now**, but its
  plan targets `POST /internal/sign-receipt` — a wire shape ADR-014 retracted.
  The move is a service binding with `entrypoint = "ReceiptSigner"`.
- `notme-bd133e`: the 404 signpost at that path ships stale integrator
  instructions and needs its wording fixed.

`cloister-c10ff2` (ninth commitment key) is optional-field-shaped: cloister
can adopt any time; with A5 shipped it carries real data from day one.

## Line D — key custody (root must not be weaker than leaves)

| # | Step | Beads | Gated on |
|---|---|---|---|
| D1 | **Exercise the KEK recovery path** — cloister is fail-closed on notme, so an unreachable KEK stops cloister | prerequisite recorded on road item 0.4 | nothing |
| D2 | Envelope-encrypt the CA master + delegated JWT keys in DO SQLite | `notme-41d0d3` | **D1 — deliberately** |
| D3 | Shared trust-anchor-helper (factor cloister's kek-helper) | `signet-20e1c7`, `signet-20a875` | parallel / after D2 |

## Line E — product shape (needs design correction before build)

- `notme-bd2a72` (`/identity/lease`): as written, the response returns an
  **ephemeral private key** — which violates the secretless invariant
  (ADR-007) and the PoP model everywhere else in the worker (client generates,
  server never sees private material). Redesign to client-generated key + PoP
  before any build. Flagged on the bead.
- `notme-cf2676` (per-tenant `tenant:<id>:*` scopes): gated on cloister
  ADR-0034 sequencing, and the vocabulary decision interacts with
  `scope-chain.ts`'s warning that hierarchical scopes reintroduce infinite
  strictly-decreasing chains — decide the separator and the chain rule
  together.

## Line F — ripe now, no dependencies

- `signet-6d2bcd`, `signet-c07d12` — both were blocked on `notme-28959a`,
  which **closed**; the pin advances are actionable today.
- The **rc.3 run** — one green run closes the `notme-718ac0` /
  `signet-71d9d8` pair from both sides.
- `signet-0454a2` — consume notme's canonical CBOR fixtures instead of
  hand-copied hex.
- `signet` ADR-004 EKU prose rename (Line A7) — documentation only.
- `cloister-35ccf7` via the RPC entrypoint (Line C).

## Line G — acceptance (human signatures)

`notme-8eb592`: a WebAuthn assertion is not a DSSE signature, so the human
acceptor — the one case that cannot be self-signed — has no implementation
path. Gated on **ADR-020 open questions 1 and 4** (DSSE↔X.509 binding; the
predicate-type registry). Decisions first, then the flow.

## Deferred, deliberately (decided 2026-08-27, reasons on each bead)

CAS release distribution (`notme-e765fe` line) · substrate research
(`32c72f`, `e005a8`, `ce0903`, `d82673`) · the notme.bot → notme/auth/ lift
(`3e22e0`, `3dac49`).

## The critical path

Same shape Phase 0 had: **the expensive-looking work is cheap and the cheap-looking
decisions are the gates.** ~~A1 (namespace mechanism) gates the delegation
spine~~ — decided 2026-08-27; the spine's head is now A2, pure work. B1's
~~compose-decision gates transparency~~ — decided 2026-08-28 (Static CT via
azul); Line B is now build. ADR-020's two open questions gate acceptance. Everything on Line F can happen this week with no decisions at all.
