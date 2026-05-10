# 010: Cross-Language Canonical Encoding for Signature Verification

**Status:** Accepted
**Date:** 2026-05-09
**Bead:** notme-803923 (replaces — see "Bead restructure" below)
**Relates to:** signet ADR-002 §2.3 (CBOR canonical), signet ADR-011 (policy bundles, same pattern), notme ADR-008 (cert pair)

## Context

notme is the secure reference implementation of the **signet protocol**. Signet defines the wire format and cryptographic operations; notme implements them at the Cloudflare edge. Cap'n Proto schemas in `schema/identity.capnp` synchronize type definitions across TypeScript and Go — they are **type sync only**, not the wire format.

A cross-language canonicalization audit (2026-05-09) found three concerns:

### 1. Schema docstring lies

`schema/identity.capnp` claimed:

> "CABundle canonical encoding must produce identical bytes across all languages. Cap'n Proto's deterministic binary format guarantees this."

This is wrong as written. Capnp **does** have a canonical form (RFC-style spec at `capnproto.org/encoding.html#canonicalization`), but neither signet nor notme uses capnp wire format anywhere. The claim was aspirational text that drifted.

### 2. Signing canonicalization differs from signet protocol

Signet's protocol spec (ADR-002 §2.3) and policy-bundle spec (ADR-011) both prescribe **canonical CBOR (RFC 8949 §4.2)** for any signed-bundle structure. Implementation lives at `signet/pkg/revocation/checker.go:168-188`:

```go
message := map[int]interface{}{
    1: bundle.Epoch, 2: bundle.Seqno, 3: bundle.Keys,
    4: bundle.KeyID, 5: bundle.PrevKeyID, 6: bundle.IssuedAt,
}
encMode := cbor.CanonicalEncOptions().EncMode()
canonical := encMode.Marshal(message)
ed25519.Verify(trustAnchor, canonical, signature)
```

notme TS canonicalization (currently) at `worker/src/revocation.ts::bundleCanonical()` and the inline duplicate at `worker/src/signing-authority.ts:443-447`:

```ts
const sorted: Record<string, unknown> = {};
for (const k of Object.keys(rest).sort()) sorted[k] = rest[k];
return new TextEncoder().encode(JSON.stringify(sorted));
```

Both produce deterministic key-ordered bytes — same intent, different binary expression. notme's closed loop works in isolation (it writes JSON-canonical, verifies JSON-canonical), but **a notme-issued bundle cannot be verified by any signet-Go reference verifier, and vice versa.** This breaks the "notme is a reference impl of signet" claim at the cryptographic level.

### 3. Schema sync drift (separate concern)

`schema/codegen/capnp-to-ts.ts` is a 280-LOC hand-rolled regex parser. It silently degrades on unknown capnp features (no `Float*`, no smaller-than-32 ints, no AnyPointer, no annotations, no groups, no generics, no interfaces). Adding a field that uses anything weird falls through to `unknown` / `z.unknown()` rather than erroring.

This is a **type-sync drift** problem orthogonal to wire-format canonicalization. Tracked separately (see Bead restructure).

## Decision

### Wire format split (matches signet exactly)

| Surface | Format | Where |
|---|---|---|
| HTTP API requests + responses | JSON | `Response.json(...)`, `request.json()` everywhere in `worker/` |
| KV storage (CA_BUNDLE_CACHE) | JSON | `CA_BUNDLE_CACHE.put(JSON.stringify(bundle))` (matches signet's `https_fetcher.go` JSON-over-HTTPS) |
| DO SQLite blob columns | JSON | unchanged |
| DPoP / JWT tokens | JSON-in-base64 | RFC 7515 / 9449 — unchanged |
| **Cryptographic canonical bytes (Ed25519 sign/verify input)** | **canonical CBOR (RFC 8949 §4.2)** | `bundleCanonical()` — the function whose output is fed to `crypto.subtle.sign(ED25519, key, ...)` |

**Capnp's role:** type sync only. Schemas in `schema/*.capnp` are the source of truth for cross-language type definitions. The schema does NOT specify a wire format — that's the implementation's job, and is governed by signet protocol ADRs.

### Library choice

**`cbor-x`** for the TS-side canonical encoder.

- Pure JavaScript; runs on Cloudflare Workers V8, Node, browsers, Deno.
- ~300k weekly downloads; production-grade.
- Configurable to RFC 8949 §4.2 deterministic encoding mode.

Alternative considered: `cbor2` (newer, same author tradition). Pick `cbor-x` because it's the more battle-tested option today; revisit if `cbor2` proves more conservative on bundle size or performance.

### Field map (must match signet exactly)

The signed input is an integer-keyed map:

```
1 → Epoch     (uint64)
2 → Seqno     (uint64)
3 → Keys      (map[string][]byte)
4 → KeyID     (string)
5 → PrevKeyID (string, "" if absent)
6 → IssuedAt  (int64)
```

This is signet's choice (`checker.go:168-175`). notme TS adopts it verbatim. Field 7 (Signature) is excluded from the signing input.

### Migration path

The closed loop currently works (JSON ↔ JSON within notme), so a sudden swap risks orphaning every existing signature in KV. Two strategies were considered:

**(A) Dual-encode for one rotation cycle.** Writer signs with both JSON-canonical and CBOR-canonical, stores both signatures. Verifier accepts either. After one full epoch rotation under dual-encode with no JSON-only fallbacks observed in metrics, drop the JSON path. Adds a `signatureFormat` discriminant to CABundle (or relies on epoch-bound migration). Conservative; appropriate for production deployments with persistent signed bundles to preserve.

**(B) Hard-cutover with bounded staleness window.** Drop JSON-canonical, ship CBOR-canonical only. Existing JSON-signed bundles in KV become unverifiable until the SigningAuthority `alarm()` (every 4 minutes, per `BUNDLE_REFRESH_MS`) regenerates a fresh CBOR-signed bundle. Worst-case window: 4 minutes of revocation-check failures during deploy. Acceptable when there are no production-tier persistent signed bundles to preserve.

**Decision (2026-05-10):** **(B) hard-cutover.** notme is currently pre-production; no persistent JSON-canonical signed bundles in any production KV need preserving. The 4-minute alarm cycle bounds the unverifiable-bundle window during deploy; revocation checks fail closed during that window (per `revocation.ts::isBundleStale`), which is the same fail-closed behavior they'd take on any bundle staleness anyway.

If/when notme has production deployments with persistent signed bundles that pre-date this migration, switch to strategy (A) before bumping CBOR alignment further. The CABundle `signatureFormat` discriminant remains a future option (deferred to a follow-on ADR or a re-revisited (A) path); not implemented in this landing.

### Cross-runtime fixture suite

Mandatory CI gate: `schema/fixtures/cabundle-*.bin` + `*.expected.hex`. signet-Go test produces canonical bytes for a known fixture; notme-TS test asserts byte-equality for the same fixture. Failure means a runtime divergence (a bug in `cbor-x`, `fxamacker/cbor`, or the canonical-encoding spec interpretation).

This catches the kind of drift that produced the original bug — silent JSON-canonical when CBOR-canonical was specified.

## Consequences

**Positive:**

- **Cross-impl interop:** notme-issued CABundles become verifiable by any signet-Go consumer (and vice versa). Reference-impl claim is real, not aspirational.
- **Single source of truth for canonicalization:** bundleCanonical lives in one place (currently duplicated in two). Refactor falls out of this work.
- **Honest docstrings:** schema/identity.capnp stops claiming capnp guarantees byte equality. Future readers don't get misled.
- **Future signed bundles** (policy bundles per signet ADR-011, attestation predicates, anything else that needs cross-language signature stability) inherit the same architecture for free.

**Negative / costs:**

- **One npm dep added** (`cbor-x`). Bundle-size impact measured at integration time; if material, switch to `cbor2` or a hand-rolled minimal RFC 8949 §4.2 encoder.
- **Bounded staleness window during deploy:** with strategy (B), existing JSON-signed bundles in KV become unverifiable until the next 4-minute alarm cycle regenerates them. Revocation checks fail closed during that window — same fail-closed behavior as any other bundle-stale condition. Acceptable for notme's pre-production stage; documented as a re-evaluation trigger if notme has persistent production signed bundles in the future.

**Out of scope:**

- **Schema sync (`capnp-to-ts.ts` hand-rolled drift).** Separate bead. Type-sync correctness is independent of wire-format alignment.
- **CMS / DSSE / APAS canonicalization.** Different surfaces, governed by their own RFCs (RFC 5652 DER for CMS, in-toto §6 for DSSE). No change here.
- **Dropping JSON for transport / storage / API.** JSON is correct for those surfaces and matches signet. This ADR is about *signing canonical bytes only*.

## Bead restructure

`notme-803923` (P0) was conflating wire-format drift with schema-sync drift. Closing in favor of three properly-scoped beads:

- **(P0) protocol drift — TS adopts canonical CBOR for CABundle signatures** — implements this ADR.
- **(P1) schema sync drift — capnp-to-ts.ts silent degradation** — replace hand-rolled parser, OR add fail-loud "unknown capnp feature" error path.
- **(P3) dedupe `bundleCanonical()`** — `signing-authority.ts:443-447` is a copy-paste of `revocation.ts:159-166`. Pure refactor, falls out of the P0 implementation.

## See also

- [signet ADR-002 §2.3 — Canonical Encoding](../../../signet/docs/design/002-protocol-spec.md) — the upstream protocol spec mandating CBOR canonical.
- [signet ADR-011 — Policy Bundles](../../../signet/docs/design/011-policy-bundles-scim.md) — same canonical-CBOR pattern for policy distribution; sibling architecture.
- [signet pkg/revocation/checker.go](../../../signet/pkg/revocation/checker.go) — production code; the byte-for-byte target.
- [signet pkg/revocation/cabundle/https_fetcher.go](../../../signet/pkg/revocation/cabundle/https_fetcher.go) — confirms JSON is the transport, CBOR is signing-only.
- [ADR-008](008-bridge-cert-csr-wimse.md) — cert pair format; same principle of signet-protocol-conformance.
- [ley-line-open RTFM dossier](../../../ley-line-open/docs/decades/T8/capnp-rtfm-findings.md) — capnp canonical encoding research; useful background, but capnp wire format is not adopted here.
- `worker/src/revocation.ts::bundleCanonical` — the function to be replaced.
- `worker/src/signing-authority.ts:443-447` — the inline duplicate to be removed.
- `schema/fixtures/cabundle-*.bin` — cross-runtime fixture suite to be created.
