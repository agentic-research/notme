# Canonical-encoding fixtures (ADR-010 cross-implementation gate)

These files are the shared source of truth for the CABundle canonical
encoding — CBOR canonical form (RFC 8949 §4.2), integer-keyed map
`1=Epoch, 2=Seqno, 3=Keys, 4=KeyID, 5=PrevKeyID, 6=IssuedAt`, signature
field excluded from the signing input.

Three implementations must produce byte-identical output
(divergence silently breaks signature verification across them):

- **notme** (TypeScript): `worker/src/revocation.ts` `bundleCanonical` —
  gated by `worker/src/__tests__/bundle-canonical.test.ts`, which loads
  these files (notme-e9d2b8).
- **signet** (Go): `pkg/revocation/canonical.go` — still asserts a
  hand-copied byte literal in `canonical_test.go`; repointing it at these
  files, verified against `SHA256SUMS`, is `signet-0454a2`.
- **ley-line-open** (Rust): vendors these files with their SHA-256 sums and
  checks them against an independent encoder (`ley-line-open-0466c0`).

## File format

Per fixture `<name>`:

| File | Contents |
|---|---|
| `<name>.json` | Input bundle: `epoch`, `seqno`, `keys` (map of kid → standard-base64 key bytes), `keyId`, `prevKeyId`, `issuedAt`. No `signature` — it is excluded from the signing input; tests supply a decoy to prove the exclusion. |
| `<name>.expected.hex` | Expected canonical bytes, lowercase hex, one line. |
| `<name>.bin` | The same bytes, raw. Checked equal to `hex_decode(<name>.expected.hex)`. |

`SHA256SUMS` pins the SHA-256 of every fixture file, in standard
`sha256sum` format.

`cabundle-multikey.json` lists its `keys` in NON-canonical order on
purpose — a consumer can only pass by sorting (RFC 8949 §4.2:
length-then-bytewise, not alphabetical), never by insertion order.

`cabundle-rotation.json` is the production-shaped multi-key case: two real
32-hex-char kids (`lowercasehex(SHA-256(SPKI)[:16])`, from raw keys `00..1f`
and `20..3f`), 32-byte key values, a present `prevKeyId`, and `keys` listed
in non-canonical order. Equal-length kids are decided by the bytewise
tiebreak, not the length rule `cabundle-multikey` exercises, and a populated
`prevKeyId` with two keys is the rotation-grace state `generateBundle` emits.

## Integrity anchor (notme-1629fe)

The golden bytes are the encoder's own output written to a file, so by
themselves they only catch an *accidental* encoder change. A PR that edited
the encoder and `.expected.hex` together used to be green. Three things now
stand between that PR and `main`:

1. **Pinned digests, checked first.** `scripts/fixture-manifest.ts` fails if
   any file here is unpinned, missing, or differs from `SHA256SUMS`, or if a
   `.bin` differs from its `.expected.hex`. The notme test runs it before it
   reads a fixture, and `task docs:check` runs it in CI. An encoding change
   therefore has to touch the encoder, the vector *and* the manifest, and that
   diff names itself.
2. **CODEOWNERS** on this directory, the gate, and the encoder.
3. **An independent derivation.** The test carries an RFC 8949 §4.2 encoder
   written from the RFC, which shares no code with `revocation.ts`. It
   re-derives both vectors from their `.json` and agrees with
   `bundleCanonical` over 500 generated bundles. A paired encoder + vector +
   manifest edit still fails there.

This is the ceiling for in-repo fixtures: an author who edits all of the
above in one PR, reference encoder included, can still get it through. The
external anchor is each consumer's vendored copy and its recorded digests.
When notme changes these files, every consumer's pin breaks and that
consumer has to acknowledge the new encoding.

Verify a vendored copy with stock tools:

```sh
shasum -a 256 -c SHA256SUMS   # or: sha256sum -c SHA256SUMS
```

## Adding a fixture

Add the three files, regenerate the manifest
(`shasum -a 256 *.json *.expected.hex *.bin > SHA256SUMS`), then extend the
consuming test in each implementation. Never edit `.expected.hex`/`.bin` to
make a failing implementation pass. The encoding is the contract; three-way
agreement is the point.
