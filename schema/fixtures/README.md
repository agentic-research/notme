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

## Epoch history fixtures (notme-6a4f23)

`epochhistory-*` are the signing input of `/.well-known/epochs.json`
(ADR-019 D7), produced by `worker/src/epoch-history.ts`
`epochHistoryCanonical`. CBOR canonical form, integer-keyed map:

```
0: "notme-epoch-history-v1"   1: seqno   2: issuedAt   3: currentEpoch
4: [ {1: epoch, 2: untilEpoch|null, 3: keyId, 4: publicRaw (bytes), 5: retiredAt|null} ... ]
5: [ {1: epoch, 2: revokedAt, 3: reason} ... ]
```

Arrays keep the document's order (they are not sorted by the encoder).
`null` is CBOR simple value 22 (`0xf6`); in Go, a nil `*uint64`.

Unlike the CABundle fixtures, each `.json` is the **full served document,
`signature` included**. The signature is excluded from the signing input as
usual, and is Ed25519 by the fixture root, the key whose 32-byte seed is
`0x00..0x1f`:

```
root public key (standard base64): A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=
```

So a consumer can check the whole path: re-encode the `.json` (minus
`signature`), compare with the `.bin`, and verify `signature` over those bytes
under that key. Ed25519 is deterministic, so regenerating gives the same
signatures. `epochhistory-revoked` covers a retired key, a live key spanning a
revocation (`untilEpoch: null`), and one revocation with a reason;
`epochhistory-basic` is a fresh authority with no history.

## Revocation statement fixture (notme-8befcc)

`revocationstatement-epoch1` is the root-signed DSSE envelope that
`revokeEpoch()` logs in Rekor (ADR-019 D7), produced by
`worker/src/rekor-revocation.ts`. It differs from the CBOR fixtures:

| File | Contents |
|---|---|
| `.json` | The full envelope: `payloadType` (`application/vnd.in-toto+json`), `payload` (standard base64 of the in-toto Statement v1 JSON) and `signatures[{keyid, sig}]`. |
| `.bin` / `.expected.hex` | The signing input: DSSE v1 PAE, `"DSSEv1" SP len(type) SP type SP len(payload) SP payload`, lengths in bytes. |

The signature is Ed25519 by the same fixture root as `epochhistory-*`, key id
`a050837d85070582ccf7394b0988847c`. The statement describes the revocation in
`epochhistory-revoked`: epoch 1, the same `revokedAt` and reason, and
`historySeqno: 41`. That history has seqno 42, so it must carry the
revocation, and it does. A consumer checks four things:

1. The PAE of the decoded payload equals the `.bin`.
2. The signature verifies over it under the root.
3. The subject digest is sha256 of the root's 32 raw bytes.
4. The predicate matches the history's revocation.

The payload bytes are what is signed, so verifying it needs no JSON
canonicalization.

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
