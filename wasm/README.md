# wasm

ley-line-open's **released** `leyline_sign.wasm`, vendored byte-for-byte and
pinned (notme-bc4cd2). It is the third-party verifier for notme credentials:
cloister runs it in workerd, and a browser would run it for notme-396aff.
notme does not reimplement it. notme's tests run these bytes against chains
notme mints, so "a notme task credential verifies" is checked against the
artifact other parties actually use.

| file | what |
|---|---|
| `leyline_sign.wasm` | LLO `v0.25.0` release asset, unmodified (320,421 bytes; no imports) |
| `SHA256SUMS` | that release's `SHA256SUMS`, unmodified (it lists every asset, not just this one) |
| `llo-release.json` | the pin: tag, tag commit, sha256 of `SHA256SUMS` and of each vendored asset, and what was checked about signatures and source |

Nothing in the deployed Worker loads this directory.

## verify it yourself, with stock tools

```sh
cd wasm && shasum -a 256 -c SHA256SUMS --ignore-missing
```

That proves the file matches the release's own checksum list. It does not
prove who built it, because LLO publishes no signature (below).

## how it stays honest

- `task docs:check` runs `scripts/fetch-llo-wasm.ts --check` (offline): the
  sha256 of `SHA256SUMS` and of every asset must equal the pin, every asset
  must match its `SHA256SUMS` line, no unpinned file may sit here, and
  `leyline_sign.wasm` must still export what notme binds by name.
- The tests check the pin again on the exact bytes they compile:
  `worker/src/__tests__/llo-cert-path.test.ts` (plain pool) and
  `worker/vitest.workers.config.mts` (workers pool, before workerd sees them).
- `task llo:wasm` re-downloads the pinned tag and refuses anything that does
  not match. `task llo:wasm -- --pin vX.Y.Z` re-pins to a new release; the
  diff to `llo-release.json` is what a reviewer reads.

## trust, as it actually is

- **No signature exists.** v0.25.0 ships no cosign/sigstore bundle for
  `SHA256SUMS` or any asset, GitHub holds no artifact attestation for either
  digest, and LLO's `release.yml` attests only its OCI image. The tag object
  is unsigned. So the pin is trust-on-first-use. The fetch script fails if a
  signature file appears next to `SHA256SUMS`, so the day LLO signs, notme has
  to start verifying it.
- **Source check: a near reproduction, not proof.** Rebuilt from the tag with
  the pinned toolchain, every wasm section has the released length and the
  data, export and type sections are byte-identical, but the function, code,
  element and name sections differ, so the bytes do not match. Details in
  `llo-release.json`.

## why vendor, not fetch in CI

320 KB, under the ~2 MB line where a binary in git starts to cost more than
it saves. Vendoring keeps every gate offline: the test pools refuse the
network (notme-3fc74b, notme-73202e), and a cache keyed on a download would
add a moving part whose only job is to reproduce this file. The other two
wasm assets in the release (`leyline_envelope.wasm`, `leyline_cas_ffi.wasm`)
are not vendored because nothing here uses them yet. Add one to
`llo-release.json`'s `assets` and run `task llo:wasm` when something does.
