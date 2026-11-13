# schema/codegen

The pin for ley-line-open's **released** `capnpc-schema-bridge-zod`, the capnp
plugin that generates `../../gen/ts/identity.zod.ts` (notme-3e9c73). notme
neither builds nor vendors the plugin: the binaries are downloaded per host and
verified before capnp runs them.

| file | what |
|---|---|
| `llo-release.json` | the pin: tag, tag commit, sha256 of `SHA256SUMS`, and sha256 + size of each platform binary |
| `SHA256SUMS` | that release's `SHA256SUMS`, unmodified (it lists every asset, not just the plugin) |

```sh
task schema:zod                           # regenerate gen/ts/identity.zod.ts
task schema:zod:check                     # fail if the committed file is stale (CI `schema` job)
task llo:schema-bridge -- --check         # offline pin check (also in `task docs:check`)
task llo:schema-bridge -- --pin vX.Y.Z    # re-pin; review the llo-release.json diff, then regenerate
```

LLO publishes no signature or attestation for these assets, so the pin is
trust-on-first-use, as it is for `../../wasm/`. Details, and what the generated
validators admit, are in [`../README.md`](../README.md#codegen).
