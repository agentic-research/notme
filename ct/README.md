# notme-ct — issuance transparency log

A Static CT API log for notme's own issuance, composed from
[cloudflare/azul](https://github.com/cloudflare/azul)'s `ct_worker`. Answers
`notme-907299`: notme publishes its keys but records nothing about what it
issued, so a stolen CA key mints silently.

This directory holds the pieces that define **notme's log** — its roots, its
temporal interval, its policy. azul is the engine and is not vendored here.

## Status — what is actually proven

Verified 2026-09-25 against a locally running `ct_worker`
(`DEPLOY_ENV=notme npx wrangler -e notme dev`) and a **real** certificate
minted by notme's own `mintBridgeCertPair`:

- `add-chain` accepts the chain and returns an SCT carrying the `leaf_index`
  extension (`ext_type 0`, uint40 index).
- `get-roots` serves exactly one root: `CN=signet-authority, O=notme`.
- `log.v3.json` publishes the log's P-256 key and a `log_id` matching the
  `id` in the SCT.

**Not yet done**, and not claimed anywhere in this repo:

- `add-pre-chain` — needs notme to mint a *precertificate* carrying the CT
  poison extension. Nothing does that yet.
- SCT embedding at the three authority mint paths, plus a submission client
  for the offline producer `mintTaskCertPair`.
- Publishing the log key via pipeline-signed trust material rather than only
  `/metadata` (`notme-8e8836`).
- `cosign verify --ctfe=...` accepting a notme artifact while a cert with no
  valid SCT is rejected. That negative control is the point of the whole
  exercise and it has not been run.

## Two preconditions, both now met

1. **Ed25519 chain signatures.** azul's `x509_util::is_link_valid` accepted
   only ECDSA and RSA; Ed25519 (RFC 8410) fell to `_ => false`, so every
   notme certificate was refused. Fixed upstream in
   [azul#281](https://github.com/cloudflare/azul/pull/281), merged
   2026-08-31.
2. **Root path length.** The served root is `CA:TRUE, pathlen:1`, so
   tier-signed certificates can chain. (It was `pathlen:0` for five months —
   `notme-1b1db4`.)

## A third precondition the spike missed

`notme-1b46a8` recorded `require_server_auth_eku` as configuration. It is
not: `ct_worker` hardcoded `true` at its only call site and the field was
absent from `config.schema.json`.

notme's leaves carry `id-kp-clientAuth` and nothing else — the mTLS leaf has
exactly that EKU, and the signing leaf has no EKU extension at all — so
**every notme certificate was rejected**, for a reason unrelated to the one
the spike had already fixed. RFC 6962 §3.1's requirement is right for WebPKI
logs and wrong for a workload-identity CA.

Upstream change prepared: add the flag to the per-log config, default `true`
so no existing log changes behaviour.

## Reproducing the proof

`scripts/prove-chain-accepted.sh` submits **one** chain to two shards that
differ in exactly one field, and requires the lenient one to issue an SCT and
the strict twin to refuse. If both accepted, the flag would not be
load-bearing and the result would prove nothing about it; if both refused,
the Ed25519 arm would be the suspect.

    LOG=http://localhost:8787 CHAIN=chain.json ./scripts/prove-chain-accepted.sh

`CHAIN` is `{"chain": ["<base64 DER leaf>", ...]}`.

## Files

| file | what it is |
|---|---|
| `config.notme.json` | the log shards, copied into azul's `crates/ct_worker/` as `config.<DEPLOY_ENV>.json` |

## Where the roots file comes from

`roots.<DEPLOY_ENV>.pem` is **not** committed here. A real shard's roots file
is `trust/notme-root.pem` — the one out-of-band copy of the root, pinned and
reviewed as a trust-root change:

    cp ../trust/notme-root.pem <azul>/crates/ct_worker/roots.notme.pem

A second copy in this directory is exactly the drift that had to be fixed to
get here: the committed anchor had gone stale against production and nothing
compared it to anything outside itself (see `trust/README.md`). One copy.

The **local** proof does not use that root, and saying so matters. Its chain is
minted by a throwaway `SigningAuthority` instance in the workers test pool, so
its roots file is that instance's own CA — generated per run, never committed.
The certificates are real notme output from the real mint path, with the same
extensions, algorithms and EKUs; only the issuing instance differs. That is
what makes the proof valid and what keeps it from needing a production key.

`reject_expired` is `false` on both shards: notme leaves live five minutes,
so a fixture minted minutes earlier would be refused for a reason that has
nothing to do with the property under test. A production shard should set it
`true` — submission happens at issuance.
