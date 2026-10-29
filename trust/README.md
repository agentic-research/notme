# notme root trust anchor

This directory is the out-of-band copy of notme's root CA. It exists so a third
party can **pin** the root through a channel that is not the TLS endpoint being
authenticated.

| File | What it is |
| --- | --- |
| `notme-root.pem` | The **same certificate** that `https://auth.notme.bot/.well-known/ca-bundle.pem` serves. The file *framing* may differ by trailing whitespace, so compare the parsed certificate, never the file bytes — see [the warning below](#do-not-compare-file-bytes). Refreshed 2026-10-29; see [staleness](#this-file-went-stale-twice). |
| `notme-root.json` | Machine-readable pin: authority URL, subject, SPKI SHA-256, certificate SHA-256, validity window. |

`worker/src/__tests__/trust-anchor.test.ts` re-derives both digests from
`notme-root.pem` on every CI run (`task worker:check`, run by
`.github/workflows/ci.yml`), so the pin and the certificate beside it cannot
drift apart. A pin that disagrees with its own certificate is worse than no pin,
because it still looks authoritative.

## This file went stale twice

Self-consistency is necessary and it is not sufficient. Between 2026-08-28 and
2026-09-25 the committed certificate was the **pre-heal root** — serial
`d01f2a0a`, `pathlen:0`, issued 2026-03-31 — while production served a root
re-issued under the **same key** with `pathlen:1` (`notme-1b1db4`). Both tests
passed the whole time, because both compared the anchor only to itself.

The public key never changed, so nobody pinning the SPKI was affected. Anyone
pinning the **certificate** was pinning one production no longer serves, and
`pathlen:0` forbids the intermediate tier ADR-019 D4 issues — so a verifier
using the committed file would have rejected every tier-signed certificate.

Caught while wiring the certificate transparency log, whose `roots.<env>.pem`
is compiled in and whose chain validation enforces path length: shipping the
stale anchor would have made the log refuse the certs it exists to record
(`notme-1b46a8`).

The test now also asserts the anchor's `pathLenConstraint` equals `CA_PATH_LEN`
in `signing-authority.ts` — a fact that moves when production moves, checked
without a network call. Re-verified by restoring the stale file: it fails.

**It happened again** on 2026-10-28. The root was re-issued, again under the
same key, so that its `notBefore` is the key's creation time (`notme-0c494f`).
Before that, a re-issued root post-dated every signature made before it. The
committed file kept serial `5dcb45c3` with `notBefore` 2026-08-28; production
served serial `e7063d28` with `notBefore` 2026-03-29. The path-length test
could not catch it: path length was unchanged.

Two independent checks against itself had now failed the same way. So the fix
compares to production instead:

- `task trust:refresh` re-fetches the root, regenerates the PEM and every field
  of `notme-root.json` from it (same digest path as the test), and **refuses,
  writing nothing, if the SPKI changed**.
- `task trust:refresh -- --check` only compares. `worker:verify` runs it after
  every production deploy, so a re-issue that leaves `trust/` behind fails the
  deploy gate the same day rather than four weeks later.

**A changed SPKI is not a refresh.** It is a different authority and needs its
own review. That is why the script stops there, not because of a bug.

## Why this exists

Verification of a notme credential bottoms out in the root CA. Until now the
only way to obtain that root was to fetch `/.well-known/ca-bundle.pem` over TLS
from `auth.notme.bot` — the same host that issued the credential being checked.

The root is **self-signed** (`subject == issuer == "CN=signet-authority,
O=notme"`, confirmed by the commands below). Nothing above it vouches for it. So
that fetch does not *confirm* trust, it *establishes* it, fresh, every time —
and whoever controls the hostname controls the trust root. An adversary with the
DNS name and a WebPKI certificate for it can serve their own CA and every
downstream verification will succeed against the wrong root.

Committing the fingerprint here gives a consumer a second, independent channel:
git history, reviewed and distributed separately from the TLS endpoint. A
mismatch between what git says and what the endpoint serves is then *visible*
rather than silently accepted.

## Pin the public key, not the certificate

Pin `spki_sha256`. It is the SHA-256 of the certificate's
SubjectPublicKeyInfo — the key itself, in its DER encoding.

- **A certificate can be reissued for the same key.** Extending validity,
  correcting a name, or adding an extension produces new certificate bytes and a
  new `cert_sha256`, while the authority and its key are unchanged. A cert-hash
  pin breaks on that routine, non-security-relevant event, and a pin that cries
  wolf is one that gets disabled. An SPKI pin survives it.
- **A key rotation SHOULD break the pin.** That is not a false alarm — it is a
  genuine trust event, and a consumer must decide deliberately to accept the new
  key rather than absorb it silently. HPKP (RFC 7469) pinned SPKI hashes for
  exactly this reason.

`cert_sha256` is published too, but as an *identity* check on this exact
certificate — it confirms that the committed **certificate** was not altered.
Note that it is the digest of the parsed DER, not of the `.pem` file, and it is
not the long-lived trust anchor.

## Verification procedure

### Do not compare file bytes

**Never `sha256sum` this `.pem` against the served response, and never `diff`
the two files.** They are expected to differ, and a mismatch there means
nothing.

Measured 2026-10-29:

| | bytes | SHA-256 of the *file* | SHA-256 of the *parsed certificate* (DER) |
| --- | --- | --- | --- |
| served by `auth.notme.bot` | 484 | `bc6f4e96…c48b` | `7fd698cb…afbd` |
| `trust/notme-root.pem` | 485 | `b38beff7…3a02` | `7fd698cb…afbd` |

One byte: the served response has no trailing newline, the committed file does.
The certificate is identical — same key, same signature, same DER.

The committed file keeps its trailing newline deliberately. Chasing byte
equality would make this anchor depend on the endpoint's HTTP framing, which
can change for reasons that are not trust events at all (a whitespace edit in
the Worker, a proxy, a different serialization) and would then raise an alarm
indistinguishable from a real root substitution. **A trust anchor that cries
wolf gets switched off.** So every command below hashes what `openssl` parsed
out of the file, not the file.

### 1. Confirm the committed certificate matches the committed pin

Do this first, on a fresh clone. It needs no network.

```sh
# SPKI SHA-256 — must equal .spki_sha256 in notme-root.json
openssl x509 -in trust/notme-root.pem -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256

# Certificate DER SHA-256 — must equal .cert_sha256
openssl x509 -in trust/notme-root.pem -outform DER | openssl dgst -sha256

# The root is self-signed; this is what makes out-of-band pinning necessary.
openssl x509 -in trust/notme-root.pem -noout -subject -issuer -dates
```

Expected:

```
subject=CN=signet-authority, O=notme
issuer=CN=signet-authority, O=notme
notBefore=Mar 31 01:44:33 2026 GMT
notAfter=Mar 30 13:44:33 2036 GMT
```

### 2. Compare a live bundle against the pin

```sh
curl -sS https://auth.notme.bot/.well-known/ca-bundle.pem -o /tmp/notme-fetched.pem

diff <(openssl x509 -in /tmp/notme-fetched.pem -pubkey -noout \
        | openssl pkey -pubin -outform DER | openssl dgst -sha256) \
     <(openssl x509 -in trust/notme-root.pem -pubkey -noout \
        | openssl pkey -pubin -outform DER | openssl dgst -sha256) \
  && echo "SPKI matches the committed pin"
```

If that `diff` reports a difference, **stop**. Either notme rotated its root
key, or the endpoint is not serving notme's root. Those are indistinguishable
from the outside, which is the point: resolve it out of band before proceeding.

### 3. Adopt the pin in your own configuration

Copy `spki_sha256` into your own config, deployment manifest, or verifier — do
not re-read this file over the network at verification time. A pin fetched at
use is not a pin. Then use `notme-root.pem` as your CA file:

```sh
# Verify a notme-issued leaf against the pinned root
openssl verify -CAfile trust/notme-root.pem <leaf-cert.pem>
```

What has actually been measured here is the root's own self-signature
(`openssl verify -CAfile trust/notme-root.pem trust/notme-root.pem` → `OK`).
The leaf form above is the standard invocation, but it has *not* been exercised
against a notme-issued leaf in this directory's verification. That chain is
cross-algorithm — an Ed25519 CA signing P-256 bridge certs — and ADR-008 lists
exactly that combination as still requiring empirical verification against CF's
mTLS validation stack. Not every TLS implementation accepts it. Confirm it on
your own stack before depending on it.

### Note on multi-certificate bundles

`openssl x509` reads only the **first** certificate in a PEM file. Today the
endpoint serves exactly one, so the commands above are exact. If a future
rotation makes the bundle carry several, split it before hashing (`openssl
crl2pkcs7 -nocrl -certfile bundle.pem | openssl pkcs7 -print_certs`) and check
that the pinned SPKI is present among them — otherwise you would be checking
only whichever certificate happens to be first.

## What this gives you, and what it does not

**It gives you:** a way to stop trusting whatever TLS happened to serve you. The
root's identity comes from a reviewed commit in a repository distributed
independently of `auth.notme.bot`, so for a consumer who *actually performs step
2*, substituting the trust root means compromising both channels rather than
just the hostname. A change to the root key becomes a visible diff in a pull
request instead of an invisible change in a response body. Note the conditional:
material committed here but never checked buys nothing.

**It does not give you:**

- **Issuance transparency.** Nothing here tells you *what* notme issued. A root
  that is genuinely notme's can still sign a certificate for an identity that
  never asked for one, and no third party would observe it. Tracked as
  notme-907299 (*No issuance transparency: notme publishes its keys but records
  nothing about what it issued*).
- **Revocation of an issued certificate.** Revocation acts on what can be
  issued next: a grant (next request), a machine (next renewal), a task (next
  mint on that machine), or everything (an epoch bump, ≤ 5 minutes for online
  verifiers). A certificate already issued stays valid until it expires, which
  is 5 minutes for leaves and 1 hour for a machine's tier. There is no CRL or
  OCSP, by design.
- **Any statement about the leaf.** Pinning the root says the issuer is who you
  expected. It says nothing about whether a particular subject *should* hold the
  certificate it presents — that remains your authorization policy's job.

Background and the broader gap: notme-8e8836, and `docs/design/008-bridge-cert-csr-wimse.md`.

## Verify the signed anchor

From the first release cut after 2026-10-29, the release workflow signs
`notme-root.pem` and `notme-root.json` with its own keyless Sigstore identity
and attaches them, with their bundles, to the GitHub release. It **refuses to
sign** unless the committed root is the one production serves. Releases before
then carry no signed anchor; for those, git history is the only protection.

```bash
TAG=vX.Y.Z   # the release you trust
BASE=https://github.com/agentic-research/notme/releases/download/$TAG
curl -fLO $BASE/notme-root.pem && curl -fLO $BASE/notme-root.pem.sigstore.json

cosign verify-blob notme-root.pem \
  --bundle notme-root.pem.sigstore.json \
  --certificate-identity "https://github.com/agentic-research/notme/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Use cosign **3.1.3 or later**: older releases can report "Verified OK" for a
substituted legacy-format bundle (GHSA-fx35-mq7g-6g98).

The identity is **exact**: one workflow at one tag. A regexp here is how
signet's release verification broke and how, unescaped, a pattern matches
workflows it should not (see the container section of the top-level README).
Then pin the key as above: the SPKI of the verified file must be the one you
expect.

What the signature adds: the root now carries a statement from the release
workflow that a party controlling only `auth.notme.bot` cannot forge. What it
does not add: the workflow signs what is in the repository, so anyone who can
push a tag can sign a root. The review on the commit that changes `trust/` is
still the control on *which* root is signed.

## The CT log key pin

`notme-ct-log.json` pins the public key of notme's issuance transparency log
(`ct/README.md`), by the same logic as the root: `metadata.json` fetched from
the log authenticates nothing by itself, so the key is also committed here and
signed by the release workflow.

Two states, and tooling recognises exactly these:

- `{"status": "not-provisioned", ...}`: the log does not exist yet. This is
  today's state. `task ct:verify` exits 0 and says so; the release does not
  sign the file.
- `{"status": "provisioned", "log_name", "metadata_url", "log_id", "key",
  "key_spki_sha256", "observed_at"}`: `key` is the base64 SPKI DER, `log_id`
  its SHA-256 (base64), `key_spki_sha256` the same digest in hex. Written only
  by `task ct:verify -- --write --metadata <url>`, which refuses if a
  different pin is already recorded.

`task ct:verify` then exits 1 if the live log serves a different key or a
`log_id` that is not the SHA-256 of its key. As with the root, a changed key is
a different log, not a refresh: replace the pin only by a reviewed manual edit.

Once `provisioned`, the `trust-anchor` release job signs it as
`notme-ct-log.json` with a `.sigstore.json` bundle, verified exactly like the
root (the section above, with `notme-ct-log.json` in place of
`notme-root.pem`). Unlike the root, the release job does not compare it to the
live log before signing; run `task ct:verify` first.

## Updating this anchor

A change to `notme-root.pem` is a change to the trust root and must be reviewed
as such. Regenerate `notme-root.json` from the certificate rather than editing
the digests by hand, and expect `trust-anchor.test.ts` to fail loudly if the two
ever disagree.

Re-measure the byte/digest table above at the same time. It is a dated
observation, not an invariant — the two *file* digests are expected to go stale,
and only the point they illustrate (compare parsed certificates, not files) is
permanent.
