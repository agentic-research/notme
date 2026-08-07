# notme root trust anchor

This directory is the out-of-band copy of notme's root CA. It exists so a third
party can **pin** the root through a channel that is not the TLS endpoint being
authenticated.

| File | What it is |
| --- | --- |
| `notme-root.pem` | The **same certificate** that `https://auth.notme.bot/.well-known/ca-bundle.pem` serves. The file *framing* may differ by trailing whitespace, so compare the parsed certificate, never the file bytes — see [the warning below](#do-not-compare-file-bytes). |
| `notme-root.json` | Machine-readable pin: authority URL, subject, SPKI SHA-256, certificate SHA-256, validity window. |

`worker/src/__tests__/trust-anchor.test.ts` re-derives both digests from
`notme-root.pem` on every CI run (`task worker:check`, run by
`.github/workflows/ci.yml`), so the pin and the certificate beside it cannot
drift apart. A pin that disagrees with its own certificate is worse than no pin,
because it still looks authoritative.

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

Measured 2026-08-05:

| | bytes | SHA-256 of the *file* | SHA-256 of the *parsed certificate* (DER) |
| --- | --- | --- | --- |
| served by `auth.notme.bot` | 484 | `cee35250…87f2` | `c1ddec9d…ae86` |
| `trust/notme-root.pem` | 485 | `7d253cfe…cb53` | `c1ddec9d…ae86` |

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
- **Revocation.** A compromised credential remains valid until it expires; the
  only coarser lever is a CA epoch bump that invalidates everything at once.
  Tracked as notme-77a024 (*Revocation has no unit between "wait for expiry" and
  "revoke every credential ever issued"*).
- **Cryptographic proof of this file's provenance.** The anchor is protected by
  git history and code review, not by a signature. Signing this material with
  the release pipeline's Sigstore identity is the second half of the anchor;
  the pipeline already signs keylessly for images (`.github/workflows/
  release.yml` requests `id-token: write` for cosign), so the capability exists
  but is not applied to this directory.
- **Any statement about the leaf.** Pinning the root says the issuer is who you
  expected. It says nothing about whether a particular subject *should* hold the
  certificate it presents — that remains your authorization policy's job.

Background and the broader gap: notme-8e8836, and `docs/design/008-bridge-cert-csr-wimse.md`.

## Updating this anchor

A change to `notme-root.pem` is a change to the trust root and must be reviewed
as such. Regenerate `notme-root.json` from the certificate rather than editing
the digests by hand, and expect `trust-anchor.test.ts` to fail loudly if the two
ever disagree.

Re-measure the byte/digest table above at the same time. It is a dated
observation, not an invariant — the two *file* digests are expected to go stale,
and only the point they illustrate (compare parsed certificates, not files) is
permanent.
