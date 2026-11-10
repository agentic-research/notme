<!--
@doc-check
@endpoints: POST /join, POST /cert/gha
-->
# ADR-023: An OIDC proof at /join names its invite in the audience

**Status:** accepted (2026-11-09; owner: "These make sense I think")
**Beads:** `notme-e3dede` (this decision), `notme-3dfe15` (option A, shipped:
single-use `jti` at /join)
**Composes:** ADR-020 (compose, do not invent), ADR-021 (registration
policy), ADR-006 (DPoP, whose server nonce this reuses)

## Context

`POST /join` with `{ token, proof: { type: "oidc", token } }` redeems an
invite for the identity in an OIDC token. Today that token must carry the
shared audience `notme.bot` (`NOTME_AUDIENCE`, `@notme/contract`), the same
audience `/cert/gha`, `/cert`, `/token` and `/auth/oidc/login` accept.

Option A (`notme-3dfe15`) made the token single-use: its `jti` is spent in
the DO when the invite is redeemed, and in the shared `jti:<jti>` keyspace
afterwards. What option A cannot do is tie the token to **this** join. A
`notme.bot` token captured anywhere it travels (a CI log, a proxy, a
compromised step in someone's workflow) can be spent at /join against any
invite its holder has, provided nobody spent it first. The owner's ruling
(2026-11-03): "a makes sense regardless. But b seems correct long term. We
don't want to make hell for an automated world."

The constraint is the hard part. GitHub Actions OIDC tokens have no `nonce`
claim. The only value a workflow controls is `audience`
(`core.getIDToken(audience)`). So a server nonce, for an automated caller,
has to travel in the audience, and the shared audience is a contract other
code pins.

## Survey: who uses the `notme.bot` audience, and who calls /join with a proof

Observed on 2026-11-09 by searching first-party source, not inferred.

| Caller | Mints `aud=notme.bot`? | Calls | Calls /join with a proof? |
|---|---|---|---|
| notme `action/` (`core.getIDToken(audience)`, `action/src/index.ts:74`) | yes (input `audience`) | `/cert/gha` | no |
| signet `authority exchange-token` (`cmd/signet/authority_exchange.go`) | yes, with `--audience notme.bot` | `<authority>/exchange-token`, a signet-authority route notme does not serve (de-advertised in 4a51a6d) | no |
| signet `sigstore-kms-signet` (`cmd/sigstore-kms-signet/enroll.go:157`) | yes (`defaultOIDCAudience`) | `/cert/gha` | no |
| notme `_login.html` | — | `/join` **without** a proof (passkey path) | no |
| rig | no | — (WAF rule names the path only) | no |
| two private substrate repos | one schema field documents `aud` as e.g. `"notme.bot"` | — | no |

**No first-party caller sends an OIDC proof to /join.** Every automated
caller of `notme.bot` goes to `/cert/gha` (or to a signet authority). So:

1. changing the shared audience would break three callers to fix a route
   none of them use, and is rejected;
2. the deprecation window for plain `notme.bot` at /join protects
   third-party callers we cannot see, not first-party ones, and can end on
   evidence (below) rather than on a date.

## Decision

### D1. A /join-specific audience carries the nonce; the shared one is untouched

/join gains a challenge step. The caller asks for a challenge for its
invite, then requests an OIDC token whose audience is the challenge:

```
POST /join/challenge   { "token": "<invite>" }
→ 200 { "audience": "https://auth.notme.bot/join/<nonce>", "expires_at": <unix> }

# in a workflow: one step
aud=$(curl -s -X POST …/join/challenge -d '{"token":"…"}' | jq -r .audience)
token=$(core.getIDToken "$aud")            # or ACTIONS_ID_TOKEN_REQUEST_URL&audience=$aud

POST /join   { "token": "<invite>", "proof": { "type": "oidc", "token": "<token>" } }
```

`notme.bot` stays exactly what every consumer pins. The new audience is a
URL under **this deployment's** authority URL (`SIGNET_AUTHORITY_URL`, as
the passkey origin is derived), never a literal, so:

- it cannot collide with any other relying party's audience;
- a token minted for staging, or for a self-hosted deployment, does not
  verify here. That closes THREAT_MODEL residual F3 for /join: today the
  literal `notme.bot` is shared by every deployment, so single-use holds per
  deployment only.

### D2. The nonce is the DPoP nonce construction, bound to the invite

Compose, do not invent (ADR-020): `src/auth/dpop-nonce.ts` already issues a
stateless server nonce, `<issuedAt>.<base64url(HMAC)>`, under an HKDF key
derived from the session secret with a domain separator. The join nonce is
the same construction with:

- its own domain separator, `notme-join-nonce-v1`, so a DPoP nonce is not a
  join nonce and vice versa;
- the MAC covering `domain : issuedAt : base64url(SHA-256(invite token))`,
  so a challenge issued for one invite does not verify against another;
- the same 300 s lifetime and 5 s future skew.

Stateless for the reasons dpop-nonce.ts gives: no write per challenge, and
no unauthenticated write amplification. Stateless means the nonce is not
single-use by itself. It does not need to be: the token's `jti` is
single-use (option A), and the invite is single-use. The nonce supplies what
those two lack, **binding**: a token minted for this challenge names this
invite and nothing else.

### D3. Such a token is useless anywhere else, by construction

`/cert/gha`, `/cert`, `/token` and `/auth/oidc/login` pin the audience
`notme.bot` (or `GHA_CERT_AUDIENCE`). A token whose audience is
`https://auth.notme.bot/join/<nonce>` fails every one of them, with no new
code on those routes. The implementation must pin that with a test per
route, not assume it.

### D4. /challenge is not an invite oracle

`POST /join/challenge` answers 200 with a challenge for **any** well-formed
token, valid invite or not. Whether the invite exists is decided at /join,
which already answers garbage and expired invites with the same 403 as a bad
proof (`ERROR_STATUS.OIDC_PROOF_REJECTED`). It sits behind `PASSKEY_LIMITER`
under its own key prefix (`join-challenge:<ip bucket>`), as the no-proof
branch of /join already does under `passkey:`.

### D5. Plain `notme.bot` at /join: allowed, counted, then refused on evidence

During the window, /join accepts either audience:

- the challenge audience: verified as D2;
- plain `notme.bot`: accepted as today under option A, and **counted**
  (a `joinPlainAudience: { count, lastAt }` counter in the authority DO,
  served at `/admin/alarm-health` beside the CT and Rekor counters, plus a
  log line naming the issuer, never the subject).

A config flag `JOIN_REQUIRE_NONCE` (default off, parsed like
`DPOP_REQUIRE_NONCE`: only `true`/`1` enable it) turns plain `notme.bot`
into a refusal. The survey found no first-party caller, so the switch can
flip once the counter has read zero for 30 days in production. The counter
decides, not a calendar.

### D6. Issuers

- **GitHub Actions**: D1 as written.
- **auth.notme.bot**: the same rule. A caller holding a notme-issued token
  at /join requests it with the challenge audience.
- **Google** (`GOOGLE_CLIENT_ID`): the audience is the deployment's client
  id and cannot carry a nonce. Google binds natively through the `nonce`
  claim in a browser flow, which is out of scope here (bead: browser OIDC).
  Until then a Google token at /join stays on option A, and
  `JOIN_REQUIRE_NONCE` must not refuse Google tokens. The implementation
  states that exception in code, beside the flag.

## Consequences

- One extra round trip for an automated /join, in exchange for a token that
  cannot be spent anywhere but the invite it was minted for.
- No change to `@notme/contract`'s audience, and no change for the action,
  signet or sigstore-kms-signet. `CONTRACT_VERSION` is untouched. The new
  route and its response shape are additive.
- `verifyOIDC` gains a per-call expected-audience override. The issuer map
  stays the trust root. The override can only **narrow** what an issuer
  may carry (a challenge audience for a trusted issuer), never add an
  issuer.

## Not verified yet (must be measured, not assumed)

- GitHub's limits on a requested audience (length, characters). The
  challenge audience is about 90 characters. A workflow in
  `test-identity.yml` must request one and spend it at a staging /join
  before `JOIN_REQUIRE_NONCE` is ever enabled.
- Whether any third party calls /join with a proof. That is what D5's
  counter is for.

## Implementation outline (after acceptance)

1. `src/auth/join-nonce.ts`: issue and verify, reusing dpop-nonce's
   key-derivation shape with the new domain. Unit tests: wrong invite,
   expired, future-dated, bad MAC, DPoP nonce presented as a join nonce.
2. `POST /join/challenge` behind `PASSKEY_LIMITER` (`join-challenge:`);
   returns 200 for a garbage invite.
3. /join: accept a challenge audience (verified against the body's invite)
   or plain `notme.bot` (counted). `JOIN_REQUIRE_NONCE` refuses the latter
   except for Google.
4. Route tests: a challenge-audience token is refused at `/cert/gha`,
   `/cert`, `/token` and `/auth/oidc/login`.
5. A staging workflow proves D1 end to end with a real GitHub token.
