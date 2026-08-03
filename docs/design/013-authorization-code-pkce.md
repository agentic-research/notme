<!--
@doc-check
@endpoints: GET /authorize, POST /authorize/code, POST /authorize/redeem
-->
# ADR-013: Authorization code + PKCE for the /authorize redirect

**Status:** Accepted (2026-08-03)
**Bead:** notme-2bba44
**Relates to:** [011-external-oauth-provider.md](011-external-oauth-provider.md) (the public-AS project this is a down payment on), [012-sender-constrained-oidc.md](012-sender-constrained-oidc.md) (why notme refuses to vend bearer identity assertions), THREAT_MODEL.md `token in URL logs`, notme-07204f (the corrected threat-model claim that surfaced this)
**Standards:** RFC 6749 §4.1 (authorization code grant), RFC 7636 (PKCE), RFC 8414 §2 (AS metadata omission rules), OAuth 2.0 Security BCP (§4.3.2 — access tokens MUST NOT be transmitted in URI query parameters)

## Context

`/authorize` completes by navigating the browser to
`${redirect_uri}?token=<access token>`. That token is an **unbound bearer** —
`mintRedirectToken` omits `cnf.jkt` deliberately, because the flow's DPoP
keypair does not survive the navigation and there is nothing left on the far
side to prove possession with.

The binding constraint is real. The delivery is not. A live credential in a
URL query parameter lands in:

1. Browser history on the user's machine.
2. The destination's request line, therefore its access logs. Verified: the
   sole consumer, `rig/web/src/index.ts:355`, reads it with
   `c.req.query('token')` — a server-side read.
3. Onward `Referer` headers from the destination page, governed by the
   destination's Referrer-Policy, not ours.

Bounded by a 5-minute lifetime and an `aud` that pins the token to one
resource server — moderate, not critical. But it is the one place in notme
where a credential is handed over in a form that possession alone unlocks,
which is the exact thing the project exists to eliminate. "Short-lived
bearer" is the argument notme rejects everywhere else.

## Decision

Replace token-in-URL with **an authorization code the URL carries instead of
a credential**, redeemed server-to-server, bound with PKCE.

```
rig                        browser                    notme
 |-- verifier, challenge      |                          |
 |   stored under `state`     |                          |
 |-- 302 /authorize?code_challenge=…&state=… ----------->|
 |                            |<-- session check, page --|
 |                            |-- POST /authorize/code -->|   (session-auth)
 |                            |<-- { code } --------------|
 |<-- 302 ?code=…&state=… ----|                          |
 |-- POST /authorize/redeem { code, code_verifier } ----->|   (PKCE-auth)
 |<-- { access_token } --------------------------------- |
```

What each property buys:

- **The URL carries a code, not a credential.** A code in a log is worthless
  once redeemed, and it is single-use.
- **PKCE (RFC 7636, S256 only)** binds the code to the party that started the
  flow. An attacker who reads the code out of a log still cannot redeem it
  without the verifier, which never leaves rig. This is what makes the
  logged-code exposure genuinely inert rather than merely short.
- **Server-to-server redemption** means the access token never enters a URL,
  a browser history entry, or a Referer.

### Deliberately NOT in scope

This is a down payment on ADR-011, not ADR-011.

- **No client registry / `client_id` / `client_secret`.** `ALLOWED_REDIRECT_HOSTS`
  (`src/auth/redirect-uri.ts`) is an exact-host allowlist and already serves as
  the first-party client registry. Adding a registry is ADR-011's job.
- **No consent UI.** First-party flow; the user is the deployer.
- **No refresh tokens.** Unchanged from today — 5-minute access tokens, re-run
  the flow.
- **`authorization_endpoint` and `code_challenge_methods_supported` stay in
  `FORBIDDEN_METADATA_FIELDS`.** This is the subtle one, and it is deliberate.
  Publishing them advertises "notme is an OAuth AS you can integrate with,"
  which invites exactly the third-party integration that has no client
  registry and no consent screen behind it. The flow here is first-party by
  construction — the redirect-host allowlist *is* the authorization. When
  ADR-011 lands the registry and consent, flipping those two entries is a
  one-line change and becomes true at the same moment it becomes safe.

  The existing rationale comment on `authorization_endpoint` ("no grant type
  uses it — and none does") is now narrowed rather than deleted: no *publicly
  available* grant uses it.

### Rejected alternatives

- **Fragment (`#token=`).** Kills the log and Referer vectors but leaves the
  token in history, keeps a bearer as the thing being handed over, and forces
  rig's server-side read to become client-side anyway — the same migration
  cost as the code flow for a strictly weaker result. Rejected as a
  half-measure that would have to be undone.
- **POST-to-target (auto-submitting form).** Same rig-side cost, no advantage
  over the code flow, and no PKCE story.
- **Leave it, rely on the 5-minute TTL.** This is the status quo, and the
  argument for it ("the window is short") is the bearer-token argument notme
  exists to refuse.

## Storage

Codes live in the singleton `SigningAuthority` DO's SQLite, alongside
`dpop_jtis`, and follow the same atomicity discipline as
`mintDPoPTokenOnce`: SQLite statements run synchronously before the first
await, so two concurrent redemptions cannot both observe an unspent code.

**The code is stored as SHA-256, never in the clear.** A code is a
credential until redeemed; storing the hash means a read of the DO's storage
does not yield redeemable codes. Comparison is by hash lookup, so it is not
a timing oracle on the code value.

Fields: `code_hash` (PK), `principal_id`, `scopes`, `audience`,
`redirect_uri`, `code_challenge`, `expires_at`. Redemption requires the
presented `redirect_uri` to equal the stored one (RFC 6749 §4.1.3), which
stops a code minted for one destination being redeemed toward another.

**TTL: 60 seconds.** RFC 6749 §4.1.2 recommends a maximum of 10 minutes; the
code is redeemed by a server that already holds the verifier, so the real
window needed is one round-trip. Short TTL is the cheapest defense.

## Migration

`/authorize` negotiates on capability: **if the request carries
`code_challenge`, it completes with `?code=`; if not, it completes with
`?token=` as today.** rig ships its side, then the legacy branch is deleted.

This is a migration, not a hedge. The legacy branch has a deletion bead
(notme-2bba44 follow-up) and no reason to outlive rig's deploy. A flag-day
break is not acceptable here for a specific reason: `/admin/setup-github` is
the flow used to *recover* admin access, so breaking it costs more than the
exposure being closed.
