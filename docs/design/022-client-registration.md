<!--
@doc-check
@endpoints: GET /.well-known/oauth-authorization-server, GET /authorize, POST /authorize/code, POST /authorize/redeem, POST /token
-->
# ADR-022: OAuth client registration is a document you fetch, not a row you store

**Status:** proposed (2026-10-26)
**Beads:** `notme-be4bef` (this decision), `notme-0078a9` (ADR-011, whose
apps-registry shape this replaces)
**Composes:** ADR-013 (authorization code + PKCE), ADR-020 (compose, do not
invent), ADR-021 (principal registration), ADR-010 (canonical encoding);
cloister ADR-0055 (RFC 9728 discovery); signet ADR-013 (policy over the
certificate chain, which consumes `client_tier`)

## Context

notme has two registries and is missing a third:

| Registry | Answers | Where |
|---|---|---|
| **Principal** | Who may get a certificate at all? | ADR-021: invite today, `sigpol` bundle later |
| **Redirect allowlist** | Where may `/authorize` send a code? | `ALLOWED_REDIRECT_HOSTS`, `src/auth/redirect-uri.ts` (ADR-013) |
| **OAuth client** | Which *application* is asking, on whose behalf, with what redirect URIs? | **none** |

ADR-013 made the redirect allowlist double as the client registry, and was
explicit that this keeps the flow first-party by construction. That is why
`as-metadata.ts` withholds `authorization_endpoint` and
`code_challenge_methods_supported` (`FIRST_PARTY_WITHHELD_FIELDS`).

The cost is now concrete. A third-party MCP client, such as a claude.ai
custom connector pointed at cloister, gets this far and stops:

1. cloister answers 401 with `WWW-Authenticate: Bearer resource_metadata=…`
   (cloister ADR-0055);
2. cloister's RFC 9728 document names notme as the authorization server;
3. notme's RFC 8414 document advertises no `authorization_endpoint` and no
   way to register. **End of chain.**

cloister ADR-0055's 2026-07-29 amendment already named this as the chain's
last hop.

ADR-011 planned to fill the gap with an apps registry of `client_id` /
`client_secret` / `redirect_uri` rows. The MCP specification has since moved:
the 2026-07-28 revision prefers **Client ID Metadata Documents** (CIMD,
`draft-ietf-oauth-client-id-metadata-document`) and keeps Dynamic Client
Registration (DCR, RFC 7591) only as a fallback. MCP clients try CIMD first,
then DCR, then a manually entered client ID.

## Decision

### D1. CIMD is the client registry

A client's `client_id` is an `https` URL. To learn about the client, notme
fetches that URL and validates the JSON it returns. Nothing is stored that
the client's own origin does not publish.

This is notme's derive-never-receive invariant (`notme-6ad276`, ADR-016 rule
4) applied to clients. It is also ADR-020 working as intended: CIMD is a
standard, so adopting it composes rather than invents.

Validation, all fail-closed:

- `client_id`: `https`, has a path, no fragment, no userinfo, no dot
  segments, and is **not** under notme's own origin (D2 reserves that).
- The fetched document's `client_id` equals the URL it was fetched from,
  byte for byte.
- `redirect_uri` on `/authorize` exactly matches one of the document's
  `redirect_uris`. The document replaces `ALLOWED_REDIRECT_HOSTS` **for
  third-party clients only**. First-party flows keep the allowlist unchanged.
- No `client_secret`, ever. `token_endpoint_auth_method` is `none` (PKCE
  carries the binding, as in ADR-013) or `private_key_jwt` (D6).

**Fetching an attacker-chosen URL is the new attack surface**, so the fetch
is constrained:

- `https` only; no redirects followed; response size cap (8 KiB) and timeout
  (2 s); `application/json` only.
- Host must be a DNS name, not an IP literal.
- Cached by `Cache-Control`, clamped between 5 minutes and 24 hours, so a
  client cannot pin a stale document and an attacker cannot force a fetch
  per request.
- Rate-limited per `client_id` host, using the same limiter family as
  `/cert/*`.

### D2. DCR is accepted, and stored as a notme-hosted CIMD document

For clients that only speak DCR, `POST /register` accepts RFC 7591 metadata
and turns it into the D1 shape:

1. Normalize the metadata: drop unknown fields, reject any `client_secret`
   request, validate `redirect_uris` with D1's rules.
2. Encode as canonical CBOR (RFC 8949 §4.2, per ADR-010) and hash with
   SHA-256.
3. Store the document immutably under that hash and serve it, as JSON, at
   `${issuer}/clients/<base64url(hash)>`.
4. Return that URL as the `client_id`.

Consequences:

- **One code path.** Everything downstream sees a `client_id` URL and runs
  D1's validation. A DCR client is a CIMD client whose document notme hosts.
- **No pile of registrations.** Identical metadata hashes to the identical
  `client_id`, so a client that reconnects a thousand times is one entry.
  Documents are immutable, so changing metadata means a new `client_id`.
- **No mutable registry**, and so no RFC 7592 management endpoint.

### D3. The two kinds of client are different trust tiers, visibly

| Tier | `client_id` | What vouches for it |
|---|---|---|
| `cimd-verified` | URL on the client's own origin | DNS + TLS for that origin |
| `dcr-derived` | `${issuer}/clients/…` | Nothing; the client's own claims |

- The optional operator allowlist of trusted `client_id`s **never matches**
  the `/clients/` prefix, by construction rather than by configuration.
- The consent screen (D4) shows the **redirect host** and the tier.
  `client_name` and `logo_uri` are shown only as secondary, labelled
  "provided by the application", and never alone.
- The tier is a published fact: it travels with the issued token so a
  resource server can write policy about it (signet ADR-013's `client_tier`).

### D4. Consent, recorded as a grant

No third-party code is issued without the principal's consent to
*(client_id, scopes)*. Consent is recorded in the existing grant store and
read through `liveScopes`, so ADR-021's de-authorization applies:
revoking a client's grant takes effect on that client's next request.

Client registration grants **nothing** by itself. A client can obtain a
token only for a principal who is already registered under ADR-021 and who
consents. These are separate axes: ADR-021 decides who exists, this ADR
decides which applications they may let act for them.

### D5. Derive the withheld metadata; do not flip it

ADR-013 described publishing `authorization_endpoint` as "a one-line change".
`as-metadata.ts` has since said what it should be instead: **derived**,
emitted iff a client registry exists, so the document describes capability
that exists rather than capability someone asserted.

`buildAsMetadata` therefore emits `authorization_endpoint`,
`code_challenge_methods_supported: ["S256"]`, `response_types_supported:
["code"]` and `client_id_metadata_document_supported: true` only when D1 is
configured, and `registration_endpoint` only when D2 is also configured.
There is no boolean an operator can flip without having the registry.
`FIRST_PARTY_WITHHELD_FIELDS` becomes the list of fields *conditional* on
the registry rather than permanently forbidden; the contract test asserts
both states.

### D6. Key-bound clients

A CIMD document may carry `jwks_uri` (or, for D2, `jwks` in the registration
request, kept in the derived document). Such a client authenticates at
`/token` with `private_key_jwt` (RFC 7523) and receives tokens bound to its
DPoP key (`cnf.jkt`, which notme already mints).

This gives a `dcr-derived` client a stable, key-bound identity without
making its claims any more trustworthy: it is recognisably the *same*
client across reconnects, which is what the tier needs to mean anything.

`tls_client_auth` / `cnf.x5t#S256` stay out until notme has Cloudflare mTLS
bindings, for the reason `as-metadata.ts` records for removing the
attacker-controllable `X-Client-Cert` path.

## Rejected alternatives

- **ADR-011's apps registry** (`client_id` + `client_secret` rows). A
  mutable registry, a secret store, and a management surface, for a
  mechanism the MCP specification has stopped preferring.
- **DCR only.** Unverifiable claims stored as unbounded rows; the problem
  claude.ai's connector dialog warns about ("creates many client
  registrations on busy servers").
- **CIMD only, no DCR.** Viable, and the recommended *first* step (see
  order below). D2 exists so DCR-only clients are not locked out, at a cost
  of one endpoint and one immutable store.
- **Publishing the fields behind a flag.** Rejected by D5, for the reason
  `as-metadata.ts` already gives.

## Consequences

- A standard MCP client can complete the discovery chain cloister ADR-0055
  started, ending at a current mechanism rather than a deprecated one.
- notme makes outbound fetches to client-chosen URLs. D1's limits are part of
  the decision, not an implementation detail.
- `notme-0078a9` / ADR-011 keep consent UX, introspection and revocation;
  their client-registry section is superseded by this ADR.

## Implementation order

1. D1 with an operator allowlist of `client_id`s (default empty = no third
   parties), D4 consent, D5 derived metadata. That alone makes claude.ai's
   "Use Claude's published identity" option work.
2. Open D1 beyond the allowlist, still labelled by tier.
3. D2 (`/register`), only if a DCR-only client needs it.
4. D6 `private_key_jwt`.

## Open questions

1. Does the issued token carry `client_tier` as a claim, or does the
   resource server derive it from `client_id`'s prefix? Deriving needs no new
   claim but couples resource servers to notme's URL layout.
2. Where do D2's immutable documents live: the existing Durable Object, or a
   content-addressed store shared with ley-line? ADR-020 argues for the
   latter; nothing yet requires it.
