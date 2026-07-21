# 011: notme as external OAuth 2.0 / OIDC provider

**Status:** Proposed
**Date:** 2026-06-25
**Bead:** (TBD — bd embeddeddolt format mismatch in `.beads/`; file when bd state is reconciled, or track via cloister-side cross-link)
**Relates to:** notme `/oauth/token` (client_credentials) already shipped via cloister.capnp identity-bridge tenant; cloister ADR-0007 (Interlace substrate, the orthogonal internal trust layer); cloister ADR-0018 (notme co-location)
**Companion reading:** [Cloudflare "OAuth for All" (2026-06)](https://blog.cloudflare.com/oauth-for-all/)

## Context

Cloudflare's "OAuth for All" announcement opened OAuth delegation to any Worker — every developer on CF can now ship an OAuth-server surface. That raises a substrate-trust question for ART: should notme expose a Cloudflare-compatible OAuth dance so third-party apps that already speak OAuth (and may be deployed on CF) can use notme as their identity provider, the way they'd OAuth into Google / GitHub / Atlassian today?

Today notme's identity-bridge surface (per `cloister.capnp`, registered under the `wellKnownIdentityBridge` route kind) ships:

> **CORRECTION (2026-07-21).** As originally written, four of the five rows
> below were wrong — they described intent, not shipped code. Re-verified
> against `worker/worker.ts` routes *and* static assets. Do not re-assert a
> ✓ here without grepping the route table first; a design doc claiming a
> surface exists is how the wrong thing gets built on top of it.

| Endpoint | Purpose | Shipped | Evidence |
|---|---|---|---|
| `GET /.well-known/jwks.json` | JWK Set (Ed25519 / EdDSA) | ✓ | `worker.ts` jwks handler |
| `GET /.well-known/signet-authority.json` | Authority discovery (signet-native) | ✓ | `worker.ts` |
| `GET /.well-known/oauth-authorization-server` | OAuth 2.0 AS metadata (RFC 8414) | ✓ | shipped 2026-07-21 |
| `GET /.well-known/openid-configuration` | Same RFC 8414 body, for libraries that probe only this path. **Not an OIDC OP** — no `id_token`, no `scope=openid` | ✓ | shipped 2026-07-21 |
| `POST /token` | DPoP-bound `at+jwt` mint (RFC 9449). Note: path is `/token`, **not** `/oauth/token` | ✓ | `worker.ts` token handler |
| `GET /authorize` | Renders an HTML page; issues **no** authorization code | ✓ | `worker.ts` |
| `GET /.well-known/webfinger` | JRD `?resource=acct:cluster@host` | ✗ | no route, no static asset |
| `GET /.well-known/nostr.json` | NIP-05 names + relays | ✗ | no route, no static asset |
| `POST /oauth/token` | `client_credentials` grant | ✗ | path does not exist |

What's missing for a real third-party-app OAuth provider:

| Endpoint / capability | Spec | Missing |
|---|---|---|
| `GET /oauth/authorize` | RFC 6749 §4.1 — authorization-code flow entrypoint | ✗ |
| Consent UI | The user-facing "Allow App X to access ...your beads?" page | ✗ |
| Developer-app registration surface | `client_id` + `client_secret` + `redirect_uri` allowlist | ✗ |
| Authorization-code → token exchange on `/oauth/token` | RFC 6749 §4.1.3 | ✗ |
| PKCE for public clients | RFC 7636 | ✗ |
| Token introspection | RFC 7662 (`/oauth/introspect`) | ✗ (currently using JWT-only verification) |
| Token revocation | RFC 7009 (`/oauth/revoke`) | ✗ |
| Refresh-token grant | RFC 6749 §6 | ✗ |

## Why this is worth ratifying

The substrate today works fine with Interlace-only authn for internal trust. The OAuth surface unlocks **external developer adoption** — apps built outside the ART substrate that want to authn against ART users without learning the Interlace cert flow. Examples:

- A third-party IDE plugin that talks to a cluster's MCP surface on behalf of a developer
- A CI/CD tool that wants to read+write beads in a cluster from its own pipeline
- A research dashboard that aggregates data across multiple ART clusters with explicit consent

Cloudflare's announcement makes this strictly easier — they ship the Hydra-based primitives that let any Worker BE an OAuth server. notme either (a) wraps Hydra, or (b) implements the relevant slice of the OAuth spec directly inside the existing notme Worker.

## Architectural decision matrix

### Option A — Wrap Ory Hydra as a sidecar

- **Pros**: battle-tested OAuth 2.0 + OIDC engine (the one CF runs); ~250k LOC of Go already audited; supports every OAuth flow ART might ever want
- **Cons**: new substrate dep (Go binary + Postgres / SQL backend); duplicates trust-root concerns Hydra already enforces with its own client-credentials state; large attack surface to host
- **Footprint**: a new bundle in `cluster.toml` for the Hydra sidecar + a new `[[wires]]` entry from cloister-router; notme becomes the "login provider" + "consent provider" Hydra calls back to

### Option B — Implement the spec slice in-stack (TypeScript inside notme's existing Worker)

- **Pros**: no new substrate dep; reuses notme's existing Ed25519 master signing for JWT issuance; consent UI is a small static page on the same Worker; trust root stays inside the ADR-0007 Interlace pipeline
- **Cons**: implementation work (~2-3k LOC of careful TypeScript: auth-code state machine + PKCE + token issuance + introspection + revocation + JWKS publishing); ART takes responsibility for spec compliance
- **Footprint**: extends the `wellKnownIdentityBridge` route to also handle `/oauth/authorize`, `/oauth/consent`, `/oauth/introspect`, `/oauth/revoke`; adds an apps-registry SQLite table to notme's DO

### Recommendation

**Option B**. Substrate principle: notme is already the trust root; introducing a second OAuth engine alongside it would split the trust model and create a new "who's the source of truth for sessions" question. The spec slice notme actually needs (auth-code + token + introspection + PKCE + JWKS) is well-bounded; the rest of OAuth 2.0 (resource owner password credentials grant, implicit flow, etc.) is **explicitly out of scope** (RFC 6749 itself deprecates them).

JWT-formatted bearer tokens (Ed25519-signed by notme's master, the same key already published at `/.well-known/jwks.json`) let resource servers verify offline without an introspection round-trip — same posture as ART's existing internal trust layer.

## Scope shape

```
notme/
├── docs/design/011-external-oauth-provider.md   ← this doc
├── worker/src/oauth/
│   ├── authorize.ts          // GET /oauth/authorize handler
│   ├── consent.ts            // POST /oauth/consent handler + static HTML
│   ├── token.ts              // POST /oauth/token (extends existing client_credentials with auth-code grant)
│   ├── introspect.ts         // POST /oauth/introspect (RFC 7662)
│   ├── revoke.ts             // POST /oauth/revoke (RFC 7009)
│   ├── apps-registry.ts      // CRUD over client_id / client_secret / redirect_uris / scopes
│   ├── auth-code-state.ts    // DO-backed short-lived code → state mapping
│   └── pkce.ts               // RFC 7636 verifier/challenge
└── worker/test/oauth/
    └── ...                   // happy-path + adversarial paths
```

Cloister-side: extends `cloister.capnp` `identity-bridge` route to declare the new paths under the same `wellKnownIdentityBridge` route kind (no new tenant; same trust boundary).

## Scope question worth deciding now

**Scope translation from Interlace to OAuth.** Interlace has rich per-call scope semantics (the `scope:<value>` in the lease). OAuth has loose space-separated scope strings. Cleanest mapping: a developer-app's allowed scopes are the union of Interlace scope strings it's whitelisted for; the token carries them as the OAuth `scope` claim. Resource servers verifying the token map back via the same string match. **Decide before implementation:** are OAuth scopes a 1:1 mirror of Interlace scopes, or a curated subset (e.g., only `read` / `write` / `admin` instead of fine-grained `bead.create` / `bead.update`)?

The 1:1 mirror gives developers full flexibility but exposes the substrate's internal scope vocabulary. The curated subset is friendlier for external developers but requires maintaining a mapping table.

Recommend: **1:1 mirror initially**; add a curation layer when external developers ask for one.

## Out of scope

- Replacing Interlace cert-based authn for internal substrate trust. Interlace stays the substrate-tier mechanism.
- SSO / SAML / corporate-IdP federation. Different problem; if needed, an Auth0-style upstream IdP can land later as a separate ADR.
- Centralized hosting (à la Auth0 / Clerk). notme stays self-hosted by the cluster operator.
- Refresh-token rotation with leaked-token detection (RFC 6749 §10.4). Land in a follow-up.

## Open questions

1. **Consent UI hosting**: same Worker, or a static page on R2 + a Worker-side state-binding callback? (Recommend: same Worker — small page, low complexity, no new substrate dep.)
2. **Apps-registry storage**: a new DO class, or extend notme's existing DO? (Recommend: extend existing DO — apps registry is small, append-mostly.)
3. **Token-lifetime defaults**: align with CF's "multiple hours" or with Interlace's short-lease posture? (Recommend: aligned with Interlace — short access tokens + refresh-token rotation; the substrate principle is "short leases, frequent re-issuance.")
4. **Compatibility with notme's existing `client_credentials` grant**: keep both grants on the same `/oauth/token` endpoint (RFC 6749-compliant — `grant_type` parameter disambiguates), or split? (Recommend: keep on one endpoint per spec.)

## Why P2

Product-direction question, not a substrate gap. ART works today with Interlace-only authn. The OAuth surface unlocks external developer adoption — it's an ecosystem play, not a reliability fix. Land after the substrate-trust layer is stable but before the first external developer onboarding push.
