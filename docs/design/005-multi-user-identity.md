# 005: Multi-User Identity Architecture

**Status:** Proposed
**Date:** 2026-03-28
**Bead:** notme-7c7f83
**Relates to:** ADR-004 (bridge certs), ADR-0002 (identity & secrets architecture)

## Context

auth.notme.bot is the identity authority for the signet protocol. It currently supports
one admin user registered via passkey with a bootstrap code. A second user (the admin's
wife) attempted to use the system from her phone and could not onboard: registration
requires an admin session (circular for new users), and sign-in requires an existing
passkey (which she does not have on her device).

This is not a UX bug -- it is a structural problem. The system was designed around a
single-admin model and multi-user was not considered at the architectural level.

This document designs the correct multi-user model from first principles.

## Problem Analysis

### Five structural issues in the current implementation

**Issue 1: Conflation of identity, credential, and capability.**
The system has `passkey_users` (identity), `passkey_credentials` (credential), and
`connections` (linked identities), but they are wired incorrectly. The `connections`
table keys on `credential_id` but the route handler passes `session.userId` as the
credential ID. A userId is a random UUID; a credential_id is a WebAuthn hardware
identifier. These are categorically different things. If a user authenticates with a
different passkey, their connections become unreachable.

**Issue 2: `is_admin` contradicts the stated design philosophy.**
The ADR and design documents state "no persistent admin role -- only ephemeral certs
with scoped capabilities." But `passkey_users.is_admin` is a persistent boolean set at
registration time and carried in every session cookie for 24 hours. The session model
(role-based) and the cert model (capability-based) are contradictory.

**Issue 3: Circular registration dependency.**
New user registration requires an admin session cookie. A new user has no session. The
bootstrap code is single-use and designed for the deployer only. There is no mechanism
for user N to onboard.

**Issue 4: No stable identity across credential rotation.**
If a user loses their phone and registers a new passkey, they get a new credential_id.
The `connections` table has no way to link old and new credentials to the same identity.
The random UUID in `passkey_users` is the closest thing to a stable identifier, but it
is tied to a single registration event.

**Issue 5: OIDC is subordinate to passkeys.**
Connections can only be created from an active passkey session. OIDC cannot be used as
a standalone authentication method. For self-hosters whose users lack passkey support
(old Android, corporate browsers, managed devices), the system is unusable.

## Design Constraints

1. No persistent admin role -- capabilities flow through cert scopes
2. OIDC as a first-class login method, not subordinate to passkeys
3. No stored OAuth client secrets for OIDC verification (the whole point)
4. Self-hosters must be able to run the system without passkey hardware
5. Multi-user from day one in the data model
6. The deployer (user 0) is privileged only during bootstrap, not forever

## Decision

### The Principal Model

Introduce a **principal** as the stable identity entity, independent of any credential.

```
principal
  |
  +-- credentials (passkeys, one-to-many)
  |
  +-- federated_identities (OIDC subjects, one-to-many)
  |
  +-- capabilities (what certs this principal can request)
```

A principal is created when:
- The deployer registers (bootstrap flow)
- An existing principal invites a new user (invite flow)
- A user authenticates via OIDC for the first time (open registration, if enabled)

A principal is identified by a server-generated UUID that is stable across credential
changes, device migrations, and identity provider switches.

### Data Model

```sql
-- The stable identity. Survives credential rotation.
CREATE TABLE principals (
  principal_id   TEXT PRIMARY KEY,           -- UUID, server-generated
  display_name   TEXT,
  created_at     TEXT NOT NULL DEFAULT (datetime('now')),
  created_by     TEXT,                       -- principal_id of inviter, NULL for bootstrap
  status         TEXT NOT NULL DEFAULT 'active'  -- active | suspended | revoked
);

-- WebAuthn credentials. A principal may have zero or more.
CREATE TABLE passkey_credentials (
  credential_id  TEXT PRIMARY KEY,           -- WebAuthn credential ID
  principal_id   TEXT NOT NULL REFERENCES principals(principal_id),
  public_key     TEXT NOT NULL,
  counter        INTEGER NOT NULL DEFAULT 0,
  transports     TEXT,                       -- JSON array
  created_at     TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at   TEXT
);

-- OIDC/external identities. A principal may have zero or more.
-- An OIDC identity can also be the PRIMARY login method (no passkey required).
CREATE TABLE federated_identities (
  id             TEXT PRIMARY KEY,           -- UUID
  principal_id   TEXT NOT NULL REFERENCES principals(principal_id),
  provider       TEXT NOT NULL,              -- "oidc:https://token.actions.githubusercontent.com", etc.
  provider_sub   TEXT NOT NULL,              -- OIDC sub claim
  provider_email TEXT,
  connected_at   TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at   TEXT,
  UNIQUE(provider, provider_sub)             -- one principal per provider identity
);

-- Capability grants. What cert scopes a principal may request.
-- Replaces the is_admin boolean.
CREATE TABLE capability_grants (
  id             TEXT PRIMARY KEY,           -- UUID
  principal_id   TEXT NOT NULL REFERENCES principals(principal_id),
  scope          TEXT NOT NULL,              -- CertScope value: "bridgeCert", "authorityManage", "certMint"
  granted_by     TEXT REFERENCES principals(principal_id),
  granted_at     TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at     TEXT,                       -- NULL = permanent until revoked
  revoked_at     TEXT,
  UNIQUE(principal_id, scope)
);

-- Invite tokens. Time-limited, single-use.
CREATE TABLE invites (
  token          TEXT PRIMARY KEY,           -- cryptographically random, 128-bit
  created_by     TEXT NOT NULL REFERENCES principals(principal_id),
  scopes         TEXT NOT NULL,              -- JSON array of CertScope values to grant on redemption
  redeemed_by    TEXT REFERENCES principals(principal_id),
  created_at     TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at     TEXT NOT NULL,
  redeemed_at    TEXT
);

-- Challenge storage for WebAuthn flows.
CREATE TABLE challenges (
  challenge      TEXT PRIMARY KEY,
  principal_id   TEXT,                       -- NULL for authentication (unknown user)
  type           TEXT NOT NULL,              -- 'registration' | 'authentication'
  created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
```

### What disappears

- `passkey_users` table -- replaced by `principals`
- `is_admin` column -- replaced by `capability_grants`
- `connections` table -- replaced by `federated_identities`
- The `isAdmin` field in session cookies -- replaced by a list of active scopes

### Session Payload

```typescript
interface SessionPayload {
  principalId: string;        // stable UUID
  scopes: string[];           // active capability scopes from capability_grants
  authMethod: string;         // "passkey" | "oidc:<issuer>" | "invite"
  exp: number;                // Unix timestamp
}
```

The session no longer carries a boolean role. It carries the intersection of
(requested scopes) and (granted capabilities). If a capability grant is revoked,
new sessions will not include that scope. Existing sessions remain valid until
expiry (max 24 hours), which is acceptable for the TTLs involved.

For operations that require real-time authorization checks (e.g., `authorityManage`
scope), the route handler re-validates against `capability_grants` at request time
rather than trusting the session alone.

### Bridge Cert Subject

The bridge cert subject identifies the holder. The correct content:

```
Subject CN: <principal_id>
Extensions:
  1.3.6.1.4.1.99999.1.1: OIDCSubject (if authenticated via OIDC)
  1.3.6.1.4.1.99999.1.7: Epoch
  1.3.6.1.4.1.99999.1.8: AuthMethod ("passkey" | "oidc:<issuer>")
  1.3.6.1.4.1.99999.1.9: PrincipalId (same as CN, in machine-readable extension)
  1.3.6.1.4.1.99999.1.10: Scopes (JSON array of granted CertScope values)
```

The CN is the principal_id (stable UUID). This survives credential rotation,
device migration, and identity provider changes. Relying parties that need to
track "which human" across sessions use the principal_id. Relying parties that
need to know "how did they prove it" check the AuthMethod extension.

## Flows

### Flow 1: Bootstrap (User 0 -- Deployer)

This flow is unchanged. It works correctly.

```
1. Deployer visits auth.example.com/login
2. System detects zero principals -> shows "bootstrap" UI
3. Deployer clicks "Register" -> system logs bootstrap code to wrangler tail
4. Deployer enters bootstrap code
5. System creates principal with all capability scopes
6. WebAuthn registration ceremony begins
7. Passkey credential stored, linked to principal
8. Session cookie issued with full scopes
```

The deployer's principal gets all three capability grants:
`bridgeCert`, `authorityManage`, `certMint`.

### Flow 2: Invite (User N -- Known User)

```
1. Existing user (with authorityManage scope) creates an invite:
   POST /invites { scopes: ["bridgeCert"], ttl: 3600 }
   -> returns { token: "a1b2c3d4...", url: "https://auth.example.com/join?t=a1b2c3d4" }

2. Inviter shares the URL (text message, email, QR code -- out of band)

3. New user opens the URL
4. System validates invite token (not expired, not redeemed)
5. System creates a new principal with the scopes specified in the invite
6. User is presented with authentication options:
   a. Register a passkey (preferred)
   b. Sign in with OIDC (if any provider tokens are available)
7. Chosen credential is linked to the new principal
8. Invite marked as redeemed
9. Session cookie issued
```

The invite token is the authorization to create an account. It replaces the
"admin must be present" requirement. The invite is time-limited (default 1 hour),
single-use, and scoped (the inviter chooses what capabilities the invitee gets).

**Security properties:**
- The invite URL is a bearer token -- anyone who has it can use it
- Time-limited (configurable, default 1 hour)
- Single-use (redeemed_at is set on first use)
- Scoped (invitee cannot escalate beyond what the invite grants)
- Auditable (created_by, redeemed_by tracked)

### Flow 3: OIDC Login (Returning User)

For users who have linked an OIDC identity (via the connections/federated_identities
mechanism), OIDC can be used as a standalone login method.

```
1. User presents an OIDC token (JWT) to POST /auth/oidc/login
   { proof: { type: "oidc", token: "<jwt>" } }

2. System verifies the JWT (generic verification via verify-proof.ts):
   - Decode header, fetch JWKS from issuer
   - Verify signature
   - Check exp, iss, sub claims

3. System looks up federated_identities WHERE provider = iss AND provider_sub = sub

4a. If found: create session for the linked principal
4b. If not found AND open registration is enabled: create new principal + link identity
4c. If not found AND open registration is disabled: reject with 403
```

**Critical constraint: no OAuth redirect flow.**

This system cannot implement "Sign in with Google" or "Sign in with GitHub" in the
browser redirect sense, because that requires a registered OAuth app with a
client_id/client_secret. The whole point of this system is no stored secrets.

What it CAN do:

- **Verify tokens obtained elsewhere.** A CLI tool (`signet auth login`) can
  implement device authorization flow or use a locally-obtained token.
- **Verify GHA OIDC tokens.** GitHub Actions workflows get tokens for free.
- **Verify CF Access JWTs.** Cloudflare Access issues tokens without client secrets.
- **Verify tokens from any OIDC issuer with a public JWKS endpoint.**

For browser-based OIDC login, the deployer has two options:

1. **Put Cloudflare Access in front of auth.notme.bot.** CF Access handles the
   OAuth redirect flow. The Worker receives a CF Access JWT (`Cf-Access-Jwt-Assertion`
   header) which it verifies against CF's public JWKS. No client secret needed in the
   Worker -- the Access policy configuration is in the CF dashboard.

2. **Register an OAuth app and store the client_id/secret.** This is a product
   decision for deployers who want browser-native "Sign in with GitHub." The
   client_id/secret goes in CF Secrets Store (per ADR-0002). This is optional,
   not required by the protocol.

### Flow 4: Passkey Login (Returning User)

Unchanged from current implementation, but the session now contains the principal_id
and scopes instead of userId and isAdmin.

```
1. User clicks "Sign in with passkey"
2. GET /auth/passkey/login/options -> WebAuthn challenge
3. User authenticates with Touch ID / Face ID / security key
4. POST /auth/passkey/login/verify { response: <webauthn_response> }
5. System looks up credential -> finds principal_id
6. System loads capability_grants for principal
7. Session cookie issued with { principalId, scopes, authMethod: "passkey" }
```

### Flow 5: Add Credential to Existing Principal

A logged-in user can add more credentials (passkeys on other devices, OIDC identities):

```
-- Add passkey:
POST /auth/passkey/register/options  (requires active session)
POST /auth/passkey/register/verify   (links new credential to session.principalId)

-- Add OIDC identity:
POST /auth/federated/link { proof: { type: "oidc", token: "<jwt>" } }
(requires active session, links identity to session.principalId)
```

### Flow 6: Self-Hoster Without Passkeys

A self-hoster whose users cannot use passkeys (corporate browsers, old Android):

```
1. Deployer bootstraps with bootstrap code + passkey (they need at least one passkey
   to establish the CA -- this is the root of trust)
2. Deployer puts CF Access in front of the instance (or registers an OAuth app)
3. Deployer creates invites for their users
4. Users redeem invites and authenticate via OIDC
5. Users never need a passkey -- OIDC is their primary authentication method
6. Bridge certs are issued with authMethod: "oidc:<issuer>"

Alternative: if even the deployer cannot use a passkey (extremely constrained),
the bootstrap code alone creates the principal and the first session. The deployer
then links an OIDC identity immediately. This is less secure but functional.
```

## Capability Model

### Replacing is_admin

The `is_admin` boolean is replaced by capability grants:

| Scope | Meaning | Who gets it |
|-------|---------|-------------|
| `bridgeCert` | Can obtain bridge certs (sign commits, auth to MCP) | Everyone |
| `authorityManage` | Can rotate epochs, create invites, manage principals | Deployer + designated admins |
| `certMint` | Can mint certs for others (delegated authority) | Automated systems, CI |

Checking authorization:

```typescript
// Before (role-based):
if (!session.isAdmin) return jsonErr("admin required", 403);

// After (capability-based):
if (!session.scopes.includes("authorityManage")) {
  return jsonErr("authorityManage capability required", 403);
}
```

### Capability Grant Lifecycle

- Created at invite redemption (scopes come from the invite)
- Created by a principal with `authorityManage` scope (grant to existing principal)
- Never auto-escalated (a principal cannot grant scopes they do not have)
- Revocable (set `revoked_at`, principal's next session will not include the scope)
- Optionally time-limited (`expires_at`)

### Constraint: no self-escalation

A principal with `authorityManage` can grant `bridgeCert` and `authorityManage` to
others, but cannot grant `certMint` unless they also hold `certMint`. The granting
function checks:

```typescript
function canGrant(grantor: string[], scope: string): boolean {
  // Must hold authorityManage AND the scope being granted
  return grantor.includes("authorityManage") && grantor.includes(scope);
}
```

The deployer (bootstrap principal) gets all scopes. They can delegate everything.
But delegation is always bounded by the grantor's own capabilities.

## Migration Path

### Phase 1: Schema migration (non-breaking)

1. Create `principals` table
2. Migrate existing `passkey_users` rows to `principals` (user_id -> principal_id)
3. Add `principal_id` column to `passkey_credentials` (populate from user_id join)
4. Create `federated_identities` from existing `connections` data
5. Create `capability_grants` from `is_admin` flag:
   - is_admin=1 -> grants for all three scopes
   - is_admin=0 -> grant for `bridgeCert` only
6. Create `invites` and `challenges` tables

### Phase 2: Code migration

1. Update session creation to use `SessionPayload` with `principalId` + `scopes`
2. Update route handlers to check scopes instead of isAdmin
3. Add `/invites` route (create, list, revoke)
4. Add `/auth/oidc/login` route
5. Update `/connections` to `/auth/federated/link`
6. Update bridge cert minting to use principal_id as CN

### Phase 3: Schema cleanup

1. Drop `passkey_users` table
2. Drop `connections` table
3. Drop `is_admin` references
4. Update identity.capnp to add `OIDCProof` to the Proof union (generic, not GHA-specific)

## Open Questions

1. **Open registration:** Should a new OIDC identity automatically create a principal,
   or require an invite? Default: require invite (more secure). Configurable via
   `OPEN_REGISTRATION=true` env var for self-hosters who want it.

2. **Principal merge:** If a user registers with a passkey and later signs in with
   OIDC, and these map to different principals, should they be mergeable? This is
   complex (which principal's capabilities win?) and probably deferred to a future
   design.

3. **Invite delivery:** The system generates invite URLs but does not send them.
   Delivery is out-of-band (text message, email, QR code). This is intentional --
   the system should not need an email sending capability.

4. **Session downgrade:** If a capability grant is revoked mid-session, should the
   session be invalidated immediately? Current design: no, sessions are valid until
   expiry. For `authorityManage` operations, the handler re-checks grants at request
   time. This is the pragmatic choice -- immediate invalidation would require a
   session revocation list, adding complexity.

5. **Passkey-less bootstrap:** Should the bootstrap flow work without a passkey at
   all? The deployer enters the bootstrap code and immediately links an OIDC
   identity instead. This weakens the root-of-trust story (OIDC issuers can be
   compromised) but enables fully passkey-free deployments. Recommendation: support
   it but warn in the UI.

## Security Analysis

### Threat: Invite token leak

An invite URL is a bearer token. If leaked, anyone can create an account with the
granted scopes. Mitigations:
- Short TTL (default 1 hour, configurable)
- Single-use
- Scoped (invitee gets only what the invite specifies)
- Auditable (created_by is recorded)
- Revocable (delete the invite before it is redeemed)

### Threat: OIDC issuer compromise

If an OIDC issuer is compromised, an attacker could forge tokens that resolve to
existing principals' federated identities. Mitigations:
- Passkey authentication is unaffected (hardware-bound)
- OIDC-only principals are at risk -- this is inherent to OIDC federation
- Deployers who require higher assurance should mandate passkeys for sensitive scopes
- The `authMethod` extension in bridge certs allows relying parties to distinguish
  passkey-authenticated certs from OIDC-authenticated certs

### Threat: Capability escalation

A principal with `bridgeCert` attempts to obtain `authorityManage`. Mitigations:
- Capability grants are stored server-side and checked at session creation
- The `canGrant` function prevents self-escalation
- Invite scopes are bounded by the inviter's own capabilities

### Threat: Stale session after capability revocation

A principal's `authorityManage` grant is revoked, but their session still carries
the scope. Mitigations:
- Session TTL is 24 hours maximum
- `authorityManage` operations re-check grants at request time (not session-only)
- For higher assurance: reduce session TTL or implement a session revocation list

## Consequences

### Positive
- Multi-user works from day one without bolting on
- OIDC is a first-class authentication method
- Self-hosters without passkey hardware can operate
- Capability model aligns with bridge cert design (no contradiction)
- Principal identity is stable across credential rotation
- Invite flow breaks the circular dependency cleanly

### Negative
- Schema migration required (one-time, automatable)
- More tables and joins than the current simple model
- Invite management adds UI surface area
- OIDC-only principals have weaker security properties than passkey principals
- Open registration (if enabled) could allow unwanted account creation

---

*Enabling multi-user identity without sacrificing the self-sovereign model*
