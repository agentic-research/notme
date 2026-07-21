# 012: Sender-constrained OIDC — id_tokens that prove possession, not presence

**Status:** Proposed (2026-07-21)
**Date:** 2026-07-21
**Bead:** file when rsry reaches notme; cross-linked from the discovery-work session.
**Relates to:** [011-external-oauth-provider.md](011-external-oauth-provider.md) (the OAuth-surface predecessor, which never addressed the id_token-is-a-bearer problem); notme #26/#27/#28 (RFC 8414 AS metadata, shipped, deliberately *not* an OP); README value prop ("possession → proof").
**Standards (verified against primary sources this session unless labeled):**
- RFC 7800 — `cnf` (confirmation) claim, general to any JWT. Members: `jwk`, `jwe`, `kid`, `jku`.
- RFC 9449 — DPoP + the `jkt` confirmation member. **`jkt` is scoped to access tokens** ("the DPoP public key to which the *access token* is bound"); DPoP is *not* defined for id_tokens.
- OpenID Connect Self-Issued OP v2 (SIOPv2) — self-issued id_token: `iss == sub`, `sub` = base64url(JWK thumbprint) with `sub_jwk`, or a DID; proof-of-possession by construction.
- FAPI 2.0 sender-constraining requirement — **UNVERIFIED** (spec page redirected); treated as motivational only, not cited as normative.

## Context

notme's thesis (README): *possession = identity* is the root vulnerability;
bearer assets are the disease; the cure is proof-of-possession. The shipped
access-token path honours this — `at+jwt` carries `cnf.jkt` (RFC 9449), so a
stolen token is inert without the DPoP private key.

An OpenID Connect **`id_token` is a bearer assertion**: a JWT the OP signs to
say "this subject authenticated," which any relying party (RP) accepts on
sight. That is precisely the asset class notme exists to eliminate. This is
why #26/#27/#28 deliberately made notme an OAuth *authorization server* and
**not** an OpenID *provider*: `scopes_supported` has no `openid`,
`response_types_supported` is `[]`, and `FORBIDDEN_METADATA_FIELDS`
(`worker/src/as-metadata.ts`) pins the omissions test-guarded:
`subject_types_supported`, `authorization_endpoint`,
`code_challenge_methods_supported`, `algorithms_supported`.

One nuance the naive reading gets wrong (an earlier draft of this doc got it
wrong too): `id_token_signing_alg_values_supported` is **already published**
— `["EdDSA"]`, deployer-overridable via `ID_TOKEN_SIGNING_ALGS` — *not*
forbidden. It's there as a go-oidc interop fix (absent, clients default to
RS256-only and reject every EdDSA token), documented in `as-metadata.ts` as a
correctness requirement, not an OP capability claim. The "not an OP" signals
are the scope/response-type absences, never the alg list.

So the question is not "add id_tokens." It is: **how does notme give an RP a
standard, discoverable, verifiable identity assertion that still cannot be
stolen by copying it?**

## The core tension, precisely

A useful OIDC identity assertion must be (a) *standard* — an RP verifies it
with an off-the-shelf library against a discovered JWKS — and (b)
*non-bearer* — a captured copy is useless. Standard OIDC gives (a) and breaks
(b). Pure PoP protocols give (b) but aren't OIDC. The design space is how to
get both, and the security model shifts because notme starts vending identity
assertions to **third-party RPs** — a wider trust surface than today's
first-party cert/token consumers.

## Standards reality (what actually binds)

- Sender-constraining an id_token via `cnf` **is** spec-legitimate: RFC 7800
  defines `cnf` for any JWT, not just access tokens.
- But **`cnf.jkt` is the wrong member to reuse** — RFC 9449 scopes `jkt` to
  access tokens. The standards-clean binding for an id_token is `cnf.jwk`
  (embed the holder public key) or `cnf.kid`. Reusing `jkt` on an id_token is
  a defensible extension (same key, same thumbprint) but MUST be documented as
  non-standard, never presented as "DPoP."
- SIOPv2 already defines a holder-key-bound id_token where `sub` is the key
  thumbprint and PoP is structural. notme's bridge cert already computes a
  dispatch-key identity — the same shape.

## Options

### A — notme as OP, id_token sender-constrained via `cnf`

Implement the standard authorization-code flow (currently absent: `/authorize`
renders HTML, issues no code; no PKCE) and mint an ephemeral, nonce-bound
`id_token` carrying `cnf.jwk` (the holder's dispatch key). RPs:

- **naive RP** verifies signature + `iss`/`aud`/`nonce`/`exp` → standard OIDC.
- **PoP-aware RP** additionally checks `cnf` and demands a proof of the key.

*Pro:* one Ed25519 root signs it; RP trusts notme; incremental over #26–28.
*Con:* **graceful degradation is also a downgrade attack** — an RP that
ignores `cnf` accepts a stolen id_token as a bearer. The PoP property is only
as strong as the *weakest* RP. This is the load-bearing risk (see below).

### B — SIOPv2 self-issued (holder key IS the issuer)

The dispatch's own key issues and signs the id_token; `iss == sub == `
thumbprint(dispatch key); the RP verifies the signature *against the key named
in `sub`*, so PoP is by construction — there is no separable bearer, ever.
notme's bridge cert is already this identity.

*Pro:* the only option where PoP cannot be downgraded by a lazy RP.
*Con:* pure SIOP has no third-party issuer to anchor trust — the RP trusts the
holder's self-assertion unless something *attests* the key. That "something"
is exactly notme.

### C — notme-attested, holder-key-bound id_token (recommended)

Synthesis. notme signs the id_token (so RPs discover + trust the notme root,
verifying against the published JWKS), **and** `sub`/`cnf` binds it to the
dispatch key (SIOP-style holder binding — `sub` = dispatch-key thumbprint,
`cnf.jwk` = dispatch key). The RP gets a third-party-anchored assertion whose
subject *is* a key the presenter must prove. This is the notme shape: notme
vouches for *which key*, the holder proves *possession of that key*.

*Pro:* third-party trust anchor **and** structural holder-binding; maps
directly onto the bridge-cert / APAS "dispatch = unit of cryptographic
identity" model.
*Con:* still exposes the downgrade surface of A for RPs that verify signature
but ignore `sub`/`cnf` binding. Mitigation must be explicit (below).

## The security-model shift (this is new territory)

Publishing id_tokens changes notme from "issues credentials to first-party
consumers" to "asserts identity to arbitrary RPs." What must be modelled:

1. **The downgrade surface — verdict (fable, 2026-07-21): contained, not
   eliminated; C is not a net regression, under five issuance-side invariants.**
   First, sharpen the threat. The "naive RP" is in practice a *library-using*
   RP: every off-the-shelf OIDC library validates `iss`/`aud`/`exp` (and
   `nonce` if sent) — what none of them validate is `cnf`. So the realistic
   floor is not "accepts any signed blob"; it is "accepts a valid, in-window,
   correctly-audienced token without proof of the key." Second, the delivery
   channel matters more than the doc's options A–C framing admitted: in
   code-flow-only issuance the RP receives its id_token **exclusively from the
   token endpoint over TLS** — there is no front-channel token an attacker can
   steal from a URL fragment or inject into a victim session. The classic
   stolen-id_token attack requires a front channel (implicit/hybrid/form_post)
   that notme simply must not offer. What remains is (a) exfil from the RP's
   own logs/memory — a 5-min, single-`aud` asset, replayable only against an
   RP that skips `nonce`, and (b) the ecosystem anti-pattern of accepting
   id_tokens as API bearer credentials. Class (b) is the one place where "a
   signature-verifiable assertion from a trusted root" is itself the asset —
   but that class is not enlarged by `cnf`'s presence or absence, and it is
   bounded by the claims: a single-valued `aud` + 5-min `exp` makes the
   assertion a five-minute statement to one named consumer, not a portable
   credential. The "weakest RP defines the security" argument, taken
   seriously, indicts every OP that has ever existed; the honest form of the
   question is whether notme *widens* the attacker's capability class versus
   standard OIDC — it strictly narrows it — and whether it widens it versus
   not shipping — only by the root now signing statements consumable outside
   the first-party boundary, which is inherent to offering identity at all and
   is a key-blast-radius question (invariant v), not a downgrade question.
   The invariants, all enforceable by notme with zero reliance on RP diligence:
   (i) **every id_token is `cnf.jwk`-bound; no unbound variant exists** (see
   decision 1 below); (ii) **code flow only, back-channel delivery only** —
   `response_types_supported` gains `["code"]` and nothing else, ever; no
   `id_token`, no hybrid, no form_post; (iii) **single-valued `aud` = the
   requesting `client_id`, `exp` ≤ 5 min, `nonce` required at mint** — notme
   refuses authorization requests without `nonce`, tightening OIDC's
   code-flow OPTIONAL to a profile MUST; (iv) **closed RP registration in
   Phase 1** — id_tokens are minted only for enrolled `client_id`s whose
   operators have acknowledged the PoP profile, so "the weakest RP" is one we
   enrolled and can audit, not an arbitrary stranger; open/dynamic
   registration is a separate future decision with its own review; (v)
   **distinct `kid` for id_token signing** — same JWKS, dedicated key — so
   the identity-assertion key rotates/revokes independently of the `at+jwt`
   root, and cross-protocol confusion is additionally stopped by claims shape
   (`at+jwt` has no `nonce` and a resource `aud`; RFC 9068 verifiers reject
   non-`at+jwt` `typ` in the other direction).
2. **`sub` correlation / privacy — resolved: no real conflict, because the
   correlator's lifetime is the dispatch's, not the principal's.** The tension
   would be real if `sub` were a stable key for a long-lived principal being
   tracked across RPs. It isn't: a dispatch key is minted per dispatch (the
   APAS "dispatch = unit of cryptographic identity" model), so the thumbprint
   correlates exactly one dispatch's activity across the RPs it touches —
   which is the *auditability APAS wants*, not a privacy leak about a person.
   Nothing in the token links one dispatch key to another, so cross-dispatch
   correlation of the human behind them is not enabled by `sub`. Decision:
   `sub` = dispatch-key thumbprint, `subject_types_supported: ["public"]`, no
   pairwise machinery in Phase 1. **Tripwire:** this resolution is load-bearing
   on the per-dispatch-key invariant. If a long-lived holder key (user key,
   org key) is ever accepted as an id_token subject, pairwise `sub` becomes
   mandatory and this section must be revisited before that ships.
3. **Replay + nonce — resolved: RP-side `nonce` owns id_token replay; notme's
   new replay duty is the authorization code.** notme cannot see id_token
   presentations, so server-side replay tracking of the token itself is
   category error; the OIDC design puts that on the RP's `nonce` check, and
   invariant (iii) above makes `nonce` unconditionally present. What notme
   *must* replay-protect is (a) the authorization code — strictly single-use,
   short TTL, tracked server-side; reuse the jti-ledger pattern from the DPoP
   proof path (`worker/src/auth/dpop-handler.ts` `checkJtiReplay`/`storeJti`
   with `worker/src/auth/dpop.ts` — the replay *logic*. An earlier draft
   miscited `platform.ts` as the machinery; `platform.ts`'s `MemoryCache` is
   only the local-workerd TTL *store* that backs the ledger, KV in prod —
   store, not logic) — and (b) any
   notme-facing PoP proofs, which already ride that ledger. Mint a `jti` into
   every id_token anyway: it costs nothing and gives audit logs a stable
   token identity.
4. **Code flow + PKCE.** Option A/C need the code flow notme lacks. PKCE
   (RFC 7636) is mandatory for public clients; it is currently unimplemented.
5. **Refresh.** RFC 9449 binds refresh tokens for public clients. If notme
   issues refresh alongside id_tokens, the DPoP binding there is standard —
   unlike the id_token binding. Keep the two straight.
6. **The presentation gap (added in review — this was the doc's biggest
   hand-wave).** `cnf.jwk` tells the RP *which* key; it does not give the RP a
   way to make the holder *prove* it. "PoP-aware RP additionally … demands a
   proof of the key" is vaporware until a concrete challenge–response profile
   exists: what the holder signs, over what nonce/htu/htm material, with what
   freshness window, carried in which header. Without it, even a maximally
   careful RP can only do bearer verification plus a `sub`-format check, and
   the entire security argument for C over A collapses to "the claims are
   shaped nicely." Decision: Phase 1 MUST ship a written presentation profile
   — a DPoP-*shaped* proof JWT (ES256/EdDSA over an RP-supplied nonce +
   target URI + method, ≤ 60 s window, `jti` single-use at the RP), published
   in `service_documentation`, and explicitly **not called DPoP** (RFC 9449
   scopes DPoP to access tokens; see Standards reality above). RP enrollment
   (invariant iv) includes acknowledging this profile.

## What flips in code (grounding, not scope-creep)

- `worker/src/as-metadata.ts` (verified against the file, 2026-07-21):
  `FORBIDDEN_METADATA_FIELDS` loses three of its four entries —
  `subject_types_supported` (publish `["public"]`, per decision 2),
  `authorization_endpoint` (publish it; RFC 8414 §2's omission license lapses
  the moment a grant type uses it), and `code_challenge_methods_supported`
  (publish `["S256"]` when PKCE lands). `algorithms_supported` stays
  forbidden — it's the dead non-standard field, unrelated to this work.
  `response_types_supported` gains `code` **and must never gain anything
  else** (invariant ii); `scopes_supported` gains `openid`. **No change** to
  `id_token_signing_alg_values_supported`: it already publishes `["EdDSA"]`
  (deployer-overridable via `ID_TOKEN_SIGNING_ALGS`, empty-list-proofed) — an
  earlier draft wrongly listed it as forbidden-today.
- `as-metadata.test.ts`: the omission guards **invert** — specifically:
  the `it.each(FORBIDDEN_METADATA_FIELDS)` absence loop (shrinks with the
  list), "advertises no OIDC-provider capability" (`scopes_supported` not
  containing `openid` flips to containing it; `response_types_supported` not
  containing `id_token` **stays** — that assertion becomes invariant ii's
  tripwire, don't delete it), "does not claim PKCE", "response_types_supported
  … is empty", and "omitting authorization_endpoint does not break go-oidc
  discovery" (retired for a presence + URL-shape assertion). New tests must
  assert a minted id_token carries `sub` = thumbprint + `cnf.jwk`, a required
  `nonce`, single-valued `aud`, ≤ 5-min `exp`, and the dedicated `kid`. That
  inversion is the tripwire that keeps this from silently becoming a plain
  bearer OP.
- New: authorization-code + PKCE state machine (codes single-use via the
  jti-ledger pattern, §3 above); id_token minting with `cnf`; the
  presentation-profile document (§6 above); RP registration records
  (invariant iv).
- Prior-art warning from this codebase: `worker/src/signing-authority.ts`
  already grew one unbound bearer path — the redirect token, minted with an
  explicit "no cnf.jkt … Bearer path" comment. That is exactly the creep
  pattern decision 1 below forbids for id_tokens; the redirect token's
  existence is why "no unbound variant" needs a test, not a convention.

## Recommendation

**Option C, phased.** The review pass (below) settled the downgrade surface:
build C, but the five invariants in §1 are *constitutive*, not hardening —
drop any one and this becomes "notme quietly became a bearer OP," and the
correct move at that point is to not ship rather than ship without it.

Phase 1: code flow + PKCE + a `cnf.jwk`/`sub`-bound id_token, 5-min, hard
single `aud`, mandatory `nonce`, dedicated `kid`, closed RP registration, and
the written presentation profile (§6). Phase 2: publish the flipped metadata
+ inverted tests. Phase 3: SIOP-compatible presentation for RPs that want
structural PoP.

## Decisions (were: open questions; resolved in review, 2026-07-21)

1. **No unbound id_token path, ever.** Every id_token is `cnf.jwk`-bound with
   `sub` = thumbprint; there is no negotiation by which a client or RP can
   request an unbound variant. Rationale: (a) an unbound id_token *is* the
   asset class notme exists to eliminate — minting one is misissuance by this
   project's own thesis, regardless of whose "risk" it nominally is; (b) two
   variants create a protocol-level downgrade lever (steer issuance to the
   unbound shape) that no RP-side care can compensate for; (c) this codebase
   has already demonstrated the creep — the unbound redirect token in
   `signing-authority.ts`. Enforce with a mint-path test asserting `cnf` is
   present on every issued id_token, not with review vigilance.
2. **`sub` = stable dispatch-key thumbprint; no pairwise; `subject_types_supported:
   ["public"]`.** Both-at-once is a footgun (an RP choosing pairwise silently
   opts out of the audit property APAS depends on), and pairwise solves a
   problem the per-dispatch key lifetime already solves — see §2 of the
   security-model section, including the tripwire if long-lived subject keys
   ever appear.
3. **Yes for careful RPs — once the presentation profile exists — and not a
   net regression for naive ones.** For an RP that follows the profile,
   binding + challenge–response proof closes the gap structurally. For the
   library-floor RP, §1's analysis holds: code-flow-only back-channel
   delivery removes the injection surface; `aud`/`exp`/`nonce` bound the
   residue; closed registration makes the RP population enumerable. The
   feature is a net security *improvement* over not shipping for its actual
   alternative — because the realistic alternative is not "no identity
   assertion" but RPs improvising identity out of access tokens or bridge
   certs without any of this discipline. The one caveat that keeps this
   honest: before the §6 presentation profile ships, C is
   indistinguishable-in-practice from A. The profile is therefore Phase 1
   scope, not Phase 3 polish.
4. **The "not an OP" stance inverts cleanly; no third profile.** The stance
   was never identity-averse — it was overclaim-averse: discovery must not
   advertise capabilities that don't exist (`as-metadata.ts` says exactly
   this; over-claiming is the failure mode its tests pin). Once id_tokens are
   really minted, *omitting* the OP fields would be the new lie. So: publish
   standard OP metadata truthfully, and express the notme-specific tightening
   (mandatory `cnf`, mandatory `nonce`, 5-min, closed registration, the
   presentation profile) as a documented issuer profile referenced from
   `service_documentation` — a stricter OP, not a third species. README and
   discovery comments flip in the same commit as the capability, so the
   docs and the metadata never disagree in either direction.

## Review verdict (fable, 2026-07-21)

**Bottom line: Option C is safe to build** — under the five §1 invariants
(always-bound, code-flow/back-channel only, aud+exp+nonce discipline, closed
Phase-1 registration, dedicated `kid`) and with the §6 presentation profile
promoted into Phase 1. It is not a net regression versus not shipping: the
classic stolen-id_token attack needs a front channel this design never
offers, the residual bearer window is five minutes at one enrolled RP, and
the "weakest RP" is bounded by registration rather than by the open internet.
The genuinely new risk is root blast radius — notme's signatures becoming
consumable outside the first-party boundary — which is inherent to offering
identity at all and is mitigated (not removed) by the dedicated signing key.

What this review changed, beyond answering the open questions in place:

- **Corrected three code-facts.** (1) `id_token_signing_alg_values_supported`
  is already published (`["EdDSA"]`, `ID_TOKEN_SIGNING_ALGS` override), not
  in `FORBIDDEN_METADATA_FIELDS`; (2) the forbidden list's actual contents
  are `subject_types_supported` / `authorization_endpoint` /
  `code_challenge_methods_supported` / `algorithms_supported`, and the "what
  flips" section now walks the real fields and the real named tests; (3) the
  jti replay machinery is in `worker/src/auth/dpop-handler.ts` +
  `worker/src/auth/dpop.ts`, not `platform.ts`.
- **Named the presentation gap (§6)** — `cnf` without a challenge–response
  profile is decorative; this was the doc's largest hand-wave and is now
  Phase 1 scope.
- **Resolved the audit/privacy tension** via the per-dispatch key lifetime,
  with an explicit tripwire on that invariant.
- **Surfaced the unbound-redirect-token prior art** as evidence that "no
  unbound variant" needs a test, not a convention.
- **Left honestly unverified:** FAPI 2.0 (already labeled); and the OIDC Core
  §3.1.3.7 validation-steps characterization in §1 (aud MUST contain
  client_id; nonce MUST be verified if sent; nonce OPTIONAL in code-flow
  requests) is from reviewer memory of the spec — confirm against the
  openid.net text before Phase 1 lands, per this doc's own standards
  discipline.
