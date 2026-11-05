// Generalized certificate exchange — any proof → bridge cert.
//
// This is the core of the signet protocol at the edge:
//   1. Accept a proof (passkey session, OIDC JWT, bootstrap code)
//   2. Verify the proof
//   3. Resolve to a principal
//   4. Check the principal has the requested capability
//   5. Mint a bridge cert with principal_id as CN + scopes in extensions
//
// Schema-driven: input/output types from gen/ts/identity.ts (generated from identity.capnp).

import { verifyPopProofs } from "./auth/pop";
import { opaqueError } from "./error-body";
import { AUTH_METHOD, oidcAuthMethod, type AuthMethod } from "./auth/session";
import { authorityStub } from "./authority-stub";

// Types from the schema (would import from gen/ts/identity.ts, but
// we keep it simple and define the wire format inline to avoid
// build-time dependency on the generated code for now)

export interface CertExchangeRequest {
  proof: {
    type: "session";
  } | {
    type: "oidc";
    token: string;
  } | {
    type: "bootstrap";
    code: string;
  };
  scopes?: string[];
  // 008: optional PoP cert exchange — if present, returns cert pair instead of token
  public_keys?: { mtls: string; signing: string };
  // Required with public_keys on the SESSION proof: the session term of the
  // binding, from POST /cert/nonce (notme-486e8a).
  nonce?: string;
  proofs?: { mtls: string; signing: string };
}

// Response when public_keys + proofs are provided (008 cert pair)
export interface CertPairExchangeResponse {
  certificates: { mtls: string; signing: string };
  identity: string;
  scopes: string[];
  expires_at: number;
  binding: string;
  authority: { epoch: number; key_id: string };
  principal_id: string;
  auth_method: string;
}

// Legacy response when no public_keys (browser/passkey flows — DPoP or unbound)
export interface TokenExchangeResponse {
  token: string;
  token_type: "DPoP" | "Bearer";
  expires_in: number;
  subject: string;
  authority: { epoch: number; key_id: string };
  principal_id: string;
  scopes: string[];
  auth_method: string;
  jkt?: string;
}


export async function handleCertExchange(
  request: Request,
  env: any,
  // Only the OIDC proof needs it: its jti is single-use, in the same
  // keyspace /cert/gha uses (`jti:<jti>`), so a GitHub token is spendable
  // once across both routes.
  platform?: { cache: { get(k: string): Promise<string | null>; put(k: string, v: string, o?: { expirationTtl?: number }): Promise<void> } },
): Promise<Response> {
  if (request.method !== "POST") {
    return Response.json({ error: "method not allowed" }, { status: 405 });
  }

  const body = (await request.json()) as CertExchangeRequest;
  if (!body.proof?.type) {
    return Response.json({ error: "proof.type required" }, { status: 400 });
  }

  const requestedScopes = body.scopes ?? ["bridgeCert"];
  // Typed stub, and a typed method: the mint takes only a parsed AuthMethod,
  // so each proof branch below must produce one (notme-32003c).
  const authority = authorityStub(env);

  let principalId: string;
  let grantedScopes: string[];
  let authMethod: AuthMethod;
  // Set only for OIDC proofs: the token the PoP binds, and its jti/exp for
  // single-use accounting after the proofs verify.
  let oidc: { token: string; issuer: string; jti: string; exp: number } | null = null;

  // ── Resolve proof to principal ──

  if (body.proof.type === "session") {
    // Already authenticated via passkey — read session cookie
    const cookie = parseCookie(
      request.headers.get("cookie") || "",
      "notme_session",
    );
    if (!cookie) {
      return Response.json({ error: "no session cookie" }, { status: 401 });
    }
    // Through the isolate cache and the session limiter (per session, then
    // per principal, after the HMAC), as every cookie route is: a junk cookie
    // must not cost the SigningAuthority (notme-a34dad).
    const { verifySessionCached, sessionLimiter } = await import("./auth/session-secret-cache");
    const checked = await verifySessionCached(cookie, authority, sessionLimiter(env));
    if (!checked.ok && checked.limited) {
      return Response.json({ error: "rate_limited" }, { status: 429, headers: { "Retry-After": "60" } });
    }
    const session = checked.ok ? checked.session : null;
    if (!session) {
      return Response.json({ error: "invalid session" }, { status: 401 });
    }
    principalId = session.principalId;
    // LIVE grants, not the cookie's copy (notme-486e8a): a revoked scope
    // stops at once, not when the cookie expires.
    const { liveScopes } = await import("./auth/session");
    grantedScopes = await liveScopes(session, authority);
    // Provenance is derived from the session, and verifySessionCookie has
    // already refused one that cannot state it (notme-32003c). Defaulting to
    // "passkey" here would launder an invite- or OIDC-authed session into a
    // cert claiming a human touched an authenticator.
    authMethod = session.authMethod;
  } else if (body.proof.type === "oidc") {
    // ADR-019 case 3: automation acting under a PRINCIPAL's authority. The
    // verified OIDC identity resolves to the principal it was LINKED to
    // (by redeeming an invite with this OIDC proof); /cert/gha, by contrast,
    // mints a workload identity that represents no principal.
    //
    // This branch used to verify the token and return 501 — while the API
    // docs advertised `oidc` as a supported proof type with an example.
    const { verifyOIDC, issuerAudiences } = await import("./auth/verify-proof");
    let identity: { issuer: string; subject: string };
    try {
      identity = await verifyOIDC(body.proof.token, issuerAudiences(env));
    } catch (e: any) {
      // Constant bodies on this route (notme-b567c9): verifier, key-import
      // and Durable Object messages are logged, not returned.
      return opaqueError("cert", "invalid token", 401, e);
    }
    const claims = JSON.parse(
      atob(body.proof.token.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/")),
    ) as { jti?: unknown; exp?: unknown };
    if (typeof claims.jti !== "string" || !claims.jti) {
      return Response.json({ error: "jti claim required for replay protection" }, { status: 400 });
    }
    if (!body.public_keys?.mtls || !body.public_keys?.signing || !body.proofs?.mtls || !body.proofs?.signing) {
      // A cert pair is what this proof buys. The token branch below is the
      // session's; an OIDC token already IS a bearer token.
      return Response.json(
        { error: "an oidc proof exchanges for a cert pair — send public_keys and proofs" },
        { status: 400 },
      );
    }
    const found = await authority.findPrincipalByOIDC(identity.issuer, identity.subject);
    if (!found) {
      return Response.json(
        { error: "unknown identity — link it first by redeeming an invite with this OIDC proof" },
        { status: 403 },
      );
    }
    principalId = found;
    // LIVE grants — there is no cookie here to mistake for the source.
    grantedScopes = await authority.getPrincipalScopes(found);
    authMethod = oidcAuthMethod(identity.issuer);
    oidc = { token: body.proof.token, issuer: identity.issuer, jti: claims.jti, exp: Number(claims.exp) || 0 };
  } else if (body.proof.type === "bootstrap") {
    // Bootstrap code — deployer only
    const valid = await authority.consumeBootstrapCode(body.proof.code);
    if (!valid) {
      return Response.json(
        { error: "invalid or consumed bootstrap code" },
        { status: 403 },
      );
    }
    principalId = crypto.randomUUID();
    grantedScopes = [...(await import("./auth/admin-scopes")).ADMIN_SCOPES];
    authMethod = AUTH_METHOD.bootstrap;
    // Persist the admin this exchange mints a credential for. Pre-fix,
    // principalId was local-only: the sole bootstrap code was burned, a live
    // credential carrying authorityManage+certMint walked away, and the
    // authority still had ZERO principals — nothing to look up, grant, or
    // revoke against, and no admin to recover with (notme-92a1b9).
    await authority.createPrincipalWithCapabilities(principalId, grantedScopes);
  } else {
    // Exhaustiveness: CertExchangeRequest.proof is a discriminated union.
    // If a new variant is added without a branch, the assignment below
    // fails to typecheck (body.proof is no longer `never` here).
    const _exhaustive: never = body.proof;
    const seen = (_exhaustive as { type?: unknown }).type;
    return Response.json(
      { error: "unknown proof type: " + String(seen) },
      { status: 400 },
    );
  }

  // ── Check requested scopes against granted ──

  // narrowScopes rather than a bare filter: the intersection is the same, but
  // the subset postcondition is CHECKED, so an edit that lets the result
  // exceed grantedScopes fails here instead of minting (notme-acc822). Both
  // artifacts downstream inherit it — the cert branch narrows further through
  // certScopesForSession, the token branch carries this set as-is.
  const { narrowScopes } = await import("./auth/scope-chain");
  const effectiveScopes = narrowScopes(grantedScopes, requestedScopes);
  if (effectiveScopes.length === 0) {
    return Response.json(
      {
        error: "none of the requested scopes are granted",
        requested: requestedScopes,
        granted: grantedScopes,
      },
      { status: 403 },
    );
  }

  // ── 008: cert pair if public_keys + proofs provided, else legacy token ──
  if (body.public_keys?.mtls && body.public_keys?.signing &&
      body.proofs?.mtls && body.proofs?.signing) {
    // A CERTIFICATE may carry less than the session does. auth/
    // passkey-cert-scopes.ts states the rule and the reason: certMint is "a
    // delegation the human never agreed to at the touch prompt", and
    // authorityManage in a long-lived exportable credential removes the
    // "human present at a browser" property that made granting it
    // acceptable. /cert/passkey enforced it; this route did not, so the same
    // admin session yielded a cert carrying both one route over
    // (notme-18dfd0).
    //
    // The rule belongs to the ARTIFACT, not the route — a certificate is
    // long-lived, exportable and usable off-origin however it was obtained —
    // so it is applied HERE, on the cert branch, and not to the token branch
    // below, whose artifact is short-lived and DPoP-bound.
    //
    // This also narrows the bootstrap path deliberately. Its principal keeps
    // authorityManage + certMint (persisted by notme-92a1b9); the CERT it
    // walks away with does not. Capabilities live on the principal; a cert
    // carries only what is safe to export.
    const { certScopesForSession } = await import("./auth/passkey-cert-scopes");
    const certScopes = certScopesForSession(effectiveScopes);
    if (certScopes.length === 0) {
      return Response.json(
        {
          error: "none of the requested scopes may be carried by a certificate",
          requested: requestedScopes,
          eligible: ["bridgeCert"],
        },
        { status: 403 },
      );
    }
    // PoP cert pair exchange — verify proofs, issue certs
    const { importPublicKey } = await import("./cert-authority");
    let mtlsPubKey: CryptoKey;
    let signingPubKey: CryptoKey;
    try {
      mtlsPubKey = await importPublicKey(body.public_keys.mtls);
      signingPubKey = await importPublicKey(body.public_keys.signing);
    } catch (e: any) {
      return opaqueError("cert", "invalid public key", 400, e);
    }

    // Verify PoP proofs against a binding payload.
    //
    // SESSION proofs bind a session-scoped nonce (notme-486e8a). They used to
    // bind only mtls_spki || signing_spki — a function of the keys alone — so
    // anyone holding a valid session could replay a victim's captured
    // keys+proofs and bind the victim's keys to their OWN identity: the exact
    // attack /cert/passkey's session term was written to stop. BOOTSTRAP
    // proofs keep the keys-only binding: the code is single-use and was
    // already consumed above, so there is no second session to replay under.
    const mtlsSpki = (await crypto.subtle.exportKey("spki", mtlsPubKey)) as ArrayBuffer;
    const signingSpki = (await crypto.subtle.exportKey("spki", signingPubKey)) as ArrayBuffer;
    let bindingInput: Uint8Array;
    if (oidc) {
      // Same binding as /cert/gha: captured proofs cannot be paired with
      // another token.
      const tokenHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(oidc.token));
      bindingInput = new Uint8Array(mtlsSpki.byteLength + signingSpki.byteLength + 32);
      bindingInput.set(new Uint8Array(mtlsSpki), 0);
      bindingInput.set(new Uint8Array(signingSpki), mtlsSpki.byteLength);
      bindingInput.set(new Uint8Array(tokenHash), mtlsSpki.byteLength + signingSpki.byteLength);
    } else if (body.proof.type === "session") {
      if (typeof body.nonce !== "string" || !body.nonce) {
        return Response.json(
          { error: "nonce required with public_keys on a session proof — POST /cert/nonce first" },
          { status: 400 },
        );
      }
      const { certPairBinding } = await import("./auth/cert-pair-binding");
      bindingInput = await certPairBinding(new Uint8Array(mtlsSpki), new Uint8Array(signingSpki), body.nonce);
    } else {
      bindingInput = new Uint8Array(mtlsSpki.byteLength + signingSpki.byteLength);
      bindingInput.set(new Uint8Array(mtlsSpki), 0);
      bindingInput.set(new Uint8Array(signingSpki), mtlsSpki.byteLength);
    }
    // PoP over the binding PRE-IMAGE — never its digest (notme-a011d2).
    const pop = await verifyPopProofs(bindingInput, mtlsPubKey, signingPubKey, body.proofs);
    if (!pop.ok) {
      return Response.json(
        { error: `${pop.algorithm} proof-of-possession failed` },
        { status: 401 },
      );
    }
    // Spent only after the proofs verify; bound to this principal.
    if (body.proof.type === "session" && !(await authority.consumePopNonce(body.nonce!, principalId))) {
      return Response.json({ error: "invalid_nonce" }, { status: 401 });
    }
    // The OIDC token's jti, likewise spent only after the proofs verify, so a
    // forged request cannot burn the real holder's token.
    if (oidc) {
      if (!platform) {
        return Response.json({ error: "replay protection unavailable" }, { status: 500 });
      }
      const key = `jti:${oidc.jti}`;
      if (await platform.cache.get(key)) {
        return Response.json({ error: "token already used" }, { status: 401 });
      }
      // The authoritative spend (notme-b0d10f): the DO key every OIDC route
      // shares. KV is the cross-check, not the guard.
      if (!(await authority.spendOidcJti(oidc.issuer, oidc.jti, oidc.exp))) {
        return Response.json({ error: "token already used" }, { status: 401 });
      }
      const ttl = Math.max(60, oidc.exp - Math.floor(Date.now() / 1000));
      await platform.cache.put(key, "1", { expirationTtl: ttl });
    }

    const { wimseTrustDomain } = await import("../worker");
    // The identity names the PRINCIPAL, not the ceremony (ADR-019 D2,
    // notme-77438b). authMethod still travels — in OID_AUTH_METHOD, where a
    // verifier reads it as a claim instead of splitting a URI whose segment
    // meanings used to differ by route.
    const { principalIdentity } = await import("./cert-authority");
    const identity = principalIdentity(wimseTrustDomain(env), principalId);

    let result;
    try {
      result = await authority.mintBridgeCertPair({
        subject: principalId,
        identity,
        mtlsPublicKeyPem: body.public_keys.mtls,
        signingPublicKeyPem: body.public_keys.signing,
        scopes: certScopes,
        authMethod,
      });
    } catch (e: any) {
      return opaqueError("cert", "cert minting failed", 500, e);
    }

    const response: CertPairExchangeResponse = {
      certificates: result.certificates,
      identity: result.identity,
      scopes: certScopes,
      expires_at: result.expires_at,
      binding: result.binding,
      authority: result.authority,
      principal_id: principalId,
      auth_method: authMethod,
    };
    return Response.json(response);
  }

  // ── Legacy: token for browser/passkey flows (no public_keys provided) ──
  // Audience uses the outgoing-token convention (https://<host>) so the
  // resource-server SDK in packages/dpop validates against the same form
  // /token and /authorize/token use. Earlier, this minted aud="notme.bot"
  // (the INCOMING-OIDC convention), producing tokens no resource server
  // would accept — see notme-612016. Two conventions still live in this
  // codebase: bare hostname for tokens TO notme, https-form for tokens
  // FROM notme.
  let accessToken: string;
  try {
    accessToken = await authority.mintRedirectToken({
      sub: principalId,
      scope: effectiveScopes.join(" "),
      audience: "https://notme.bot",
    });
  } catch (e: any) {
    return opaqueError("cert", "token minting failed", 500, e);
  }

  const state = await authority.getAuthorityState();
  const tokenResponse: TokenExchangeResponse = {
    token: accessToken,
    token_type: "Bearer",
    expires_in: 300,
    subject: principalId,
    authority: { epoch: state.epoch, key_id: state.keyId },
    principal_id: principalId,
    scopes: effectiveScopes,
    auth_method: authMethod,
  };
  return Response.json(tokenResponse);
}

function parseCookie(cookieHeader: string, name: string): string | null {
  const match = cookieHeader
    .split(";")
    .map((c) => c.trim())
    .find((c) => c.startsWith(`${name}=`));
  return match ? match.slice(name.length + 1) : null;
}
