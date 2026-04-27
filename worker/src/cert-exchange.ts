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
): Promise<Response> {
  if (request.method !== "POST") {
    return Response.json({ error: "method not allowed" }, { status: 405 });
  }

  const body = (await request.json()) as CertExchangeRequest;
  if (!body.proof?.type) {
    return Response.json({ error: "proof.type required" }, { status: 400 });
  }

  const requestedScopes = body.scopes ?? ["bridgeCert"];
  const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
  const authority = env.SIGNING_AUTHORITY.get(authorityId);

  let principalId: string;
  let grantedScopes: string[];
  let authMethod: string;

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
    const { verifySessionCookie } = await import("./auth/session");
    const sessionSecret = await authority.getSessionSecret();
    const session = await verifySessionCookie(cookie, sessionSecret);
    if (!session) {
      return Response.json({ error: "invalid session" }, { status: 401 });
    }
    principalId = session.principalId;
    grantedScopes = session.scopes;
    authMethod = session.authMethod;
  } else if (body.proof.type === "oidc") {
    // OIDC principal lookup not yet wired to DO RPC.
    // Verify the token (to fail fast on bad input), then return 501.
    const { verifyOIDC } = await import("./auth/verify-proof");
    try {
      await verifyOIDC(body.proof.token, "notme.bot");
    } catch (e: any) {
      return Response.json(
        { error: "invalid token: " + e.message },
        { status: 401 },
      );
    }
    return Response.json(
      { error: "oidc_not_implemented", message: "OIDC proof path not yet wired to DO — use passkey or GHA OIDC at /cert/gha" },
      { status: 501 },
    );
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
    grantedScopes = ["bridgeCert", "authorityManage", "certMint"];
    authMethod = "bootstrap";
  } else {
    return Response.json(
      { error: "unknown proof type: " + (body.proof as any).type },
      { status: 400 },
    );
  }

  // ── Check requested scopes against granted ──

  const effectiveScopes = requestedScopes.filter((s) =>
    grantedScopes.includes(s),
  );
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
    // PoP cert pair exchange — verify proofs, issue certs
    const { importPublicKey } = await import("./cert-authority");
    let mtlsPubKey: CryptoKey;
    let signingPubKey: CryptoKey;
    try {
      mtlsPubKey = await importPublicKey(body.public_keys.mtls);
      signingPubKey = await importPublicKey(body.public_keys.signing);
    } catch (e: any) {
      return Response.json({ error: "invalid public key: " + e.message }, { status: 400 });
    }

    // Verify PoP proofs against a binding payload
    // For /cert, binding = SHA-256(mtls_spki || signing_spki) — no OIDC JWT in this path
    const mtlsSpki = (await crypto.subtle.exportKey("spki", mtlsPubKey)) as ArrayBuffer;
    const signingSpki = (await crypto.subtle.exportKey("spki", signingPubKey)) as ArrayBuffer;
    const bindingInput = new Uint8Array(mtlsSpki.byteLength + signingSpki.byteLength);
    bindingInput.set(new Uint8Array(mtlsSpki), 0);
    bindingInput.set(new Uint8Array(signingSpki), mtlsSpki.byteLength);
    const bindingPayload = await crypto.subtle.digest("SHA-256", bindingInput);

    // Verify P-256 PoP
    try {
      const proofBytes = Uint8Array.from(atob(body.proofs.mtls.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
      const valid = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" }, mtlsPubKey, proofBytes, bindingPayload,
      );
      if (!valid) return Response.json({ error: "P-256 proof-of-possession failed" }, { status: 401 });
    } catch (e: any) {
      return Response.json({ error: "P-256 proof error: " + e.message }, { status: 401 });
    }

    // Verify Ed25519 PoP
    try {
      const proofBytes = Uint8Array.from(atob(body.proofs.signing.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
      const valid = await crypto.subtle.verify(
        "Ed25519" as any, signingPubKey, proofBytes, bindingPayload,
      );
      if (!valid) return Response.json({ error: "Ed25519 proof-of-possession failed" }, { status: 401 });
    } catch (e: any) {
      return Response.json({ error: "Ed25519 proof error: " + e.message }, { status: 401 });
    }

    const identity = `wimse://notme.bot/${authMethod}/${principalId}`;

    let result;
    try {
      result = await authority.mintBridgeCertPair({
        subject: principalId,
        identity,
        mtlsPublicKeyPem: body.public_keys.mtls,
        signingPublicKeyPem: body.public_keys.signing,
        scopes: effectiveScopes,
        authMethod,
      });
    } catch (e: any) {
      return Response.json({ error: "cert minting failed: " + e.message }, { status: 500 });
    }

    const response: CertPairExchangeResponse = {
      certificates: result.certificates,
      identity: result.identity,
      scopes: effectiveScopes,
      expires_at: result.expires_at,
      binding: result.binding,
      authority: result.authority,
      principal_id: principalId,
      auth_method: authMethod,
    };
    return Response.json(response);
  }

  // ── Legacy: token for browser/passkey flows (no public_keys provided) ──
  let accessToken: string;
  try {
    accessToken = await authority.mintRedirectToken({
      sub: principalId,
      scope: effectiveScopes.join(" "),
      audience: "notme.bot",
    });
  } catch (e: any) {
    return Response.json({ error: "token minting failed: " + e.message }, { status: 500 });
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
