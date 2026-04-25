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
    type: "session"; // passkey session cookie (already authenticated)
    // Future: "oidc" | "x509" | "bootstrap"
  } | {
    type: "oidc";
    token: string; // raw JWT from any issuer
  } | {
    type: "bootstrap";
    code: string;
  };
  scopes?: string[]; // requested scopes (default: ["bridgeCert"])
}

export interface CertExchangeResponse {
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

  // ── Mint token (DPoP-bound if proof present, unbound otherwise) ──
  const dpopHeader = request.headers.get("DPoP");
  let accessToken: string;
  let tokenType: "DPoP" | "Bearer" = "Bearer";
  let jkt: string | undefined;

  if (dpopHeader) {
    // DPoP proof present — bind the token to the caller's key
    const { validateDpopProof } = await import("./auth/dpop");
    let dpopResult;
    try {
      dpopResult = await validateDpopProof(dpopHeader, {
        htm: "POST",
        htu: new URL(request.url).origin + "/cert",
      });
    } catch (e: any) {
      return Response.json(
        { error: "invalid DPoP proof: " + e.message },
        { status: 401 },
      );
    }
    try {
      accessToken = await authority.mintDPoPToken({
        sub: principalId,
        scope: effectiveScopes.join(" "),
        audience: "notme.bot",
        jkt: dpopResult.thumbprint,
      });
    } catch (e: any) {
      return Response.json(
        { error: "token minting failed: " + e.message },
        { status: 500 },
      );
    }
    tokenType = "DPoP";
    jkt = dpopResult.thumbprint;
  } else {
    // No DPoP — unbound token (for bootstrap/passkey flows)
    try {
      accessToken = await authority.mintRedirectToken({
        sub: principalId,
        scope: effectiveScopes.join(" "),
        audience: "notme.bot",
      });
    } catch (e: any) {
      return Response.json(
        { error: "token minting failed: " + e.message },
        { status: 500 },
      );
    }
  }

  const state = await authority.getAuthorityState();

  const response: CertExchangeResponse = {
    token: accessToken,
    token_type: tokenType,
    expires_in: 300,
    subject: principalId,
    authority: { epoch: state.epoch, key_id: state.keyId },
    principal_id: principalId,
    scopes: effectiveScopes,
    auth_method: authMethod,
    ...(jkt ? { jkt } : {}),
  };

  return Response.json(response);
}

function parseCookie(cookieHeader: string, name: string): string | null {
  const match = cookieHeader
    .split(";")
    .map((c) => c.trim())
    .find((c) => c.startsWith(`${name}=`));
  return match ? match.slice(name.length + 1) : null;
}
