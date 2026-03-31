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
  certificate: string;
  private_key: string;
  expires_at: number;
  subject: string;
  authority: { epoch: number; key_id: string };
  principal_id: string;
  scopes: string[];
  auth_method: string;
}

const CERT_TTL_MS = 5 * 60 * 1000; // 5 minutes

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
    // Verify OIDC JWT from any issuer
    const { verifyOIDC } = await import("./auth/verify-proof");
    let identity;
    try {
      identity = await verifyOIDC(body.proof.token);
    } catch (e: any) {
      return Response.json(
        { error: "invalid token: " + e.message },
        { status: 401 },
      );
    }

    // Look up principal by federated identity
    const { findPrincipalByFederated, getCapabilities } = await import(
      "./auth/principals"
    );
    const found = findPrincipalByFederated(
      // Need DO sql access — delegate to authority
      // For now, we don't have direct sql access from here.
      // This will be wired via DO RPC.
      null as any, // TODO: wire via authority RPC
      identity.issuer,
      identity.subject,
    );

    if (!found) {
      return Response.json(
        {
          error: "unknown identity — register first or get an invite",
          issuer: identity.issuer,
          subject: identity.subject,
        },
        { status: 403 },
      );
    }

    principalId = found;
    grantedScopes = getCapabilities(null as any, principalId); // TODO: wire via DO
    authMethod = `oidc:${identity.issuer}`;
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

  // ── Mint bridge cert ──

  let signingKey: CryptoKey;
  let authorityState: { epoch: number; keyId: string };
  try {
    const keys = await authority.getOrCreateSigningKey();
    signingKey = keys.signingKey;
    authorityState = await authority.getAuthorityState();
  } catch (e: any) {
    return Response.json(
      { error: "authority unavailable: " + e.message },
      { status: 503 },
    );
  }

  // Generate ephemeral P-256 keypair
  const kp = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;

  const pubDer = (await crypto.subtle.exportKey(
    "spki",
    kp.publicKey,
  )) as ArrayBuffer;
  const pubB64 = btoa(String.fromCharCode(...new Uint8Array(pubDer)));
  const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${pubB64.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;

  const privDer = (await crypto.subtle.exportKey(
    "pkcs8",
    kp.privateKey,
  )) as ArrayBuffer;
  const privB64 = btoa(String.fromCharCode(...new Uint8Array(privDer)));
  const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${privB64.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----`;

  const { mintGHABridgeCert } = await import("./cert-authority");
  let result;
  try {
    result = await mintGHABridgeCert(
      principalId, // CN = principal UUID
      publicKeyPem,
      signingKey,
      CERT_TTL_MS,
    );
  } catch (e: any) {
    return Response.json(
      { error: "cert minting failed: " + e.message },
      { status: 500 },
    );
  }

  const response: CertExchangeResponse = {
    certificate: result.certificate,
    private_key: privateKeyPem,
    expires_at: result.expires_at,
    subject: result.subject,
    authority: {
      epoch: authorityState.epoch,
      key_id: authorityState.keyId,
    },
    principal_id: principalId,
    scopes: effectiveScopes,
    auth_method: authMethod,
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
