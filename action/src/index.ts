import * as core from "@actions/core";
import * as http from "@actions/http-client";
import * as crypto from "crypto";

interface AuthResponse {
  token: string;
  token_type: string;
  expires_in: number;
  jkt: string;
  subject: string;
  authority: { epoch: number; key_id: string };
  claims: {
    repository: string;
    ref: string;
    sha: string;
    actor: string;
    workflow: string;
    run_id: string;
    event_name: string;
  };
}

// ── DPoP proof construction (RFC 9449) ──────────────────────────────────────
// The ephemeral P-256 keypair lives only in this process's memory.
// It is never written to $GITHUB_OUTPUT, never serialized, never exported.
// When this step exits, the key dies. The token is useless without it.

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

async function generateDPoPProof(
  keypair: crypto.webcrypto.CryptoKeyPair,
  htm: string,
  htu: string,
): Promise<{ proof: string; thumbprint: string }> {
  const wc = crypto.webcrypto;

  // Export public JWK for the header
  const pubJwk = (await wc.subtle.exportKey(
    "jwk",
    keypair.publicKey,
  )) as JsonWebKey;

  // Compute JWK thumbprint (RFC 7638) — same as gen/ts/dpop.ts computeJwkThumbprint
  const thumbprintInput = JSON.stringify({
    crv: pubJwk.crv,
    kty: pubJwk.kty,
    x: pubJwk.x,
    y: pubJwk.y,
  });
  const thumbprintHash = await wc.subtle.digest(
    "SHA-256",
    Buffer.from(thumbprintInput),
  );
  const thumbprint = b64url(Buffer.from(thumbprintHash));

  // Build the DPoP JWT
  const header = {
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: { kty: pubJwk.kty, crv: pubJwk.crv, x: pubJwk.x, y: pubJwk.y },
  };
  const payload = {
    jti: crypto.randomUUID(),
    htm,
    htu,
    iat: Math.floor(Date.now() / 1000),
  };

  const headerB64 = b64url(Buffer.from(JSON.stringify(header)));
  const payloadB64 = b64url(Buffer.from(JSON.stringify(payload)));
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`);

  const sig = await wc.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    keypair.privateKey,
    signingInput,
  );

  const proof = `${headerB64}.${payloadB64}.${b64url(Buffer.from(sig))}`;
  return { proof, thumbprint };
}

async function run(): Promise<void> {
  const audience = core.getInput("audience");
  const authorityUrl = core.getInput("authority_url");
  const skipBridgeCert = core.getBooleanInput("skip_bridge_cert");

  const octoStsScope = core.getInput("octo_sts_scope");
  if (octoStsScope) {
    core.warning(
      "octo-sts is not yet supported in the TS action. " +
        "Use agentic-research/notme/.github/workflows/gha-identity.yml for octo-sts + bridge cert.",
    );
  }

  if (skipBridgeCert) {
    core.info("skip_bridge_cert is true — skipping identity exchange");
    return;
  }

  // ── Enforce HTTPS on authority URL ──
  if (
    authorityUrl.startsWith("http://") &&
    !authorityUrl.includes("localhost") &&
    !authorityUrl.includes("127.0.0.1")
  ) {
    throw new Error(
      "authority_url must be HTTPS — an HTTP URL would transmit the OIDC token in plaintext",
    );
  }

  // ── OIDC token ──
  core.info(`requesting OIDC token (audience: ${audience})`);
  let oidcToken: string;
  try {
    oidcToken = await core.getIDToken(audience);
  } catch (err) {
    throw new Error(
      `failed to get OIDC token — does the job have 'permissions: id-token: write'? ${err}`,
    );
  }

  // ── Generate ephemeral DPoP keypair (lives only in this process) ──
  core.info("generating ephemeral DPoP keypair (P-256, in-memory only)");
  const wc = crypto.webcrypto;
  const dpopKeypair = (await wc.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false, // NON-EXTRACTABLE — cannot be serialized or output
    ["sign", "verify"],
  )) as crypto.webcrypto.CryptoKeyPair;

  // ── Build DPoP proof for the /cert/gha request ──
  const certUrl = `${authorityUrl}/cert/gha`;
  const { proof, thumbprint } = await generateDPoPProof(
    dpopKeypair,
    "POST",
    certUrl,
  );

  core.info(`exchanging OIDC + DPoP proof at ${certUrl} (jkt: ${thumbprint.slice(0, 8)}...)`);

  // ── Exchange OIDC + DPoP → DPoP-bound token ──
  const client = new http.HttpClient("notme-action");
  const res = await client.postJson<AuthResponse>(certUrl, null, {
    Authorization: `Bearer ${oidcToken}`,
    DPoP: proof,
    "Content-Type": "application/json",
  });

  if (res.statusCode !== 200 || !res.result) {
    throw new Error(
      `identity exchange failed (${res.statusCode}): ${JSON.stringify(res.result)}`,
    );
  }

  const auth = res.result;

  if (!auth.token || auth.token_type !== "DPoP") {
    throw new Error(`expected DPoP token, got ${auth.token_type || "nothing"}`);
  }

  // Mask the token in logs (DPoP-bound — useless without the key, but still mask it)
  core.setSecret(auth.token);

  // ── Outputs ──
  // The token is DPoP-bound (cnf.jkt). It is NOT a bearer credential.
  // To use it, the caller must present a DPoP proof signed by the matching key.
  // The key exists only in this step's process memory — it cannot be output.
  //
  // For cross-step usage: each step runs the action independently to get its
  // own DPoP keypair + bound token. No credential sharing between steps.
  core.setOutput("notme_url", authorityUrl);
  core.setOutput("notme_token", auth.token);
  core.setOutput("notme_jkt", auth.jkt);
  core.setOutput("expires_in", auth.expires_in.toString());

  core.info(
    `DPoP-bound identity established for ${auth.subject} ` +
      `(epoch ${auth.authority.epoch}, key ${auth.authority.key_id}, ` +
      `jkt: ${thumbprint.slice(0, 8)}...)`,
  );
  core.info(
    "note: the DPoP private key exists only in this step's memory. " +
      "downstream steps should run the action independently for their own keypair.",
  );
}

run().catch((err) => core.setFailed(err.message));
