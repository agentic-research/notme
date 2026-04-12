import * as core from "@actions/core";
import * as http from "@actions/http-client";

interface AuthResponse {
  token: string;
  token_type: string;
  expires_in: number;
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

async function run(): Promise<void> {
  const audience = core.getInput("audience");
  const authorityUrl = core.getInput("authority_url");
  const skipBridgeCert = core.getBooleanInput("skip_bridge_cert");

  // ── octo-sts (optional) ──
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

  // ── Enforce HTTPS on authority URL (prevent OIDC token interception) ──
  if (
    authorityUrl.startsWith("http://") &&
    !authorityUrl.includes("localhost") &&
    !authorityUrl.includes("127.0.0.1")
  ) {
    throw new Error(
      "authority_url must be HTTPS — an HTTP URL would transmit the OIDC token in plaintext",
    );
  }

  // ── OIDC token (no env vars — core.getIDToken handles everything) ──
  core.info(`requesting OIDC token (audience: ${audience})`);
  let oidcToken: string;
  try {
    oidcToken = await core.getIDToken(audience);
  } catch (err) {
    throw new Error(
      `failed to get OIDC token — does the job have 'permissions: id-token: write'? ${err}`,
    );
  }

  // ── Exchange OIDC for access token (secretless — no private key returned) ──
  const certUrl = `${authorityUrl}/cert/gha`;
  core.info(`exchanging OIDC token at ${certUrl}`);

  const client = new http.HttpClient("notme-action");
  const res = await client.postJson<AuthResponse>(certUrl, null, {
    Authorization: `Bearer ${oidcToken}`,
    "Content-Type": "application/json",
  });

  if (res.statusCode !== 200 || !res.result) {
    throw new Error(
      `identity exchange failed (${res.statusCode}): ${JSON.stringify(res.result)}`,
    );
  }

  const auth = res.result;

  if (!auth.token) {
    throw new Error("response missing token");
  }

  // Mask the token in logs (it's a Bearer credential)
  core.setSecret(auth.token);

  // ── Outputs: URL + token, never a private key ──
  core.setOutput("notme_url", authorityUrl);
  core.setOutput("notme_token", auth.token);
  core.setOutput("expires_in", auth.expires_in.toString());

  core.info(
    `identity established for ${auth.subject} (epoch ${auth.authority.epoch}, key ${auth.authority.key_id})`,
  );
}

run().catch((err) => core.setFailed(err.message));
