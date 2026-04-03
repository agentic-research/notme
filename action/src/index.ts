import * as core from "@actions/core";
import * as http from "@actions/http-client";

interface CertResponse {
  certificate: string;
  private_key: string;
  expires_at: number;
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
    // octo-sts is a separate action — call it inline would require
    // importing their code. For now, log that it's not yet supported
    // in the TS action and recommend the YAML workflow for octo-sts.
    core.warning(
      "octo-sts is not yet supported in the TS action. " +
        "Use agentic-research/notme/.github/workflows/gha-identity.yml for octo-sts + bridge cert.",
    );
  }

  if (skipBridgeCert) {
    core.info("skip_bridge_cert is true — skipping bridge cert exchange");
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

  // ── exchange for bridge cert ──
  const certUrl = `${authorityUrl}/cert/gha`;
  core.info(`exchanging OIDC token at ${certUrl}`);

  const client = new http.HttpClient("notme-action");
  const res = await client.postJson<CertResponse>(certUrl, null, {
    Authorization: `Bearer ${oidcToken}`,
    "Content-Type": "application/json",
  });

  if (res.statusCode !== 200 || !res.result) {
    throw new Error(
      `cert exchange failed (${res.statusCode}): ${JSON.stringify(res.result)}`,
    );
  }

  const cert = res.result;

  if (!cert.certificate || !cert.private_key) {
    throw new Error("response missing certificate or private_key");
  }

  // ── mask + encode + output ──
  // Mask the full PEM (catches exact match in logs)
  core.setSecret(cert.private_key);
  // Mask individual PEM lines — GHA masks line-by-line, so the full
  // multi-line string won't match if printed across multiple log lines.
  // Skip BEGIN/END headers (generic strings that break log readability).
  for (const line of cert.private_key.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.length > 0 && !trimmed.startsWith("-----")) {
      core.setSecret(trimmed);
    }
  }
  const certB64 = Buffer.from(cert.certificate).toString("base64");
  const keyB64 = Buffer.from(cert.private_key).toString("base64");
  core.setSecret(keyB64);

  core.setOutput("bridge_cert", certB64);
  core.setOutput("bridge_key", keyB64);
  core.setOutput("bridge_expires_at", cert.expires_at.toString());

  core.info(
    `bridge cert issued for ${cert.subject} (epoch ${cert.authority.epoch}, expires ${cert.expires_at})`,
  );
}

run().catch((err) => core.setFailed(err.message));
