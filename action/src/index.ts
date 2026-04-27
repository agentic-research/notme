import * as core from "@actions/core";
import * as http from "@actions/http-client";
import * as crypto from "crypto";

interface CertPairResponse {
  certificates: {
    mtls: string;
    signing: string;
  };
  identity: string;
  scopes: string[];
  expires_at: number;
  binding: string;
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

// ── PoP proof construction ──────────────────────────────────────────────────
// Two ephemeral keypairs (P-256 + Ed25519) live only in this process's memory.
// Never written to $GITHUB_OUTPUT, never serialized, never exported.
// When this step exits, the keys die. The certs are useless without them.

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function exportSpkiPem(spki: ArrayBuffer, label = "PUBLIC KEY"): string {
  const b64 = Buffer.from(spki).toString("base64");
  const lines = b64.match(/.{1,64}/g)!;
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
}

async function run(): Promise<void> {
  const audience = core.getInput("audience");
  const authorityUrl = core.getInput("authority_url");
  const skipBridgeCert = core.getBooleanInput("skip_bridge_cert");

  const octoStsScope = core.getInput("octo_sts_scope");
  if (octoStsScope) {
    core.warning(
      "octo-sts is not yet supported in the TS action. " +
        "Use agentic-research/notme/.github/workflows/gha-identity.yml for octo-sts.",
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

  // ── Generate ephemeral keypairs (both extractable:false — cannot be serialized) ──
  const wc = crypto.webcrypto;

  core.info("generating ephemeral P-256 keypair (mTLS, in-memory only)");
  const mtlsKeypair = (await wc.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  )) as crypto.webcrypto.CryptoKeyPair;

  core.info("generating ephemeral Ed25519 keypair (signing, in-memory only)");
  const signingKeypair = (await wc.subtle.generateKey(
    { name: "Ed25519" } as any,
    false,
    ["sign", "verify"],
  )) as crypto.webcrypto.CryptoKeyPair;

  // Export public keys as SPKI PEM (public data — safe to transmit)
  // Note: exportKey("spki") works on non-extractable PUBLIC keys
  const mtlsSpki = await wc.subtle.exportKey("spki", mtlsKeypair.publicKey);
  const signingSpki = await wc.subtle.exportKey("spki", signingKeypair.publicKey);
  const mtlsPem = exportSpkiPem(mtlsSpki);
  const signingPem = exportSpkiPem(signingSpki);

  // ── Compute binding payload + PoP proofs ──
  // binding = SHA-256(mtls_spki || signing_spki || SHA-256(oidc_jwt))
  const oidcHash = await wc.subtle.digest("SHA-256", Buffer.from(oidcToken));
  const bindingInput = Buffer.concat([
    Buffer.from(mtlsSpki),
    Buffer.from(signingSpki),
    Buffer.from(oidcHash),
  ]);
  const bindingPayload = await wc.subtle.digest("SHA-256", bindingInput);

  // Sign binding payload with P-256 key (ES256)
  const mtlsProof = await wc.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    mtlsKeypair.privateKey,
    bindingPayload,
  );

  // Sign binding payload with Ed25519 key
  const signingProof = await wc.subtle.sign(
    { name: "Ed25519" } as any,
    signingKeypair.privateKey,
    bindingPayload,
  );

  // ── Exchange: OIDC + public keys + PoP proofs → cert pair ──
  const certUrl = `${authorityUrl}/cert/gha`;
  core.info(`exchanging OIDC + PoP proofs at ${certUrl}`);

  const client = new http.HttpClient("notme-action");
  const res = await client.postJson<CertPairResponse>(certUrl, {
    public_keys: {
      mtls: mtlsPem,
      signing: signingPem,
    },
    proofs: {
      mtls: b64url(Buffer.from(mtlsProof)),
      signing: b64url(Buffer.from(signingProof)),
    },
  }, {
    Authorization: `Bearer ${oidcToken}`,
    "Content-Type": "application/json",
  });

  if (res.statusCode !== 200 || !res.result) {
    throw new Error(
      `cert exchange failed (${res.statusCode}): ${JSON.stringify(res.result)}`,
    );
  }

  const result = res.result;

  if (!result.certificates?.mtls || !result.certificates?.signing) {
    throw new Error("response missing certificates");
  }

  // ── Outputs: certs + identity, NEVER private keys ──
  // Cert PEMs are public data (transmitted in TLS handshakes anyway).
  // The private keys exist only in this step's process memory.
  // For cross-step usage: each step runs the action independently
  // to get its own keypair + certs. No credential sharing.
  core.setOutput("notme_url", authorityUrl);
  core.setOutput("notme_cert", result.certificates.mtls);
  core.setOutput("notme_signing_cert", result.certificates.signing);
  core.setOutput("notme_identity", result.identity);
  core.setOutput("expires_at", result.expires_at.toString());

  core.info(
    `bridge cert pair issued: ${result.identity} ` +
      `(epoch ${result.authority.epoch}, key ${result.authority.key_id}, ` +
      `binding ${result.binding.slice(0, 8)}..., ` +
      `expires ${result.expires_at})`,
  );
  core.info(
    "note: private keys exist only in this step's memory — " +
      "downstream steps should run the action independently for their own keypair.",
  );
}

run().catch((err) => core.setFailed(err.message));
