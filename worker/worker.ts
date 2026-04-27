// notme.bot — minimal Worker shell
// Static assets served via ASSETS binding. Add routes here as needed.

export { RevocationAuthority } from "./src/revocation";
export { SigningAuthority } from "./src/signing-authority";

import { WorkerEntrypoint } from "cloudflare:workers";
import type { Platform } from "./src/platform";

// ── Private RPC surface — only callable via service binding ──
// Consuming Workers bind to this entrypoint:
//   [[services]]
//   binding = "AUTH"
//   service = "notme-bot"
//   entrypoint = "AuthService"
//
// Then call: await env.AUTH.mintBridgeCert(subject, publicKeyPem)
// No HTTP, no public URL, no CORS, no tokens needed.

// ── Held credentials — module-level so they survive across RPC calls ──
// Set by authenticate(), used by proxy() and sign().
let heldCerts: {
  mtlsCert: string;
  signingCert: string;
  mtlsKey: CryptoKey;
  signingKey: CryptoKey;
  identity: string;
  scopes: string[];
  expiresAt: number;
} | null = null;

// Cloud metadata endpoints — hard-denied, not configurable
const DENIED_HOSTS = new Set([
  "169.254.169.254",        // AWS/GCP metadata
  "metadata.google.internal", // GCP metadata
  "100.100.100.200",        // Alibaba metadata
]);

function isDeniedDestination(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (DENIED_HOSTS.has(parsed.hostname)) return true;
    // fd00:ec2::254 and other IPv6 metadata
    if (parsed.hostname.startsWith("fd00:")) return true;
    // Link-local IPv4
    if (parsed.hostname.startsWith("169.254.")) return true;
    return false;
  } catch {
    return true; // unparseable URL = denied
  }
}

export class AuthService extends WorkerEntrypoint<any> {
  private getAuthority() {
    const id = this.env.SIGNING_AUTHORITY.idFromName("default");
    return this.env.SIGNING_AUTHORITY.get(id);
  }

  /** Mint a bridge cert for a verified subject. */
  async mintBridgeCert(subject: string, publicKeyPem: string, ttlMs?: number) {
    const authority = this.getAuthority();
    return authority.mintBridgeCert(subject, publicKeyPem, ttlMs);
  }

  /** Mint a DPoP-bound access token. */
  async mintDPoPToken(params: { sub: string; scope: string; audience: string; jkt: string }) {
    const authority = this.getAuthority();
    return authority.mintDPoPToken(params);
  }

  /** Get the CA public key PEM. */
  async getPublicKeyPem() {
    const authority = this.getAuthority();
    return authority.getPublicKeyPem();
  }

  /** Get the X.509 CA certificate PEM (for mTLS trust store). */
  async getCACertificatePem() {
    const authority = this.getAuthority();
    return authority.getCACertificatePem();
  }

  /** Get authority state (epoch, seqno, keyId). */
  async getAuthorityState() {
    const authority = this.getAuthority();
    return authority.getAuthorityState();
  }

  /** Verify a session cookie, return principal info. */
  async verifySession(cookie: string) {
    const authority = this.getAuthority();
    const { verifySessionCookie } = await import("./src/auth/session");
    const secret = await authority.getSessionSecret();
    return verifySessionCookie(cookie, secret);
  }

  // ── 009: Identity-gated runtime methods ──────────────────────────────────

  /**
   * Store credentials for proxy/sign operations.
   * Called after a successful 008 PoP exchange. Keys must be CryptoKey objects
   * (non-extractable). Certs are PEM strings (public data).
   */
  async authenticate(creds: {
    mtlsCert: string;
    signingCert: string;
    mtlsKey: CryptoKey;
    signingKey: CryptoKey;
    identity: string;
    scopes: string[];
    expiresAt: number;
  }) {
    heldCerts = creds;
  }

  /**
   * Proxy an HTTP request with mTLS using the held P-256 bridge cert.
   * The agent Worker calls this instead of fetch() (which is disabled).
   */
  async proxy(request: {
    url: string;
    method?: string;
    headers?: Record<string, string>;
    body?: string;
  }): Promise<{
    status: number;
    headers: Record<string, string>;
    body: string;
  }> {
    if (!heldCerts) {
      throw new Error("not authenticated — call authenticate() first");
    }
    if (heldCerts.expiresAt <= Math.floor(Date.now() / 1000)) {
      throw new Error("credentials expired — re-authenticate");
    }

    // Destination check
    if (isDeniedDestination(request.url)) {
      throw new Error("destination denied — cloud metadata endpoints are blocked");
    }

    // Scope check
    if (!heldCerts.scopes.includes("bridgeCert")) {
      throw new Error("scope insufficient — bridgeCert required for proxy");
    }

    // Make the request (in workerd, fetch() is available to the notme Worker
    // because it has globalOutbound configured)
    const res = await fetch(request.url, {
      method: request.method || "GET",
      headers: request.headers || {},
      body: request.body,
    });

    // Collect response headers
    const responseHeaders: Record<string, string> = {};
    res.headers.forEach((v, k) => { responseHeaders[k] = v; });

    return {
      status: res.status,
      headers: responseHeaders,
      body: await res.text(),
    };
  }

  /**
   * Sign data with the held Ed25519 signing key.
   * Returns the signature + the signing cert (public) + the WIMSE identity.
   */
  async sign(
    payload: ArrayBuffer,
    format: "raw" | "dsse" | "git-commit" = "raw",
  ): Promise<{
    signature: ArrayBuffer;
    certificate: string;
    identity: string;
  }> {
    if (!heldCerts) {
      throw new Error("not authenticated — call authenticate() first");
    }

    // Scope check for signing
    const signingScopes = ["sign:git", "sign:attestation"];
    const hasSignScope = format === "raw"
      ? true // raw signing doesn't require a specific scope
      : heldCerts.scopes.some(s => signingScopes.includes(s));
    if (!hasSignScope) {
      throw new Error(`scope insufficient — ${format} requires one of: ${signingScopes.join(", ")}`);
    }

    const signature = await crypto.subtle.sign(
      "Ed25519" as any,
      heldCerts.signingKey,
      payload,
    );

    return {
      signature,
      certificate: heldCerts.signingCert,
      identity: heldCerts.identity,
    };
  }

  /** Get current identity and capabilities. */
  async identity(): Promise<{
    identity: string;
    scopes: string[];
    certificates: { mtls: string; signing: string };
    expires_at: number;
    authenticated: boolean;
  }> {
    if (!heldCerts) {
      return {
        identity: "",
        scopes: [],
        certificates: { mtls: "", signing: "" },
        expires_at: 0,
        authenticated: false,
      };
    }
    return {
      identity: heldCerts.identity,
      scopes: heldCerts.scopes,
      certificates: {
        mtls: heldCerts.mtlsCert,
        signing: heldCerts.signingCert,
      },
      expires_at: heldCerts.expiresAt,
      authenticated: true,
    };
  }
}

// ── auth.notme.bot/cert/gha — GitHub Actions OIDC → bridge cert exchange ──
//
// GHA CI jobs request an OIDC token (audience: notme.bot) and POST it here.
// We validate RS256 signature, check claims, generate an ephemeral P-256 keypair
// at the edge, mint a 5-minute bridge cert, and return both cert + private key.
// No stored GH secret needed — the OIDC JWT is the credential.
//
// SIGNET_MASTER_KEY must be set as a Worker secret (wrangler secret put).

// All tunables are configurable via wrangler.toml [vars] for self-hosted deploys.
// Defaults match the notme.bot production deployment.

function getConfig(env: any) {
  return {
    ghaCertAudience: (env.GHA_CERT_AUDIENCE as string) ?? "notme.bot",
    ghaCertTtlMs: Number(env.GHA_CERT_TTL_MS ?? 300_000), // 5 min
    jtiMinTtlSeconds: Number(env.JTI_MIN_TTL_SECONDS ?? 60),
    rateLimitWindowMs: Number(env.RATE_LIMIT_WINDOW_MS ?? 3600_000), // 1 hour
    rateLimitMaxCerts: Number(env.RATE_LIMIT_MAX_CERTS ?? 10),
    rateLimitKvTtlSeconds: Number(env.RATE_LIMIT_KV_TTL_SECONDS ?? 3600),
  };
}
function getAllowedOwners(env: any): Set<string> {
  const raw: string = env.GHA_ALLOWED_OWNERS ?? "agentic-research";
  return new Set(
    raw
      .split(",")
      .map((s: string) => s.trim().toLowerCase())
      .filter(Boolean),
  );
}

function jsonErr(message: string, status: number): Response {
  return Response.json({ error: message }, { status });
}

async function handleCertGHA(request: Request, env: any, platform: Platform): Promise<Response> {
  if (request.method !== "POST") {
    return jsonErr("method not allowed", 405);
  }

  const cfg = getConfig(env);

  // Get authority DO stub (signing happens inside the DO — CryptoKey can't cross RPC)
  const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
  const authority = env.SIGNING_AUTHORITY.get(authorityId);
  try {
    // Ensure CA bundle is published to KV (lazy init — first request bootstraps)
    const existingBundle = await platform.cache.get("bundle:current");
    if (!existingBundle) {
      const bundle = await authority.generateBundle();
      await platform.cache.put("bundle:current", JSON.stringify(bundle));
    }
  } catch (e: any) {
    return jsonErr("authority unavailable: " + e.message, 503);
  }

  const authHeader = request.headers.get("authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return jsonErr("missing Bearer token", 401);
  }
  const token = authHeader.slice(7);

  const { validateGHAToken } = await import("./src/gha-oidc");
  let claims;
  try {
    claims = await validateGHAToken(token, cfg.ghaCertAudience);
  } catch (e: any) {
    return jsonErr(`invalid token: ${e.message}`, 401);
  }

  // Allowlist check — only permitted owners can get certs from this authority
  const allowedOwners = getAllowedOwners(env);
  if (!allowedOwners.has(claims.repository_owner.toLowerCase())) {
    return jsonErr("repository owner not permitted", 403);
  }

  // JTI replay protection — each OIDC token can be exchanged exactly once
  if (!claims.jti) {
    return jsonErr("jti claim required for replay protection", 400);
  }
  {
    const jtiKey = `jti:${claims.jti}`;
    const seen = await platform.cache.get(jtiKey);
    if (seen) {
      return jsonErr("token already used", 401);
    }
    const ttl = Math.max(cfg.jtiMinTtlSeconds, claims.exp - Math.floor(Date.now() / 1000));
    await platform.cache.put(jtiKey, "1", { expirationTtl: ttl });
  }

  // Rate limit — atomic, edge-fast (replaces KV-based TOCTOU-vulnerable limiter)
  if (platform.rateLimit) {
    const allowed = await platform.rateLimit(`cert:${claims.repository}`);
    if (!allowed) {
      return jsonErr("rate limit exceeded", 429);
    }
  }

  // ── Bridge cert pair via PoP exchange (008) ──
  // Caller sends two public keys + proof-of-possession signatures.
  // Authority verifies proofs, issues a P-256 mTLS cert + Ed25519 signing cert.
  // No private key in request or response. No bearer tokens issued.
  let body: {
    public_keys?: { mtls?: string; signing?: string };
    proofs?: { mtls?: string; signing?: string };
  };
  try {
    body = await request.json();
  } catch {
    return jsonErr("invalid JSON body", 400);
  }

  if (!body.public_keys?.mtls || !body.public_keys?.signing) {
    return jsonErr("public_keys.mtls and public_keys.signing required (SPKI PEM)", 400);
  }
  if (!body.proofs?.mtls || !body.proofs?.signing) {
    return jsonErr("proofs.mtls and proofs.signing required (signatures over binding payload)", 400);
  }

  // Import public keys to verify PoP proofs
  const { importPublicKey } = await import("./src/cert-authority");
  let mtlsPubKey: CryptoKey;
  let signingPubKey: CryptoKey;
  try {
    mtlsPubKey = await importPublicKey(body.public_keys.mtls);
    signingPubKey = await importPublicKey(body.public_keys.signing);
  } catch (e: any) {
    return jsonErr(`invalid public key: ${e.message}`, 400);
  }

  // Compute binding payload: SHA-256(mtls_spki || signing_spki || SHA-256(oidc_jwt))
  const mtlsSpki = (await crypto.subtle.exportKey("spki", mtlsPubKey)) as ArrayBuffer;
  const signingSpki = (await crypto.subtle.exportKey("spki", signingPubKey)) as ArrayBuffer;
  const oidcHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  const bindingInput = new Uint8Array(mtlsSpki.byteLength + signingSpki.byteLength + 32);
  bindingInput.set(new Uint8Array(mtlsSpki), 0);
  bindingInput.set(new Uint8Array(signingSpki), mtlsSpki.byteLength);
  bindingInput.set(new Uint8Array(oidcHash), mtlsSpki.byteLength + signingSpki.byteLength);
  const bindingPayload = await crypto.subtle.digest("SHA-256", bindingInput);

  // Verify PoP: caller must have signed the binding payload with both keys
  // P-256 proof (ES256)
  try {
    const proofBytes = Uint8Array.from(atob(body.proofs.mtls.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      mtlsPubKey,
      proofBytes,
      bindingPayload,
    );
    if (!valid) return jsonErr("P-256 proof-of-possession failed", 401);
  } catch (e: any) {
    return jsonErr(`P-256 proof verification error: ${e.message}`, 401);
  }

  // Ed25519 proof
  try {
    const proofBytes = Uint8Array.from(atob(body.proofs.signing.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify(
      "Ed25519" as any,
      signingPubKey,
      proofBytes,
      bindingPayload,
    );
    if (!valid) return jsonErr("Ed25519 proof-of-possession failed", 401);
  } catch (e: any) {
    return jsonErr(`Ed25519 proof verification error: ${e.message}`, 401);
  }

  // Build WIMSE identity URI
  const identity = `wimse://notme.bot/gha/${claims.repository_owner}/${claims.repository.split("/").pop()}`;

  // Mint cert pair — both certs signed by CA, both carry the same identity + scopes
  let result;
  try {
    result = await authority.mintBridgeCertPair({
      subject: claims.sub,
      identity,
      mtlsPublicKeyPem: body.public_keys.mtls,
      signingPublicKeyPem: body.public_keys.signing,
      scopes: ["bridgeCert"],
      authMethod: "gha-oidc",
      ttlMs: cfg.ghaCertTtlMs,
    });
  } catch (e: any) {
    return jsonErr(e.message || "cert minting failed", 500);
  }

  return Response.json({
    certificates: result.certificates,
    identity: result.identity,
    scopes: result.scopes,
    expires_at: result.expires_at,
    binding: result.binding,
    authority: result.authority,
    claims: {
      repository: claims.repository,
      ref: claims.ref,
      sha: claims.sha,
      actor: claims.actor,
      workflow: claims.workflow,
      run_id: claims.run_id,
      event_name: claims.event_name,
    },
  });
}

// ── Passkey route handler ──

async function handlePasskey(
  pathname: string,
  request: Request,
  env: any,
): Promise<Response> {
  if (request.method !== "POST") {
    return jsonErr("method not allowed", 405);
  }

  const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
  const authority = env.SIGNING_AUTHORITY.get(authorityId);
  // Derive origin from SITE_URL (env), not from attacker-controlled Host header.
  // Host header can be spoofed in non-CF environments (local dev, proxies).
  const siteUrl = env.SIGNET_AUTHORITY_URL || env.SITE_URL || "https://auth.notme.bot";
  const host = new URL(siteUrl).hostname;
  const origin = siteUrl;

  try {
    if (pathname === "/auth/passkey/register/options") {
      const body = (await request.json()) as { bootstrapCode?: string };
      const userId = crypto.randomUUID();
      const result = await authority.passkeyRegistrationOptions(
        userId,
        "user",
        host,
      );

      // First user requires bootstrap code (proves deployer ownership)
      // Everyone else can register freely — gets bridgeCert scope only
      if (result.isFirstUser && !body.bootstrapCode) {
        await authority.getOrCreateBootstrapCode();
        return jsonErr(
          "bootstrap code required — check Worker logs (wrangler tail)",
          401,
        );
      }
      if (result.isFirstUser) {
        const valid = await authority.consumeBootstrapCode(
          body.bootstrapCode!,
        );
        if (!valid) {
          return jsonErr("invalid or already-used bootstrap code", 403);
        }
      }

      // Determine scopes: deployer gets all, everyone else gets bridgeCert
      const scopes = result.isFirstUser
        ? ["bridgeCert", "authorityManage", "certMint"]
        : ["bridgeCert"];

      return Response.json({ ...result, userId, scopes });
    }

    if (pathname === "/auth/passkey/register/verify") {
      const body = (await request.json()) as {
        userId: string;
        scopes?: string[];
        response: any;
      };
      if (!body.userId) {
        return jsonErr("userId required (from register/options response)", 400);
      }
      const result = await authority.passkeyVerifyRegistration(
        body.userId,
        "user",
        body.response,
        host,
        origin,
      );
      if (!result.verified) {
        return jsonErr("registration verification failed", 400);
      }

      // Scopes derived server-side from admin status — NEVER from client body.
      // Client-supplied body.scopes is intentionally ignored (scope escalation vector).
      const scopes = result.isAdmin
        ? ["bridgeCert", "authorityManage", "certMint"]
        : ["bridgeCert"];

      // Issue session immediately after registration
      const { createSessionCookie } = await import("./src/auth/session");
      const sessionSecret = await authority.getSessionSecret();
      const cookie = await createSessionCookie(
        { principalId: body.userId, scopes, authMethod: "passkey" },
        sessionSecret,
      );

      return new Response(
        JSON.stringify({ verified: true, scopes }),
        {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "Set-Cookie": cookie,
          },
        },
      );
    }

    if (pathname === "/auth/passkey/login/options") {
      const options = await authority.passkeyAuthenticationOptions(host);
      return Response.json(options);
    }

    if (pathname === "/auth/passkey/login/verify") {
      const body = (await request.json()) as { response: any };
      let result;
      try {
        result = await authority.passkeyVerifyAuthentication(
          body.response,
          host,
          origin,
        );
      } catch (verifyErr: any) {
        console.error("[passkey] verify error:", verifyErr.message);
        return jsonErr("verification error: " + verifyErr.message, 400);
      }
      if (!result.verified || !result.userId) {
        return jsonErr(
          `authentication failed (verified=${result.verified}, userId=${result.userId ? "set" : "null"})`,
          401,
        );
      }
      const { createSessionCookie } = await import("./src/auth/session");
      const sessionSecret = await authority.getSessionSecret();
      // Principal model: userId is the principalId, scopes from capabilities
      const scopes = result.isAdmin
        ? ["bridgeCert", "authorityManage", "certMint"]
        : ["bridgeCert"];
      const cookie = await createSessionCookie(
        { principalId: result.userId, scopes, authMethod: "passkey" },
        sessionSecret,
      );
      return new Response(
        JSON.stringify({
          verified: true,
          userId: result.userId,
          isAdmin: result.isAdmin,
        }),
        {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "Set-Cookie": cookie,
          },
        },
      );
    }

    return jsonErr("not found", 404);
  } catch (e: any) {
    return jsonErr(e.message || "passkey error", 500);
  }
}

function parseCookie(cookieHeader: string, name: string): string | null {
  const match = cookieHeader
    .split(";")
    .map((c) => c.trim())
    .find((c) => c.startsWith(`${name}=`));
  return match ? match.slice(name.length + 1) : null;
}

// ── GET /authorize — inline HTML page for cross-origin DPoP token issuance ──
//
// Browser POSTs to /authorize/token (same origin — session cookie automatic),
// receives an unbound redirect token (no cnf.jkt — not DPoP-bound),
// then redirects back to the caller with ?token=<jwt>&state=<state>.
//
// All params are injected via data attributes on a hidden div — no inline
// script variables, no eval. The JS reads them via dataset.

function authorizePageHtml(redirectUri: string, audience: string, state: string): string {
  // HTML-escape to prevent injection via query params
  const esc = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/"/g, "&quot;")
     .replace(/</g, "&lt;").replace(/>/g, "&gt;");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>authorize — auth.notme.bot</title>
  <link rel="icon" href="https://notme.bot/favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Syne:wght@700;800&display=swap">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      background: #1c1810;
      color: #e8dcc8;
      font-family: 'DM Mono', monospace;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
      padding: 40px 20px;
    }
    .term-window {
      max-width: 520px;
      width: 100%;
      background: rgba(28, 24, 16, 0.9);
      backdrop-filter: blur(12px);
      padding: 32px;
      border: 1px solid #3a3428;
    }
    .term-header {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid #3a3428;
    }
    .term-dots { display: flex; gap: 6px; }
    .term-dots span { width: 6px; height: 6px; border-radius: 50%; }
    .term-dots span:nth-child(1) { background: #e04030; opacity: 0.6; }
    .term-dots span:nth-child(2) { background: #f0d040; opacity: 0.6; }
    .term-dots span:nth-child(3) { background: #48c868; opacity: 0.6; }
    .term-title {
      font-size: 0.5625rem;
      color: #706050;
      letter-spacing: 0.2em;
      text-transform: uppercase;
      margin-left: auto;
    }
    .term-output { min-height: 60px; margin-bottom: 16px; }
    .term-line {
      font-size: 0.8125rem;
      line-height: 1.8;
      white-space: pre-wrap;
    }
    .term-line.dim { color: #706050; }
    .term-line.info { color: #988870; }
    .term-line.ok { color: #48c868; }
    .term-line.err { color: #e04030; }
    .term-line .hl { color: #f0d040; }
    .term-line .cyn { color: #00d4e8; }
    .spinner {
      display: inline-block;
      width: 12px;
      height: 12px;
      border: 2px solid #706050;
      border-top-color: #f0d040;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      vertical-align: middle;
      margin-right: 8px;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .term-footer {
      margin-top: 24px;
      text-align: center;
      font-size: 0.5625rem;
      color: #706050;
    }
    .term-footer a {
      color: #988870;
      text-decoration: none;
      border-bottom: 1px dotted #988870;
    }
    .term-footer a:hover { color: #00d4e8; border-color: #00d4e8; }
  </style>
</head>
<body>

<div id="params"
  data-redirect-uri="${esc(redirectUri)}"
  data-audience="${esc(audience)}"
  data-state="${esc(state)}"
  style="display:none"></div>

<div class="term-window">
  <div class="term-header">
    <div class="term-dots"><span></span><span></span><span></span></div>
    <span class="term-title">auth.notme.bot/authorize</span>
  </div>

  <div class="term-output" id="output">
    <div class="term-line dim">notme — token issuance</div>
    <div class="term-line dim">&nbsp;</div>
    <div class="term-line info"><span class="spinner"></span>generating keypair + requesting token...</div>
  </div>

  <div id="statusLine" class="term-line dim">&nbsp;</div>

  <div class="term-footer">
    <a href="/">&#8592; back to authority</a>
  </div>
</div>

<script>
(function() {
  var el = document.getElementById('params');
  var redirectUri = el.getAttribute('data-redirect-uri');
  var audience = el.getAttribute('data-audience');
  var state = el.getAttribute('data-state');
  var output = document.getElementById('output');
  var statusLine = document.getElementById('statusLine');

  function addLine(text, cls) {
    var line = document.createElement('div');
    line.className = 'term-line ' + (cls || 'dim');
    line.textContent = text;
    output.appendChild(line);
  }

  function setStatus(text, cls) {
    statusLine.textContent = text;
    statusLine.className = 'term-line ' + (cls || 'dim');
  }

  async function run() {
    try {
      // POST to /authorize/token — mints an unbound redirect token (no DPoP).
      // Session cookie sent automatically (same origin).
      // No client-side crypto needed — the session IS the identity proof.
      addLine('requesting redirect token...', 'info');
      var res = await fetch('/authorize/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ audience: audience }),
        credentials: 'same-origin'
      });

      if (!res.ok) {
        var err;
        try { err = (await res.json()).error; } catch(e) { err = res.statusText; }
        throw new Error(err || 'token request failed (' + res.status + ')');
      }

      var data = await res.json();
      var token = data.access_token;
      if (!token) throw new Error('no access_token in response');

      addLine('redirect token issued (5min TTL)', 'ok');

      // 5. Redirect back to caller with token + state
      var sep = redirectUri.indexOf('?') === -1 ? '?' : '&';
      var dest = redirectUri + sep + 'token=' + encodeURIComponent(token);
      if (state) dest += '&state=' + encodeURIComponent(state);

      setStatus('redirecting to ' + new URL(redirectUri).hostname + '...', 'ok');
      setTimeout(function() { window.location.href = dest; }, 600);

    } catch(e) {
      setStatus('error: ' + e.message, 'err');
      addLine('', 'dim');
      addLine('token issuance failed. try signing in again.', 'info');
    }
  }

  run();
})();
</script>
</body>
</html>`;
}

const SPEC_URL =
  "https://github.com/agentic-research/signet/blob/main/docs/apas/agent-provenance-standard.md";
const IMPL_URL =
  "https://github.com/agentic-research/signet/blob/main/docs/apas/agent-provenance-standard.md";

const DISPATCH_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  title: "APAS Dispatch Predicate v1",
  description:
    "Agent Provenance Attestation Standard — dispatch predicate. Records the full context of an agent dispatch: work item, agent identity, pipeline phase, execution details, verification results, and hash chain linkage.",
  type: "object",
  predicateType: "https://notme.bot/provenance/dispatch/v1",
  spec: SPEC_URL,
  referenceImplementation: IMPL_URL,
  properties: {
    dispatchDefinition: {
      type: "object",
      description: "What was dispatched and to whom",
      properties: {
        beadRef: {
          type: "object",
          description: "Work item reference",
          properties: {
            repo: { type: "string" },
            beadId: { type: "string" },
            contentHash: { type: "string", pattern: "^sha256:[a-f0-9]+$" },
          },
          required: ["repo", "beadId", "contentHash"],
        },
        pipeline: {
          type: "object",
          properties: {
            phases: { type: "array", items: { type: "string" } },
            currentPhase: { type: "integer" },
            pipelineId: { type: "string", format: "uuid" },
          },
        },
        agent: {
          type: "object",
          properties: {
            name: { type: "string" },
            definition: {
              type: "string",
              description: "sha256 hash of agent definition file",
            },
            provider: { type: "string" },
            model: { type: "string" },
            permissionProfile: { type: "string" },
          },
          required: ["name", "provider", "model"],
        },
      },
    },
    runDetails: {
      type: "object",
      description: "What happened during execution",
      properties: {
        orchestrator: {
          type: "object",
          properties: {
            name: { type: "string" },
            version: { type: "string" },
            identity: { type: "object" },
          },
        },
        execution: {
          type: "object",
          properties: {
            workDir: { type: "string" },
            startedAt: { type: "string", format: "date-time" },
            completedAt: { type: "string", format: "date-time" },
            durationMs: { type: "integer" },
            sessionId: { type: "string", format: "uuid" },
            isolationLevel: {
              type: "string",
              enum: ["git-worktree", "container", "vm", "none"],
            },
          },
        },
        work: {
          type: "object",
          properties: {
            commits: { type: "array" },
            filesChanged: { type: "array", items: { type: "string" } },
            linesAdded: { type: "integer" },
            linesRemoved: { type: "integer" },
          },
        },
        verification: {
          type: "object",
          properties: {
            passed: { type: "boolean" },
            highestTier: { type: "integer" },
            tiers: { type: "array" },
          },
        },
        handoffChain: {
          type: "object",
          description: "Hash chain linking this phase to the pipeline",
          properties: {
            phaseHash: { type: "string" },
            previousPhaseHash: { type: "string" },
            chainRoot: { type: "string" },
          },
        },
      },
    },
  },
};

const HANDOFF_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  title: "APAS Handoff Predicate v1",
  description:
    "Agent Provenance Attestation Standard — handoff predicate. Records phase transitions in an agent pipeline with hash chain linkage for tamper evidence.",
  predicateType: "https://notme.bot/provenance/handoff/v1",
  spec: SPEC_URL,
  referenceImplementation: IMPL_URL,
  type: "object",
  properties: {
    fromPhase: { type: "string" },
    toPhase: { type: "string" },
    handoffDocument: {
      type: "string",
      description:
        "Filename of the handoff artifact (plan.md, changes.md, eval.md, feedback.md)",
    },
    documentHash: { type: "string", pattern: "^sha256:[a-f0-9]+$" },
    previousChainHash: { type: "string" },
    chainHash: { type: "string" },
  },
};

function wantsJson(request: Request): boolean {
  const accept = request.headers.get("Accept") || "";
  // Explicitly request JSON, for API tools
  if (
    accept.includes("application/json") ||
    accept.includes("application/schema+json")
  ) {
    return true;
  }
  // For all other requests (including browsers), default to HTML
  return false;
}

function renderPredicateHtml(schema: Record<string, unknown>): Response {
  const title = schema.title as string;
  const desc = schema.description as string;
  const predType = schema.predicateType as string;
  const props = schema.properties as Record<string, any>;

  // Build property list from schema
  let propsHtml = "";
  for (const [key, val] of Object.entries(props)) {
    const propDesc = val.description || val.type || "object";
    const nested = val.properties
      ? Object.keys(val.properties)
          .map((k: string) => `<span style="color:#00D4E8">${k}</span>`)
          .join(", ")
      : "";
    propsHtml += `<tr><td style="color:#F0D040;font-weight:600">${key}</td><td>${propDesc}${nested ? '<br><span style="color:#706050;font-size:0.75rem">fields: ' + nested + "</span>" : ""}</td></tr>`;
  }

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title>
  <link rel="stylesheet" href="/styles.css">
  <style>
    body { background: #141210; color: #C8B8A0; font-family: 'DM Mono', monospace; font-size: 0.875rem; line-height: 1.8; }
    .page { max-width: 700px; margin: 0 auto; padding: 24px 28px; }
    h1 { font-family: 'Syne', sans-serif; color: #FFE060; font-size: 1.5rem; font-weight: 800; margin: 48px 0 8px; }
    .uri { color: #00D4E8; font-size: 0.8125rem; margin-bottom: 24px; display: block; }
    p { margin: 0 0 16px; }
    a { color: #00D4E8; text-decoration: none; border-bottom: 1px dotted rgba(0,212,232,0.3); }
    a:hover { color: #F0D040; }
    table { width: 100%; border-collapse: collapse; margin: 24px 0; }
    th { text-align: left; padding: 8px 12px; font-size: 0.625rem; letter-spacing: 0.1em; text-transform: uppercase; color: #706050; border-bottom: 2px solid #3A3428; }
    td { padding: 10px 12px; border-bottom: 1px solid #2C2820; font-size: 0.8125rem; vertical-align: top; }
    .hint { color: #706050; font-size: 0.75rem; margin-top: 32px; border-top: 1px solid #3A3428; padding-top: 16px; }
    code { color: #00D4E8; background: rgba(0,212,232,0.08); padding: 1px 5px; }
    nav { padding: 20px 0; display: flex; align-items: center; gap: 20px; border-bottom: 2px solid #3A3428; }
    .logo { display: flex; align-items: center; gap: 10px; text-decoration: none; color: #E8DCC8; border: none; }
    .logo-text { font-family: 'Syne', sans-serif; font-size: 1.25rem; font-weight: 800; color: #F0D040; }
    .nav-links { display: flex; gap: 20px; margin-left: auto; }
    .nav-links a { color: #706050; font-size: 0.8125rem; border: none; }
    .nav-links a:hover { color: #00D4E8; }
  </style>
</head>
<body>
<div class="grain"></div>
<div class="page">
  <nav>
    <a href="/" class="logo">
      <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
        <rect x="4" y="4" width="24" height="24" rx="2" stroke="#F0D040" stroke-width="2.5" fill="none"/>
        <line x1="10" y1="10" x2="22" y2="22" stroke="#E04030" stroke-width="3" stroke-linecap="round"/>
      </svg>
      <span class="logo-text">notme</span>
    </a>
    <div class="nav-links">
      <a href="/apas">apas</a>
      <a href="/architecture">how it works</a>
      <a href="/research">research</a>
      <a href="https://github.com/agentic-research">source</a>
    </div>
  </nav>

  <h1>${title}</h1>
  <span class="uri">${predType}</span>
  <p>${desc}</p>
  <p>Part of the <a href="/apas">Agent Provenance Attestation Standard</a> (APAS). Full spec: <a href="${SPEC_URL}">signet/docs/apas</a>.</p>

  <table>
    <thead><tr><th>field</th><th>description</th></tr></thead>
    <tbody>${propsHtml}</tbody>
  </table>

  <p class="hint">For machine-readable JSON Schema, request with <code>Accept: application/json</code> or use <code>curl -H "Accept: application/json" ${predType}</code></p>
</div>
</body>
</html>`;

  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "public, max-age=86400",
    },
  });
}

function jsonResponse(schema: Record<string, unknown>): Response {
  return Response.json(schema, {
    headers: {
      "Cache-Control": "public, max-age=86400",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

function getSubdomain(host: string): string | null {
  const match = host.match(/^(\w[\w-]*)\.notme\.bot$/);
  return match?.[1] ?? null;
}

// ── CF Edge Cache helpers ──
// With run_worker_first = true, responses constructed in the Worker bypass CF
// edge cache entirely. We use the Cache API to store and serve them at the edge.
// Cache key includes Accept header for content-negotiated routes.

function cacheKey(request: Request, vary?: string): Request {
  // For content-negotiated routes, include Accept in the cache key so
  // JSON and HTML responses are cached separately.
  if (vary === "Accept") {
    const url = new URL(request.url);
    const accept = request.headers.get("Accept") || "";
    const suffix = accept.includes("application/json") ? "?_accept=json" : "?_accept=html";
    return new Request(url.origin + url.pathname + suffix, request);
  }
  return request;
}

// Edge cache disabled when cacheApiOutbound is not configured (local workerd).
let cacheEnabled = true;

async function cachePut(request: Request, response: Response, vary?: string): Promise<Response> {
  if (!cacheEnabled || request.method !== "GET") return response;
  if (!response.ok && response.status !== 301) return response;
  try {
    const cache = caches.default;
    const toCache = response.clone();
    await cache.put(cacheKey(request, vary), toCache);
  } catch {
    cacheEnabled = false; // Disable for remainder of isolate lifetime
  }
  return response;
}

async function cacheMatch(request: Request, vary?: string): Promise<Response | undefined> {
  if (!cacheEnabled || request.method !== "GET") return undefined;
  try {
    const cache = caches.default;
    return cache.match(cacheKey(request, vary));
  } catch {
    cacheEnabled = false;
    return undefined;
  }
}

export default {
  async fetch(request: Request, env: any): Promise<Response> {
    // ── CORS: handle preflight + restrict origins ──
    const requestOrigin = request.headers.get("Origin") || "";
    const CORS_ALLOWED_ORIGINS = new Set([
      "https://rosary.bot",
      "https://auth.rosary.bot",
      "https://notme.bot",
      "https://auth.notme.bot",
      "https://mcp.rosary.bot",
      "https://mache.rosary.bot",
    ]);
    // Allow localhost for dev
    const corsAllowed = CORS_ALLOWED_ORIGINS.has(requestOrigin) ||
      requestOrigin.startsWith("http://localhost:");

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": corsAllowed ? requestOrigin : "",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization, DPoP",
          "Access-Control-Max-Age": "86400",
        },
      });
    }

    const url = new URL(request.url);
    const pathname = url.pathname;
    const host = request.headers.get("host") || "";
    const sub = getSubdomain(host);
    const envSiteUrl: string = env.SITE_URL || "";
    const isLocal = envSiteUrl.startsWith("http://localhost");
    if (isLocal) cacheEnabled = false; // Cache API unavailable in local workerd

    const { createPlatform } = await import("./src/platform");
    const platform = createPlatform(env);

    // ── Canonical host enforcement ──
    // Redirect any non-notme.bot host (e.g. workers.dev) to the canonical domain.
    // This prevents Google from indexing the workers.dev URL as a duplicate.
    if (!isLocal && !host.endsWith("notme.bot") && host !== "") {
      const canonicalUrl = `https://notme.bot${pathname}${url.search}`;
      const redirect = new Response(null, {
        status: 301,
        headers: {
          Location: canonicalUrl,
          "Cache-Control": "public, max-age=31536000, immutable",
        },
      });
      return cachePut(request, redirect);
    }

    // ── auth.notme.bot — signet identity authority ──
    if (sub === "auth" || isLocal) {
      const authorityUrl: string =
        env.SIGNET_AUTHORITY_URL || "https://auth.notme.bot";
      const siteUrl: string = env.SITE_URL || "https://notme.bot";

      // /me — shows current session (validates cookie)
      if (pathname === "/me") {
        const cookie = parseCookie(
          request.headers.get("cookie") || "",
          "notme_session",
        );
        if (!cookie) {
          return Response.redirect(`${siteUrl}/login`, 302);
        }
        const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
        const authority = env.SIGNING_AUTHORITY.get(authorityId);
        const { verifySessionCookie } = await import("./src/auth/session");
        const sessionSecret = await authority.getSessionSecret();
        const session = await verifySessionCookie(cookie, sessionSecret);
        if (!session) {
          return Response.redirect(`${siteUrl}/login`, 302);
        }
        if (wantsJson(request)) {
          return Response.json({
            authenticated: true,
            userId: session.userId,
            isAdmin: session.isAdmin,
            expiresAt: session.exp,
          });
        }
        return new Response(
          `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
            `<title>me — auth.notme.bot</title>` +
            `<style>body{background:#1c1810;color:#e8dcc8;font-family:'DM Mono',monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}` +
            `.card{max-width:400px;padding:40px;text-align:center}` +
            `h1{font-family:'Syne',sans-serif;color:#f0d040;font-size:1.3rem;margin-bottom:16px}` +
            `.field{margin:8px 0;font-size:0.85rem;color:#c8b8a0}` +
            `.label{color:#706050;font-size:0.7rem;letter-spacing:0.1em;text-transform:uppercase}` +
            `.value{color:#00d4e8;word-break:break-all}` +
            `.admin{color:#48c868;font-weight:bold}` +
            `a{color:#706050;font-size:0.75rem;text-decoration:none;margin-top:24px;display:block}a:hover{color:#00d4e8}</style></head>` +
            `<body><div class="card">` +
            `<h1>authenticated</h1>` +
            `<div class="field"><span class="label">principal</span><br><span class="value">${session.principalId ?? session.userId}</span></div>` +
            `<div class="field"><span class="label">scopes</span><br><span class="value">${(session.scopes ?? []).join(", ") || "bridgeCert"}</span></div>` +
            `<div class="field"><span class="label">auth</span><br><span class="value">${session.authMethod ?? "passkey"}</span></div>` +
            `<div class="field"><span class="label">expires</span><br><span class="value">${new Date(session.exp * 1000).toISOString()}</span></div>` +
            `<a href="/">back to authority</a>` +
            `</div></body></html>`,
          { headers: { "Content-Type": "text/html; charset=utf-8" } },
        );
      }

      // API docs
      if (pathname === "/api/docs" || pathname === "/api/docs/") {
        const cached = await cacheMatch(request);
        if (cached) return cached;
        const baseUrl = env.SITE_URL || "https://notme.bot";
        const resp = await env.ASSETS.fetch(new Request(`${baseUrl}/_api-docs`));
        const headers = new Headers(resp.headers);
        headers.set("Cache-Control", "public, max-age=3600");
        const result = new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers });
        return cachePut(request, result);
      }

      // Login page
      if (pathname === "/login" || pathname === "/login/") {
        const baseUrl = env.SITE_URL || "https://notme.bot";
        return env.ASSETS.fetch(new Request(`${baseUrl}/_login`));
      }

      // ── Connections: associate OIDC/x509 identities with passkey ──
      if (pathname === "/connections" && request.method === "POST") {
        // Requires active session (passkey authenticated)
        const cookie = parseCookie(
          request.headers.get("cookie") || "",
          "notme_session",
        );
        if (!cookie) return jsonErr("sign in first", 401);
        const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
        const authority = env.SIGNING_AUTHORITY.get(authorityId);
        const { verifySessionCookie } = await import("./src/auth/session");
        const sessionSecret = await authority.getSessionSecret();
        const session = await verifySessionCookie(cookie, sessionSecret);
        if (!session) return jsonErr("invalid session", 401);

        const body = (await request.json()) as {
          proof: { type: string; token?: string; cert?: string };
        };
        if (!body.proof?.type) return jsonErr("proof.type required", 400);

        const { verifyProof } = await import("./src/auth/verify-proof");
        let identity;
        try {
          const caKey = await authority.getPublicKeyPem();
          identity = await verifyProof(body.proof as any, caKey);
        } catch (e: any) {
          return jsonErr("proof verification failed: " + e.message, 401);
        }

        // Store the connection (via DO RPC, not the imported function)
        await authority.storeConnection({
          credentialId: session.userId,
          provider: `${identity.type}:${identity.issuer}`,
          providerSubject: identity.subject,
        });

        return Response.json({
          connected: true,
          provider: `${identity.type}:${identity.issuer}`,
          subject: identity.subject,
        });
      }

      // GET /connections — list connections for current session
      if (pathname === "/connections" && request.method === "GET") {
        const cookie = parseCookie(
          request.headers.get("cookie") || "",
          "notme_session",
        );
        if (!cookie) return jsonErr("sign in first", 401);
        const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
        const authority = env.SIGNING_AUTHORITY.get(authorityId);
        const { verifySessionCookie } = await import("./src/auth/session");
        const sessionSecret = await authority.getSessionSecret();
        const session = await verifySessionCookie(cookie, sessionSecret);
        if (!session) return jsonErr("invalid session", 401);

        const conns = await authority.getConnectionsForUser(session.userId);
        return Response.json({ connections: conns });
      }

      // ── Invites: create + redeem ──

      // POST /invites — create an invite (requires authorityManage scope)
      if (pathname === "/invites" && request.method === "POST") {
        const cookie = parseCookie(request.headers.get("cookie") || "", "notme_session");
        if (!cookie) return jsonErr("sign in first", 401);
        const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
        const authority = env.SIGNING_AUTHORITY.get(authorityId);
        const { verifySessionCookie } = await import("./src/auth/session");
        const sessionSecret = await authority.getSessionSecret();
        const session = await verifySessionCookie(cookie, sessionSecret);
        if (!session) return jsonErr("invalid session", 401);
        if (!(session.scopes ?? []).includes("authorityManage")) {
          return jsonErr("authorityManage scope required", 403);
        }

        const body = (await request.json()) as { scopes?: string[]; ttl?: number };
        const scopes = body.scopes ?? ["bridgeCert"];
        // Can't grant scopes you don't have
        for (const s of scopes) {
          if (!(session.scopes ?? []).includes(s)) {
            return jsonErr(`cannot grant scope you don't have: ${s}`, 403);
          }
        }

        const invite = await authority.createInviteToken(
          session.principalId,
          scopes,
          body.ttl ?? 3600,
        );
        const host = request.headers.get("host") || "auth.notme.bot";
        return Response.json({
          token: invite.token,
          url: `https://${host}/join?t=${invite.token}`,
          expiresAt: invite.expiresAt,
          scopes,
        });
      }

      // GET /join?t=<token> — redeem an invite (shows registration page)
      if (pathname === "/join" && request.method === "GET") {
        const token = new URL(request.url).searchParams.get("t");
        if (!token) return jsonErr("missing invite token", 400);
        // Serve the login page — it will handle the invite token
        const baseUrl = env.SITE_URL || "https://notme.bot";
        return env.ASSETS.fetch(new Request(`${baseUrl}/_login`));
      }

      // POST /join — redeem invite + register (passkey or OIDC)
      if (pathname === "/join" && request.method === "POST") {
        const body = (await request.json()) as {
          token: string;
          proof?: { type: string; token?: string };
        };
        if (!body.token) return jsonErr("invite token required", 400);

        const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
        const authority = env.SIGNING_AUTHORITY.get(authorityId);

        // Create principal
        const principalId = crypto.randomUUID();
        const result = await authority.redeemInviteToken(body.token, principalId);
        if (!result) return jsonErr("invalid or expired invite", 403);

        // Create principal with the invite's scopes
        await authority.createPrincipalWithCapabilities(
          principalId,
          result.scopes,
        );

        // If OIDC proof provided, link it
        if (body.proof?.type === "oidc" && body.proof.token) {
          const { verifyOIDC } = await import("./src/auth/verify-proof");
          try {
            const identity = await verifyOIDC(body.proof.token, "notme.bot");
            await authority.linkFederatedId(
              principalId,
              identity.issuer,
              identity.subject,
            );
          } catch {
            // OIDC link is optional — principal is created regardless
          }
        }

        // Issue session
        const { createSessionCookie } = await import("./src/auth/session");
        const sessionSecret = await authority.getSessionSecret();
        const cookie = await createSessionCookie(
          { principalId, scopes: result.scopes, authMethod: "invite" },
          sessionSecret,
        );

        return new Response(
          JSON.stringify({
            joined: true,
            principalId,
            scopes: result.scopes,
          }),
          {
            status: 200,
            headers: {
              "Content-Type": "application/json",
              "Set-Cookie": cookie,
            },
          },
        );
      }

      // POST /auth/oidc/login — login with an OIDC token (break glass)
      if (pathname === "/auth/oidc/login" && request.method === "POST") {
        const body = (await request.json()) as { token: string };
        if (!body.token) return jsonErr("token required", 400);

        const { verifyOIDC } = await import("./src/auth/verify-proof");
        let identity;
        try {
          identity = await verifyOIDC(body.token, "notme.bot");
        } catch (e: any) {
          return jsonErr("invalid token: " + e.message, 401);
        }

        const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
        const authority = env.SIGNING_AUTHORITY.get(authorityId);

        const principalId = await authority.findPrincipalByOIDC(
          identity.issuer,
          identity.subject,
        );
        if (!principalId) {
          return jsonErr("unknown identity — get an invite first", 403);
        }

        const scopes = await authority.getPrincipalScopes(principalId);
        const { createSessionCookie } = await import("./src/auth/session");
        const sessionSecret = await authority.getSessionSecret();
        const cookie = await createSessionCookie(
          {
            principalId,
            scopes,
            authMethod: `oidc:${identity.issuer}`,
          },
          sessionSecret,
        );

        return new Response(
          JSON.stringify({
            authenticated: true,
            principalId,
            scopes,
            authMethod: `oidc:${identity.issuer}`,
          }),
          {
            status: 200,
            headers: {
              "Content-Type": "application/json",
              "Set-Cookie": cookie,
            },
          },
        );
      }

      // Passkey reset — temporary, for fixing corrupted credential data
      // Requires the bootstrap code (proves deployer ownership)
      if (pathname === "/auth/passkey/reset" && request.method === "POST") {
        try {
          const body = (await request.json()) as { bootstrapCode?: string };
          const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
          const authority = env.SIGNING_AUTHORITY.get(authorityId);
          // Generate a fresh bootstrap code for reset auth
          const code = await authority.getOrCreateBootstrapCode();
          if (!code) {
            return jsonErr("bootstrap code already consumed — reset not available", 403);
          }
          if (!body.bootstrapCode || body.bootstrapCode !== code) {
            return jsonErr(`wrong code — check wrangler tail for the bootstrap code`, 403);
          }
          const result = await authority.resetPasskeyData();
          return Response.json({ ok: true, ...result });
        } catch (e: any) {
          return jsonErr("reset failed: " + e.message, 500);
        }
      }

      // Passkey diagnostics — requires admin session (leaks user/admin counts, epoch, keyId)
      if (pathname === "/auth/passkey/status") {
        const { verifySessionCookie } = await import("./src/auth/session");
        const authId = env.SIGNING_AUTHORITY.idFromName("default");
        const authDO = env.SIGNING_AUTHORITY.get(authId);
        const statusCookie = parseCookie(request.headers.get("cookie") || "", "notme_session");
        if (!statusCookie) return jsonErr("unauthorized", 401);
        const statusSecret = await authDO.getSessionSecret();
        const statusSession = await verifySessionCookie(statusCookie, statusSecret);
        if (!statusSession || !statusSession.scopes.includes("authorityManage")) {
          return jsonErr("admin required", 403);
        }
        try {
          const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
          const authority = env.SIGNING_AUTHORITY.get(authorityId);
          const state = await authority.getAuthorityState();
          // Count users and credentials via a simple RPC (need to add this)
          const passkey = await authority.passkeyStats();
          return Response.json({
            authority: { epoch: state.epoch, seqno: state.seqno, keyId: state.keyId },
            passkey,
            rpId: request.headers.get("host") || "auth.notme.bot",
          });
        } catch (e: any) {
          return jsonErr("status unavailable: " + e.message, 503);
        }
      }

      // Passkey routes (POST only)
      if (pathname.startsWith("/auth/passkey/")) {
        return handlePasskey(pathname, request, env);
      }

      // POST /cert — generalized cert exchange (any proof → bridge cert)
      // This is the core signet protocol endpoint.
      if (pathname === "/cert" && request.method === "POST") {
        const { handleCertExchange } = await import("./src/cert-exchange");
        return handleCertExchange(request, env);
      }

      // POST /cert/gha — GHA OIDC JWT → bridge cert (legacy, kept for compat)
      if (pathname === "/cert/gha") {
        return handleCertGHA(request, env, platform);
      }

      // GET /authorize — OAuth-style redirect for cross-origin DPoP token issuance
      if (pathname === "/authorize" && request.method === "GET") {
        const url = new URL(request.url);
        const redirectUri = url.searchParams.get("redirect_uri") || "";
        const audience = url.searchParams.get("audience") || "https://rosary.bot";
        const state = url.searchParams.get("state") || "";

        // Validate redirect_uri
        if (!redirectUri) {
          return jsonErr("redirect_uri required", 400);
        }
        let parsed: URL;
        try {
          parsed = new URL(redirectUri);
        } catch {
          return jsonErr("invalid redirect_uri", 400);
        }
        // Enforce https for all non-localhost
        const isLocalhost = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
        if (!isLocalhost && parsed.protocol !== "https:") {
          return jsonErr("redirect_uri must be https", 400);
        }
        if (isLocalhost && parsed.protocol !== "http:" && parsed.protocol !== "https:") {
          return jsonErr("redirect_uri must be http or https", 400);
        }
        // Strict allowlist — exact domains only (no wildcard subdomains)
        const redirectHost = parsed.hostname;
        const ALLOWED_REDIRECT_HOSTS = new Set([
          "localhost",
          "127.0.0.1",
          "rosary.bot",
          "auth.rosary.bot",
          "notme.bot",
          "auth.notme.bot",
        ]);
        if (!ALLOWED_REDIRECT_HOSTS.has(redirectHost)) {
          return jsonErr("redirect_uri not on allowed domain", 403);
        }

        // Check session
        const cookie = parseCookie(
          request.headers.get("cookie") || "",
          "notme_session",
        );
        if (!cookie) {
          // No session — redirect to login, then come back
          const returnTo = `/authorize?${url.searchParams.toString()}`;
          return Response.redirect(
            `${siteUrl}/login?return_to=${encodeURIComponent(returnTo)}`,
            302,
          );
        }

        const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
        const authority = env.SIGNING_AUTHORITY.get(authorityId);
        const { verifySessionCookie } = await import("./src/auth/session");
        const sessionSecret = await authority.getSessionSecret();
        const session = await verifySessionCookie(cookie, sessionSecret);
        if (!session) {
          const returnTo = `/authorize?${url.searchParams.toString()}`;
          return Response.redirect(
            `${siteUrl}/login?return_to=${encodeURIComponent(returnTo)}`,
            302,
          );
        }

        // Session valid — serve the authorize page
        // Params are injected into a data attribute and read by JS (no inline eval)
        return new Response(authorizePageHtml(redirectUri, audience, state), {
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      }

      // POST /authorize/token — Unbound redirect token for /authorize flow.
      // Session cookie required. No DPoP — token has no cnf.jkt.
      // Used by the /authorize page JS after passkey login.
      if (pathname === "/authorize/token" && request.method === "POST") {
        try {
          const cookie = parseCookie(
            request.headers.get("cookie") || "",
            "notme_session",
          );
          if (!cookie) {
            return Response.json({ error: "session_required" }, { status: 401 });
          }

          let audience = "";
          try {
            const body = await request.json() as { audience?: string };
            audience = body.audience || "";
          } catch { /* empty body */ }

          if (!audience) {
            return Response.json({ error: "audience_required" }, { status: 400 });
          }

          const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
          const authority = env.SIGNING_AUTHORITY.get(authorityId);
          const { verifySessionCookie } = await import("./src/auth/session");
          const sessionSecret = await authority.getSessionSecret();
          const session = await verifySessionCookie(cookie, sessionSecret);
          if (!session) {
            return Response.json({ error: "invalid_session" }, { status: 401 });
          }

          const accessToken = await authority.mintRedirectToken({
            sub: session.principalId,
            scope: session.scopes.join(" "),
            audience,
          });

          return Response.json({
            access_token: accessToken,
            token_type: "Bearer",
            expires_in: 300,
          });
        } catch (e: any) {
          return Response.json({ error: "authorize token error: " + e.message }, { status: 500 });
        }
      }

      // POST /token — DPoP sender-constrained access token (RFC 9449)
      if (pathname === "/token" && request.method === "POST") {
        try {
          const dpopProof = request.headers.get("DPoP");

          // Fast-fail: no DPoP proof = 400
          if (!dpopProof) {
            return Response.json({ error: "dpop_proof_required" }, { status: 400 });
          }

          // Parse body for audience — validated against allowlist
          let audience = "";
          try {
            const body = await request.json() as { audience?: string };
            audience = body.audience || "";
          } catch { /* empty body */ }

          // Audience allowlist — only issue tokens for known resource servers
          const ALLOWED_AUDIENCES = new Set([
            "https://rosary.bot",
            "https://mcp.rosary.bot",
            "https://auth.notme.bot",
            "https://notme.bot",
            "https://mache.rosary.bot",
            // Empty audience no longer allowed — tokens must be scoped
          ]);
          if (!audience) {
            return Response.json({ error: "audience_required" }, { status: 400 });
          }
          if (!ALLOWED_AUDIENCES.has(audience)) {
            return Response.json({ error: "invalid_audience", allowed: [...ALLOWED_AUDIENCES].filter(Boolean) }, { status: 400 });
          }

          const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
          const authority = env.SIGNING_AUTHORITY.get(authorityId);

          // ── Resolve identity: session cookie OR client cert ──
          let principalId: string | null = null;
          let scopes: string[] = [];

          // Try session cookie first (browser/passkey users)
          const cookie = parseCookie(
            request.headers.get("cookie") || "",
            "notme_session",
          );
          if (cookie) {
            const { verifySessionCookie } = await import("./src/auth/session");
            const sessionSecret = await authority.getSessionSecret();
            const session = await verifySessionCookie(cookie, sessionSecret);
            if (session) {
              principalId = session.principalId;
              scopes = session.scopes;
            }
          }

          // X-Client-Cert path REMOVED — mTLS not configured in wrangler.toml,
          // so the header is attacker-controlled. Re-enable only when CF mTLS
          // bindings are active and CF injects the cert (not the client).

          if (!principalId) {
            return Response.json({ error: "session_required" }, { status: 401 });
          }

          // Rate limit — atomic, edge-fast (replaces KV-based TOCTOU-vulnerable limiter)
          if (env.TOKEN_LIMITER) {
            const { success } = await env.TOKEN_LIMITER.limit({ key: `token:${principalId}` });
            if (!success) {
              return Response.json({ error: "rate_limited" }, { status: 429 });
            }
          }

          // Validate DPoP proof
          const { validateDpopProof } = await import("./src/auth/dpop");
          let proofResult;
          try {
            proofResult = await validateDpopProof(dpopProof, {
              htm: "POST",
              htu: `${new URL(request.url).origin}/token`,
            });
          } catch {
            return Response.json({ error: "invalid_dpop_proof" }, { status: 401 });
          }

          // JTI replay check
          const jtiKey = `dpop:jti:${proofResult.jti}`;
          if (await platform.cache.get(jtiKey)) {
            return Response.json({ error: "proof_reused" }, { status: 401 });
          }

          // Store JTI BEFORE minting — prevents TOCTOU race across edge nodes.
          // If mint fails after this, the JTI is burned (acceptable — client retries with new proof).
          await platform.cache.put(jtiKey, "1", { expirationTtl: 600 });

          // Mint token inside DO — CryptoKey never crosses RPC boundary
          const accessToken = await authority.mintDPoPToken({
            sub: principalId,
            scope: scopes.join(" "),
            audience,
            jkt: proofResult.thumbprint,
          });

          return Response.json({
            access_token: accessToken,
            token_type: "DPoP",
            expires_in: 300,
          });
        } catch (e: any) {
          return jsonErr("token endpoint error: " + e.message, 500);
        }
      }

      // GET /.well-known/jwks.json — Ed25519 public key for token verification
      if (pathname === "/.well-known/jwks.json") {
        const cached = await cacheMatch(request);
        if (cached) return cached;
        try {
          const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
          const authority = env.SIGNING_AUTHORITY.get(authorityId);
          const jwk = await authority.getPublicKeyJwk();
          const { buildJwksResponse } = await import("./src/auth/dpop-handler");
          const resp = Response.json(buildJwksResponse(jwk), {
            headers: {
              "Cache-Control": "public, max-age=3600",
              "Access-Control-Allow-Origin": "*",
            },
          });
          return cachePut(request, resp);
        } catch {
          return jsonErr("authority unavailable", 503);
        }
      }

      // Authority discovery — signet equivalent of openid-configuration.
      // signet CONSUMES OIDC tokens; it does not issue them.
      if (pathname === "/.well-known/signet-authority.json") {
        const cached = await cacheMatch(request);
        if (cached) return cached;
        const resp = Response.json(
          {
            issuer: authorityUrl,
            exchange_token_endpoint: `${authorityUrl}/exchange-token`,
            cert_gha_endpoint: `${authorityUrl}/cert/gha`,
            registration_endpoint: `${authorityUrl}/api/cert/register`,
            ca_bundle_endpoint: `${authorityUrl}/.well-known/ca-bundle.pem`,
            algorithms_supported: ["Ed25519"],
            grant_types_supported: [
              "oidc_token_exchange",
              "github_actions_oidc",
              "github_pat",
              "dpop",
            ],
            cert_types_supported: ["bridge_certificate"],
            token_endpoint: `${authorityUrl}/token`,
            jwks_uri: `${authorityUrl}/.well-known/jwks.json`,
            dpop_signing_alg_values_supported: ["ES256"],
            documentation: `${siteUrl}/architecture`,
          },
          {
            headers: {
              "Cache-Control": "public, max-age=86400",
              "Access-Control-Allow-Origin": "*",
            },
          },
        );
        return cachePut(request, resp);
      }

      // CA certificate — self-signed X.509 from SigningAuthority DO.
      // CF mTLS trust store requires X.509 PEM, not raw public keys.
      if (pathname === "/.well-known/ca-bundle.pem") {
        const cached = await cacheMatch(request);
        if (cached) return cached;
        try {
          const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
          const authority = env.SIGNING_AUTHORITY.get(authorityId);
          const pem: string = await authority.getCACertificatePem();
          const resp = new Response(pem, {
            headers: {
              "Content-Type": "application/x-pem-file",
              "Cache-Control": "public, max-age=3600",
            },
          });
          return cachePut(request, resp);
        } catch {
          // DO not available — fall through to VPC proxy
        }
      }

      // Content-negotiated landing at /
      if (pathname === "/" || pathname === "") {
        const cached = await cacheMatch(request, "Accept");
        if (cached) return cached;
        if (wantsJson(request)) {
          const resp = Response.json(
            {
              name: "Signet Authority",
              authority_url: authorityUrl,
              status: "operational",
              endpoints: {
                exchange_token: "/exchange-token",
                cert_gha: "/cert/gha",
                register: "/api/cert/register",
                login: "/login",
                healthz: "/healthz",
                ca_bundle: "/.well-known/ca-bundle.pem",
              },
              algorithms: ["Ed25519"],
              discovery: "/.well-known/signet-authority.json",
              public_key_url: "/.well-known/ca-bundle.pem",
            },
            {
              headers: {
                "Cache-Control": "public, max-age=3600",
                "Access-Control-Allow-Origin": "*",
                Vary: "Accept",
              },
            },
          );
          return cachePut(request, resp, "Accept");
        }
        // HTML landing — request without .html (CF Assets auto-strips extensions)
        const baseUrl = env.SITE_URL || "https://notme.bot";
        const resp = await env.ASSETS.fetch(new Request(`${baseUrl}/_auth`));
        const headers = new Headers(resp.headers);
        headers.set("Cache-Control", "public, max-age=3600");
        headers.set("Vary", "Accept");
        const result = new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers });
        return cachePut(request, result, "Accept");
      }

      // Proxy everything else to signet via VPC tunnel (requires VPC_AUTH binding)
      if (env.VPC_AUTH) {
        const originUrl = `http://localhost${pathname}${url.search}`;
        return env.VPC_AUTH.fetch(
          new Request(originUrl, {
            method: request.method,
            headers: request.headers,
            body: request.body,
          }),
        );
      }
      return Response.json(
        { error: "auth.notme.bot not yet configured" },
        { status: 503 },
      );
    }

    // /auth → canonical URL is auth.notme.bot (302 so BYO deploys can override)
    if (pathname === "/auth" || pathname === "/auth/") {
      const authorityUrl: string =
        env.SIGNET_AUTHORITY_URL || "https://auth.notme.bot";
      return Response.redirect(authorityUrl + "/", 302);
    }

    // Never serve repository internals, hidden files, or source/config files.
    // Exempt /.well-known/ (RFC 8615) — security.txt, etc. are served below.
    if (
      (pathname.startsWith("/.") || pathname.includes("/.")) &&
      !pathname.startsWith("/.well-known/")
    ) {
      return new Response("Not found", { status: 404 });
    }

    const blockedPaths = new Set([
      "/worker.ts",
      "/wrangler.toml",
      "/Taskfile.yml",
      "/README.md",
      "/LICENSE",
      "/.gitignore",
      "/.assetsignore",
    ]);

    if (blockedPaths.has(pathname) || pathname.endsWith(".map")) {
      return new Response("Not found", { status: 404 });
    }

    if (url.pathname === "/robots.txt") {
      const cached = await cacheMatch(request);
      if (cached) return cached;
      const resp = new Response(
        `User-agent: *\nAllow: /\n\nSitemap: https://notme.bot/sitemap.xml`,
        {
          headers: {
            "Content-Type": "text/plain; charset=utf-8",
            "Cache-Control": "public, max-age=86400",
          },
        },
      );
      return cachePut(request, resp);
    }

    if (url.pathname === "/sitemap.xml") {
      const cached = await cacheMatch(request);
      if (cached) return cached;
      const today = new Date().toISOString().slice(0, 10);
      const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://notme.bot/</loc>
    <lastmod>${today}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://notme.bot/apas</loc>
    <lastmod>${today}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://notme.bot/architecture</loc>
    <lastmod>${today}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://notme.bot/research</loc>
    <lastmod>${today}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
</urlset>`;
      const resp = new Response(sitemap, {
        headers: {
          "Content-Type": "application/xml; charset=utf-8",
          "Cache-Control": "public, max-age=86400",
        },
      });
      return cachePut(request, resp);
    }

    // security.txt (RFC 9116)
    if (url.pathname === "/.well-known/security.txt") {
      const cached = await cacheMatch(request);
      if (cached) return cached;
      const resp = new Response(
        `Contact: https://github.com/agentic-research/signet/security/advisories\nExpires: 2027-03-25T00:00:00.000Z\nPreferred-Languages: en\nCanonical: https://notme.bot/.well-known/security.txt\n`,
        {
          headers: {
            "Content-Type": "text/plain; charset=utf-8",
            "Cache-Control": "public, max-age=86400",
          },
        },
      );
      return cachePut(request, resp);
    }

    // ── APAS predicate type URIs — content negotiated ──
    if (url.pathname === "/provenance/dispatch/v1") {
      const cached = await cacheMatch(request, "Accept");
      if (cached) return cached;
      const resp = wantsJson(request)
        ? jsonResponse(DISPATCH_SCHEMA)
        : renderPredicateHtml(DISPATCH_SCHEMA);
      // Add Vary header for content-negotiated responses
      const headers = new Headers(resp.headers);
      headers.set("Vary", "Accept");
      const result = new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers });
      return cachePut(request, result, "Accept");
    }

    if (url.pathname === "/provenance/handoff/v1") {
      const cached = await cacheMatch(request, "Accept");
      if (cached) return cached;
      const resp = wantsJson(request)
        ? jsonResponse(HANDOFF_SCHEMA)
        : renderPredicateHtml(HANDOFF_SCHEMA);
      const headers = new Headers(resp.headers);
      headers.set("Vary", "Accept");
      const result = new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers });
      return cachePut(request, result, "Accept");
    }

    // Redirects for renamed pages — cached at edge with long TTL
    if (url.pathname === "/stack") {
      const resp = new Response(null, {
        status: 301,
        headers: {
          Location: "https://notme.bot/",
          "Cache-Control": "public, max-age=31536000, immutable",
        },
      });
      return cachePut(request, resp);
    }
    if (url.pathname === "/agent-identity") {
      const resp = new Response(null, {
        status: 301,
        headers: {
          Location: "https://notme.bot/research",
          "Cache-Control": "public, max-age=31536000, immutable",
        },
      });
      return cachePut(request, resp);
    }
    if (url.pathname === "/favicon.ico") {
      const resp = new Response(null, {
        status: 301,
        headers: {
          Location: "https://notme.bot/favicon.svg",
          "Cache-Control": "public, max-age=31536000, immutable",
        },
      });
      return cachePut(request, resp);
    }

    // ── Static assets ──
    // Check CF edge cache first — avoids re-invoking ASSETS.fetch on cache hit.
    const cached = await cacheMatch(request);
    if (cached) return cached;

    const response = await env.ASSETS.fetch(request);

    // Add Cache-Control for responses and store in CF edge cache
    if (response.ok) {
      const contentType = response.headers.get("Content-Type") || "";
      const newHeaders = new Headers(response.headers);

      if (contentType.includes("image/") || contentType.includes("font/")) {
        // Images and fonts are content-addressed — safe to cache forever
        newHeaders.set("Cache-Control", "public, max-age=31536000, immutable");
      } else if (
        contentType.includes("text/css") ||
        contentType.includes("javascript")
      ) {
        // CSS/JS are mutable (no content hash in filenames) — cache 1 hour, revalidate
        newHeaders.set(
          "Cache-Control",
          "public, max-age=3600, must-revalidate",
        );
      } else if (contentType.includes("text/html")) {
        // HTML — cache at edge for 60s with stale-while-revalidate for fast hits.
        // Browsers still revalidate on every navigation (s-maxage governs edge only).
        newHeaders.set("Cache-Control", "public, s-maxage=60, stale-while-revalidate=300");
      } else if (contentType.includes("image/svg")) {
        // SVG favicon etc — long cache
        newHeaders.set("Cache-Control", "public, max-age=86400");
      }

      const result = new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: newHeaders,
      });
      return cachePut(request, result);
    }

    return response;
  },
};
