// SigningAuthority — Durable Object that generates and stores the Ed25519 CA master key.
//
// Zero-copy: key is born in CF and never leaves. No wrangler secret put,
// no PEM on anyone's machine. This is the reference implementation that
// `npx notme auth init` replicates to BYO CF accounts.
//
// SQLite schema:
//   keys  — singleton authority keypair (Ed25519)
//   state — epoch, seqno, keyId for bundle generation
//
// The DO owns the full lifecycle: key generation, bundle signing, rotation.
// The Worker writes signed bundles to KV for the revocation verifier.

import { DurableObject } from "cloudflare:workers";
import { X509CertificateGenerator, BasicConstraintsExtension, KeyUsagesExtension, KeyUsageFlags } from "@peculiar/x509";
import { encodeBase64urlNoPadding } from "@oslojs/encoding";
import type { CABundle } from "./revocation";
import { detectKeyStorage, type KeyStorageMode, ED25519 } from "./platform";

interface SigningAuthorityEnv {
  CA_BUNDLE_CACHE?: KVNamespace;
  NOTME_KEY_STORAGE?: string;
  NOTME_KEK_SECRET?: string;
}

// Bundle refresh interval — must be shorter than BUNDLE_MAX_AGE_MS (5 min) in revocation.ts
const BUNDLE_REFRESH_MS = 4 * 60 * 1000; // 4 minutes

export class SigningAuthority extends DurableObject<SigningAuthorityEnv> {
  private initialized = false;
  private signingKey: CryptoKey | null = null;
  private verifyKey: CryptoKey | null = null;
  /** Key storage mode — uses shared detectKeyStorage() for consistency with Worker. */
  private get keyStorageMode(): KeyStorageMode {
    const mode = detectKeyStorage(this.env as Record<string, unknown>);
    if (mode === "encrypted") {
      throw new Error(
        "encrypted key storage is not yet implemented. " +
          "Use ephemeral (local/CI) or cf-managed (production). " +
          "See docs/design/007-secretless-local-proxy.md for roadmap.",
      );
    }
    return mode;
  }

  private ensureSchema(): void {
    if (this.initialized) return;
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS keys (
        id          TEXT PRIMARY KEY DEFAULT 'authority',
        private_jwk TEXT NOT NULL,
        public_spki TEXT NOT NULL,
        key_id      TEXT NOT NULL DEFAULT '',
        created_at  TEXT NOT NULL DEFAULT (datetime('now')),
        algorithm   TEXT NOT NULL DEFAULT 'Ed25519'
      )
    `);
    // Migration: add key_id column if missing (v1 → v2)
    try {
      this.ctx.storage.sql.exec("SELECT key_id FROM keys LIMIT 0");
    } catch {
      this.ctx.storage.sql.exec(
        "ALTER TABLE keys ADD COLUMN key_id TEXT NOT NULL DEFAULT ''",
      );
    }
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS state (
        id     TEXT PRIMARY KEY DEFAULT 'authority',
        epoch  INTEGER NOT NULL DEFAULT 1,
        seqno  INTEGER NOT NULL DEFAULT 1
      )
    `);
    this.ctx.storage.sql.exec(
      "INSERT OR IGNORE INTO state (id, epoch, seqno) VALUES ('authority', 1, 1)",
    );
    this.initialized = true;
  }

  // Generate a key ID from SHA-256 of the public key (first 8 hex chars).
  // Previous djb2 hash had 32-bit collision space — SHA-256 is cryptographically strong.
  private static async keyIdFromSpki(spkiB64: string): Promise<string> {
    const raw = atob(spkiB64);
    const keyBytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) keyBytes[i] = raw.charCodeAt(i);
    const hashBuf = await crypto.subtle.digest("SHA-256", keyBytes);
    return Array.from(new Uint8Array(hashBuf).slice(0, 4))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  }

  // Load or generate the authority keypair. Cached in memory for the DO lifetime.
  async getOrCreateSigningKey(): Promise<{
    signingKey: CryptoKey;
    verifyKey: CryptoKey;
    keyId: string;
  }> {
    if (this.signingKey && this.verifyKey) {
      const kid = this.getKeyId();
      return {
        signingKey: this.signingKey,
        verifyKey: this.verifyKey,
        keyId: kid,
      };
    }

    this.ensureSchema();

    const rows = this.ctx.storage.sql
      .exec(
        "SELECT private_jwk, public_spki, key_id FROM keys WHERE id = 'authority'",
      )
      .toArray() as Array<{
      private_jwk: string;
      public_spki: string;
      key_id: string;
    }>;

    if (rows.length > 0) {
      const row = rows[0]!;

      // Ephemeral mode: private_jwk is empty — key only exists in memory.
      // If we restarted, we need to generate a new key (fall through below).
      if (!row.private_jwk) {
        // Fall through to key generation
      } else {
        const jwk = JSON.parse(row.private_jwk);
        this.signingKey = await crypto.subtle.importKey(
          "jwk",
          jwk,
          ED25519,
          false, // NON-EXTRACTABLE after import
          ["sign"],
        );
        const spkiBytes = Uint8Array.from(atob(row.public_spki), (c) =>
          c.charCodeAt(0),
        );
        this.verifyKey = await crypto.subtle.importKey(
          "spki",
          spkiBytes,
          ED25519,
          true, // public key stays extractable (needed for JWKS, raw export)
          ["verify"],
        );
        let keyId = row.key_id;
        if (!keyId) {
          keyId = await SigningAuthority.keyIdFromSpki(row.public_spki);
          this.ctx.storage.sql.exec(
            "UPDATE keys SET key_id = ? WHERE id = 'authority'",
            keyId,
          );
        }
        return { signingKey: this.signingKey, verifyKey: this.verifyKey, keyId };
      }
    }

    // Generate the authority keypair
    const isEphemeral = this.keyStorageMode === "ephemeral";
    const kp = (await crypto.subtle.generateKey(
      ED25519,
      !isEphemeral, // extractable:false in ephemeral mode
      ["sign", "verify"],
    )) as CryptoKeyPair;

    // Always extract public key (for key ID + JWKS)
    const publicSpki = (await crypto.subtle.exportKey(
      "spki",
      kp.publicKey,
    )) as ArrayBuffer;
    const publicSpkiB64 = btoa(
      String.fromCharCode(...new Uint8Array(publicSpki)),
    );
    const keyId = await SigningAuthority.keyIdFromSpki(publicSpkiB64);

    if (isEphemeral) {
      // Store public key + key ID only — no private key material on disk
      this.ctx.storage.sql.exec(
        "INSERT OR REPLACE INTO keys (id, private_jwk, public_spki, key_id) VALUES ('authority', '', ?, ?)",
        publicSpkiB64,
        keyId,
      );
      this.signingKey = kp.privateKey;
      this.verifyKey = kp.publicKey;
    } else {
      // Persistent: export JWK, store, then re-import as non-extractable
      const privateJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
      this.ctx.storage.sql.exec(
        "INSERT INTO keys (id, private_jwk, public_spki, key_id) VALUES ('authority', ?, ?, ?)",
        JSON.stringify(privateJwk),
        publicSpkiB64,
        keyId,
      );
      // Re-import as non-extractable — JWK is stored, no need to keep extractable
      this.signingKey = await crypto.subtle.importKey(
        "jwk",
        privateJwk,
        ED25519,
        false,
        ["sign"],
      );
      this.verifyKey = kp.publicKey;
    }

    await this.scheduleNextRefresh();
    return { signingKey: this.signingKey, verifyKey: this.verifyKey, keyId };
  }

  private getKeyId(): string {
    this.ensureSchema();
    const rows = this.ctx.storage.sql
      .exec("SELECT key_id FROM keys WHERE id = 'authority'")
      .toArray() as Array<{ key_id: string }>;
    return rows[0]?.key_id ?? "unknown";
  }

  // Return the authority's public key as PEM.
  async getPublicKeyPem(): Promise<string> {
    const { verifyKey } = await this.getOrCreateSigningKey();
    const spki = (await crypto.subtle.exportKey(
      "spki",
      verifyKey,
    )) as ArrayBuffer;
    const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
    const lines = b64.match(/.{1,64}/g)!;
    return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----\n`;
  }

  // Return the authority's public key as JWK (for /.well-known/jwks.json).
  async getPublicKeyJwk(): Promise<{
    kty: string;
    crv: string;
    x: string;
    kid: string;
    use: string;
    alg: string;
  }> {
    const { verifyKey, keyId } = await this.getOrCreateSigningKey();
    const raw = (await crypto.subtle.exportKey(
      "raw",
      verifyKey,
    )) as ArrayBuffer;
    const x = encodeBase64urlNoPadding(new Uint8Array(raw));
    return { kty: "OKP", crv: "Ed25519", x, kid: keyId, use: "sig", alg: "EdDSA" };
  }

  // Self-signed X.509 CA certificate for CF mTLS trust store.
  // Cached in DO SQLite; invalidated on key rotation (key_id mismatch).
  async getCACertificatePem(): Promise<string> {
    this.ensureSchema();
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS ca_cert (
        id     TEXT PRIMARY KEY DEFAULT 'cert',
        pem    TEXT NOT NULL,
        key_id TEXT NOT NULL
      )
    `);
    const currentKeyId = this.getKeyId();
    const cached = this.ctx.storage.sql
      .exec("SELECT pem, key_id FROM ca_cert WHERE id = 'cert'")
      .toArray() as Array<{ pem: string; key_id: string }>;
    // v2: require CA:TRUE in cached cert (invalidate v1 certs without BasicConstraints)
    if (cached.length > 0 && cached[0]!.key_id === currentKeyId && cached[0]!.pem.includes('BEGIN CERTIFICATE')) {
      // Check if cached cert has BasicConstraints by looking for the extension marker
      // If it was generated without extensions (v1), regenerate
      try {
        const { X509Certificate } = await import("@peculiar/x509");
        const x = new X509Certificate(cached[0]!.pem);
        const bc = x.getExtension("2.5.29.19"); // BasicConstraints OID
        if (bc) return cached[0]!.pem;
      } catch { /* regenerate */ }
    }

    const { signingKey, verifyKey } = await this.getOrCreateSigningKey();
    const now = new Date();
    const notAfter = new Date(now.getTime() + 10 * 365.25 * 24 * 60 * 60 * 1000);
    const serial = crypto
      .getRandomValues(new Uint8Array(16))
      .reduce((s, b) => s + b.toString(16).padStart(2, "0"), "");

    const cert = await X509CertificateGenerator.createSelfSigned({
      name: "CN=signet-authority,O=notme",
      notBefore: now,
      notAfter,
      signingAlgorithm: ED25519,
      keys: { privateKey: signingKey, publicKey: verifyKey },
      serialNumber: serial,
      extensions: [
        new BasicConstraintsExtension(true, 1, true), // pathlen=1: CA → orchestrator → agent
        new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign, true),
      ],
    });

    const pem = cert.toString("pem");
    this.ctx.storage.sql.exec("DELETE FROM ca_cert WHERE id = 'cert'");
    this.ctx.storage.sql.exec(
      "INSERT INTO ca_cert (id, pem, key_id) VALUES ('cert', ?, ?)",
      pem,
      currentKeyId,
    );
    return pem;
  }

  // Return the raw 32-byte Ed25519 public key as base64 (for CABundle.keys).
  async getPublicKeyRawB64(): Promise<string> {
    const { verifyKey } = await this.getOrCreateSigningKey();
    const raw = (await crypto.subtle.exportKey(
      "raw",
      verifyKey,
    )) as ArrayBuffer;
    return btoa(String.fromCharCode(...new Uint8Array(raw)));
  }

  // Sign arbitrary data with the authority key.
  async sign(data: ArrayBuffer): Promise<ArrayBuffer> {
    const { signingKey } = await this.getOrCreateSigningKey();
    return crypto.subtle.sign("Ed25519" as any, signingKey, data);
  }

  // Mint a DPoP-bound access token inside the DO — CryptoKey never crosses RPC.
  async mintDPoPToken(params: {
    sub: string;
    scope: string;
    audience: string;
    jkt: string; // JWK thumbprint of the DPoP proof key
  }): Promise<string> {
    const { signingKey, keyId } = await this.getOrCreateSigningKey();
    const { mintAccessToken } = await import("./auth/token");
    return mintAccessToken({
      sub: params.sub,
      scope: params.scope,
      audience: params.audience,
      jkt: params.jkt,
      signingKey,
      keyId,
    });
  }

  // Mint an unbound redirect token — no cnf.jkt, safe for verifyAccessToken (Bearer path).
  // Used by /authorize redirect flow where the DPoP keypair is ephemeral and lost after navigation.
  async mintRedirectToken(params: {
    sub: string;
    scope: string;
    audience: string;
  }): Promise<string> {
    const { signingKey, keyId } = await this.getOrCreateSigningKey();
    const { mintAccessToken } = await import("./auth/token");
    return mintAccessToken({
      sub: params.sub,
      scope: params.scope,
      audience: params.audience,
      // No jkt — unbound token, accepted by verifyAccessToken
      signingKey,
      keyId,
    });
  }

  // Mint a bridge cert inside the DO — CryptoKey never crosses the RPC boundary.
  async mintBridgeCert(
    subject: string,
    publicKeyPem: string,
    ttlMs?: number,
  ): Promise<{
    certificate: string;
    expires_at: number;
    subject: string;
    authority: { epoch: number; key_id: string };
  }> {
    const { signingKey } = await this.getOrCreateSigningKey();
    const state = await this.getAuthorityState();
    const { mintGHABridgeCert } = await import("./cert-authority");
    const result = await mintGHABridgeCert(subject, publicKeyPem, signingKey, ttlMs);
    return {
      ...result,
      authority: { epoch: state.epoch, key_id: state.keyId },
    };
  }

  // Current epoch and keyId for embedding in issued certs.
  async getAuthorityState(): Promise<{
    epoch: number;
    seqno: number;
    keyId: string;
  }> {
    this.ensureSchema();
    const { keyId } = await this.getOrCreateSigningKey();
    const rows = this.ctx.storage.sql
      .exec("SELECT epoch, seqno FROM state WHERE id = 'authority'")
      .toArray() as Array<{ epoch: number; seqno: number }>;
    const state = rows[0] ?? { epoch: 1, seqno: 1 };
    return { epoch: state.epoch, seqno: state.seqno, keyId };
  }

  // Generate a signed CABundle for the revocation verifier.
  // Caller writes this to CA_BUNDLE_CACHE KV.
  async generateBundle(): Promise<CABundle> {
    const { signingKey, keyId } = await this.getOrCreateSigningKey();
    const pubKeyB64 = await this.getPublicKeyRawB64();

    this.ensureSchema();

    // Advance seqno
    this.ctx.storage.sql.exec(
      "UPDATE state SET seqno = seqno + 1 WHERE id = 'authority'",
    );
    const rows = this.ctx.storage.sql
      .exec("SELECT epoch, seqno FROM state WHERE id = 'authority'")
      .toArray() as Array<{ epoch: number; seqno: number }>;
    const { epoch, seqno } = rows[0]!;

    // Build the unsigned bundle
    const bundle: Omit<CABundle, "signature"> & { signature?: string } = {
      epoch,
      seqno,
      keys: { [keyId]: pubKeyB64 },
      keyId,
      issuedAt: Math.floor(Date.now() / 1000),
    };

    // Canonical JSON for signing (same as revocation.ts bundleCanonical)
    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(bundle).sort()) {
      sorted[k] = bundle[k as keyof typeof bundle];
    }
    const canonical = new TextEncoder().encode(JSON.stringify(sorted));

    // Sign
    const sig = await crypto.subtle.sign(
      "Ed25519" as any,
      signingKey,
      canonical,
    );
    const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));

    return { ...bundle, signature: sigB64 } as CABundle;
  }

  // Rotate the CA key. Increments epoch, generates new keypair.
  // Previous keyId is preserved in the bundle as prevKeyId for graceful transition.
  async rotate(): Promise<{ newKeyId: string; epoch: number }> {
    this.ensureSchema();
    const oldKeyId = this.getKeyId();

    // Delete old key
    this.ctx.storage.sql.exec("DELETE FROM keys WHERE id = 'authority'");
    this.signingKey = null;
    this.verifyKey = null;

    // Increment epoch
    this.ctx.storage.sql.exec(
      "UPDATE state SET epoch = epoch + 1, seqno = seqno + 1 WHERE id = 'authority'",
    );

    // Generate new key (getOrCreateSigningKey will create since we deleted)
    const { keyId: newKeyId } = await this.getOrCreateSigningKey();

    // Store prevKeyId for the transition window
    await this.ctx.storage.put("prevKeyId", oldKeyId);

    const rows = this.ctx.storage.sql
      .exec("SELECT epoch FROM state WHERE id = 'authority'")
      .toArray() as Array<{ epoch: number }>;

    return { newKeyId, epoch: rows[0]!.epoch };
  }

  // ── Passkey operations (delegates to passkey module, uses DO's SQLite) ──

  async passkeyRegistrationOptions(
    userId: string,
    displayName: string,
    rpId: string,
  ): Promise<any> {
    const { registrationOptions } = await import("./auth/passkey");
    return registrationOptions(userId, displayName, rpId, this.ctx.storage.sql);
  }

  async passkeyVerifyRegistration(
    userId: string,
    displayName: string,
    response: any,
    rpId: string,
    origin: string,
  ): Promise<{ verified: boolean; isAdmin: boolean }> {
    const { verifyRegistration } = await import("./auth/passkey");
    return verifyRegistration(
      userId,
      displayName,
      response,
      rpId,
      origin,
      this.ctx.storage.sql,
    );
  }

  async passkeyAuthenticationOptions(rpId: string): Promise<any> {
    const { authenticationOptions } = await import("./auth/passkey");
    return authenticationOptions(rpId, this.ctx.storage.sql);
  }

  async passkeyVerifyAuthentication(
    response: any,
    rpId: string,
    origin: string,
  ): Promise<{ verified: boolean; userId: string | null; isAdmin: boolean }> {
    const { verifyAuthentication } = await import("./auth/passkey");
    return verifyAuthentication(response, rpId, origin, this.ctx.storage.sql);
  }

  // Get or generate the session HMAC secret (stored in DO SQLite)
  async getSessionSecret(): Promise<string> {
    this.ensureSchema();
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS session_config (
        id     TEXT PRIMARY KEY DEFAULT 'session',
        secret TEXT NOT NULL
      )
    `);
    const rows = this.ctx.storage.sql
      .exec("SELECT secret FROM session_config WHERE id = 'session'")
      .toArray() as Array<{ secret: string }>;
    if (rows.length > 0) return rows[0]!.secret;

    // Generate on first call
    const buf = new Uint8Array(32);
    crypto.getRandomValues(buf);
    const secret = btoa(String.fromCharCode(...buf));
    this.ctx.storage.sql.exec(
      "INSERT INTO session_config (id, secret) VALUES ('session', ?)",
      secret,
    );
    return secret;
  }

  // ── Invites: time-limited, single-use, scoped ──

  async createInviteToken(
    createdBy: string,
    scopes: string[],
    ttlSeconds = 3600,
  ): Promise<{ token: string; expiresAt: string }> {
    const { createInvite } = await import("./auth/principals");
    const invite = createInvite(this.ctx.storage.sql, createdBy, scopes, ttlSeconds);
    return { token: invite.token, expiresAt: invite.expiresAt };
  }

  async redeemInviteToken(
    token: string,
    redeemedBy: string,
  ): Promise<{ scopes: string[] } | null> {
    const { redeemInvite } = await import("./auth/principals");
    return redeemInvite(this.ctx.storage.sql, token, redeemedBy);
  }

  // ── Principal management ──

  async createPrincipalWithCapabilities(
    principalId: string,
    scopes: string[],
    createdBy?: string,
  ): Promise<void> {
    const { createPrincipal, grantCapability } = await import("./auth/principals");
    createPrincipal(this.ctx.storage.sql, principalId, undefined, createdBy);
    for (const scope of scopes) {
      grantCapability(this.ctx.storage.sql, principalId, scope, createdBy);
    }
  }

  async getPrincipalScopes(principalId: string): Promise<string[]> {
    const { getCapabilities } = await import("./auth/principals");
    return getCapabilities(this.ctx.storage.sql, principalId);
  }

  async linkFederatedId(
    principalId: string,
    provider: string,
    providerSub: string,
  ): Promise<void> {
    const { linkFederatedIdentity } = await import("./auth/principals");
    linkFederatedIdentity(this.ctx.storage.sql, principalId, provider, providerSub);
  }

  async findPrincipalByOIDC(
    provider: string,
    providerSub: string,
  ): Promise<string | null> {
    const { findPrincipalByFederated } = await import("./auth/principals");
    return findPrincipalByFederated(this.ctx.storage.sql, provider, providerSub);
  }

  // ── Connections: OIDC/x509 identity associations ──

  async storeConnection(input: {
    credentialId: string;
    provider: string;
    providerSubject: string;
    providerEmail?: string;
  }): Promise<void> {
    const { createConnection } = await import("./auth/connections");
    await createConnection(this.ctx.storage.sql, input);
  }

  async getConnectionsForUser(
    credentialId: string,
  ): Promise<Array<{ provider: string; subject: string; connectedAt: string }>> {
    const { getConnections } = await import("./auth/connections");
    const conns = await getConnections(this.ctx.storage.sql, credentialId);
    return conns.map((c) => ({
      provider: c.provider,
      subject: c.providerSubject,
      connectedAt: c.connectedAt,
    }));
  }

  // Reset passkey data — for when credentials are corrupted (e.g. userId mismatch bug)
  async resetPasskeyData(): Promise<{ deleted: number }> {
    const { ensurePasskeySchema } = await import("./auth/passkey");
    ensurePasskeySchema(this.ctx.storage.sql);
    const creds = this.ctx.storage.sql
      .exec("SELECT COUNT(*) as c FROM passkey_credentials")
      .toArray() as Array<{ c: number }>;
    const count = creds[0]?.c ?? 0;
    this.ctx.storage.sql.exec("DELETE FROM passkey_credentials");
    this.ctx.storage.sql.exec("DELETE FROM passkey_users");
    this.ctx.storage.sql.exec("DELETE FROM passkey_challenges");
    // Mark bootstrap as used — do NOT delete it.
    // A new code only appears on fresh DO instantiation, not after reset.
    // This prevents: know code → reset → new code → reset → infinite wipe loop.
    this.ctx.storage.sql.exec("UPDATE bootstrap SET used = 1 WHERE id = 'code'");
    return { deleted: count };
  }

  // ── Bootstrap code: one-time admin registration gate ──
  // Generated on first call, deleted after first passkey registration.
  // Only visible to the deployer (via wrangler tail / console).

  async getOrCreateBootstrapCode(): Promise<string | null> {
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS bootstrap (
        id         TEXT PRIMARY KEY DEFAULT 'code',
        code       TEXT NOT NULL,
        used       INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `);
    const rows = this.ctx.storage.sql
      .exec("SELECT code, used, created_at FROM bootstrap WHERE id = 'code'")
      .toArray() as Array<{ code: string; used: number; created_at: string }>;

    if (rows.length > 0) {
      if (rows[0]!.used) return null;
      // Expire after 15 minutes
      const created = new Date(rows[0]!.created_at + "Z").getTime();
      const BOOTSTRAP_TTL_MS = 15 * 60 * 1000;
      if (Date.now() - created > BOOTSTRAP_TTL_MS) {
        this.ctx.storage.sql.exec("DELETE FROM bootstrap WHERE id = 'code'");
      } else {
        return rows[0]!.code;
      }
    }

    const code = crypto.randomUUID();
    this.ctx.storage.sql.exec(
      "INSERT INTO bootstrap (id, code) VALUES ('code', ?)",
      code,
    );
    console.log([
      "",
      "=".repeat(50),
      "BOOTSTRAP CODE: " + code,
      "Enter this at auth.notme.bot/login to register the admin passkey.",
      "Single-use. Expires in 15 minutes.",
      "=".repeat(50),
      "",
    ].join("\n"));
    return code;
  }

  async consumeBootstrapCode(code: string): Promise<boolean> {
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS bootstrap (
        id         TEXT PRIMARY KEY DEFAULT 'code',
        code       TEXT NOT NULL,
        used       INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `);
    const rows = this.ctx.storage.sql
      .exec("SELECT code, created_at FROM bootstrap WHERE id = 'code' AND used = 0")
      .toArray() as Array<{ code: string; created_at: string }>;

    const { timingSafeEqual } = await import("./auth/timing-safe");
    if (rows.length === 0 || !(await timingSafeEqual(rows[0]!.code, code))) return false;

    // Enforce 15-minute TTL here too (not just in getOrCreateBootstrapCode)
    const BOOTSTRAP_TTL_MS = 15 * 60 * 1000;
    const created = new Date(rows[0]!.created_at + "Z").getTime();
    if (Date.now() - created > BOOTSTRAP_TTL_MS) {
      this.ctx.storage.sql.exec("DELETE FROM bootstrap WHERE id = 'code'");
      return false;
    }

    this.ctx.storage.sql.exec(
      "UPDATE bootstrap SET used = 1 WHERE id = 'code'",
    );
    return true;
  }

  // Passkey stats — no PII, just counts for diagnostics
  async passkeyStats(): Promise<{
    users: number;
    credentials: number;
    admins: number;
  }> {
    const { ensurePasskeySchema } = await import("./auth/passkey");
    ensurePasskeySchema(this.ctx.storage.sql);
    const users = this.ctx.storage.sql
      .exec("SELECT COUNT(*) as c FROM passkey_users")
      .toArray() as Array<{ c: number }>;
    const creds = this.ctx.storage.sql
      .exec("SELECT COUNT(*) as c FROM passkey_credentials")
      .toArray() as Array<{ c: number }>;
    const admins = this.ctx.storage.sql
      .exec("SELECT COUNT(*) as c FROM passkey_users WHERE is_admin = 1")
      .toArray() as Array<{ c: number }>;
    return {
      users: users[0]?.c ?? 0,
      credentials: creds[0]?.c ?? 0,
      admins: admins[0]?.c ?? 0,
    };
  }

  // ── Alarm: periodic bundle publish ──────────────────────────────────
  // Ensures CA bundle in KV stays fresh (< BUNDLE_MAX_AGE_MS).
  // Scheduled on first getOrCreateSigningKey() and re-arms after each fire.

  async scheduleNextRefresh(): Promise<void> {
    const current = await this.ctx.storage.getAlarm();
    if (!current) {
      await this.ctx.storage.setAlarm(Date.now() + BUNDLE_REFRESH_MS);
    }
  }

  override async alarm(): Promise<void> {
    try {
      const bundle = await this.generateBundle();
      if (this.env.CA_BUNDLE_CACHE) {
        await this.env.CA_BUNDLE_CACHE.put(
          "bundle:current",
          JSON.stringify(bundle),
        );
      }
    } catch (e) {
      console.error("[signing-authority] bundle refresh failed:", e);
    }
    // Re-arm
    await this.ctx.storage.setAlarm(Date.now() + BUNDLE_REFRESH_MS);
  }
}
