// SigningAuthority — Durable Object that generates and stores the Ed25519 CA master key.
//
// Zero-copy: key is born in CF and never leaves. No wrangler secret put,
// no PEM on anyone's machine. This is the reference implementation that
// `npx notme auth init` replicates to BYO CF accounts.
//
// SQLite schema:
//   keys  — singleton authority keypair (Ed25519)
//   state — epoch, seqno, keyId for bundle generation
//   dpop_jtis — atomically consumed DPoP proof identifiers
//
// The DO owns the full lifecycle: key generation, bundle signing, rotation.
// The Worker writes signed bundles to KV for the revocation verifier.

import { DurableObject } from "cloudflare:workers";
import {
  X509CertificateGenerator,
  BasicConstraintsExtension,
  KeyUsagesExtension,
  KeyUsageFlags,
} from "@peculiar/x509";
import { encodeBase64urlNoPadding } from "@oslojs/encoding";
// PKCE + code hashing come from the shared package so the authority and its
// clients run the SAME implementation — see the RFC 7636 section there.
import { sha256Base64url } from "@agentic-research/dpop";
import { bundleCanonical, type CABundle } from "./revocation";
import { detectKeyStorage, type KeyStorageMode, ED25519 } from "./platform";
import {
  deriveKek,
  readStoredJwk,
  serialiseJwkForStorage,
} from "./key-encryption";

interface SigningAuthorityEnv {
  CA_BUNDLE_CACHE?: KVNamespace;
  NOTME_KEY_STORAGE?: string;
  NOTME_KEK_SECRET?: string;
}

// Bundle refresh interval — must be shorter than BUNDLE_MAX_AGE_MS (5 min) in revocation.ts
const BUNDLE_REFRESH_MS = 4 * 60 * 1000; // 4 minutes

// Circuit-breaker threshold for the alarm() loop. After this many consecutive
// generateBundle() failures, alarm() stops re-arming itself. Manual recovery
// via resetAlarmHealth() RPC. Defends against the runaway-alarm-bills failure
// mode (per notme-5c2511 EPIC and the reddit cautionary tale that motivated it):
// if generateBundle starts throwing — DO storage corruption, key import failure,
// KV unavailable, signing-key state desync — without this, we'd fire every 4
// minutes forever, each time doing real DO storage reads/writes.
//
// 5 strikes ≈ 20 minutes of failure before kill switch fires. Tunable.
const MAX_CONSECUTIVE_ALARM_FAILURES = 5;

import { keyIdFromSpki } from "./key-id";
import type { CommitmentErrorCode } from "./receipts/commitment";
import type { DelegatedJwtErrorCode } from "./jwt/delegated-claims";

/**
 * Outcome of a receipt-signing attempt (ADR-014).
 *
 * A union rather than throw-on-failure: an RPC rejection surfaces as an
 * uncaught exception in the callee's context and stringifies the error, so a
 * caller could only branch on message text. `code` is the stable contract —
 * cloister re-reads `getReceiptFacts()` on `EPOCH_MISMATCH` instead of polling
 * for key rotation.
 */
export type ReceiptSignResult =
  | {
      ok: true;
      /**
       * RAW 64-byte Ed25519 signature. NOT a receipt envelope.
       *
       * The caller owns envelope construction — cloister already has a
       * ReceiptEnvelope encoder, and a second one here would be two
       * implementations of one wire format, which is how canonical encodings
       * drift apart.
       */
      signature: Uint8Array;
      /** The authority's epoch at signing time — the one the commitment names. */
      epoch: number;
    }
  | {
      ok: false;
      /** Exhaustive; switch on it. Only EPOCH_MISMATCH is retryable. */
      code: CommitmentErrorCode;
      message: string;
    };

/**
 * Outcome of a delegated JWT signing attempt (ADR-015).
 *
 * Union rather than throw, for the reasons on ReceiptSignResult: an RPC
 * rejection surfaces as an uncaught exception in the callee and stringifies
 * the error. None of these codes are retryable — each means the caller must
 * change what it sent.
 */
export type DelegatedJwtSignResult =
  | {
      ok: true;
      /** Raw 64-byte Ed25519 signature. The caller assembles the compact JWS. */
      signature: Uint8Array;
      /** kid of the DELEGATED key — not the CA master's. */
      kid: string;
    }
  | { ok: false; code: DelegatedJwtErrorCode; message: string };

export class SigningAuthority extends DurableObject<SigningAuthorityEnv> {
  #initialized = false;
  #signingKey: CryptoKey | null = null;
  #verifyKey: CryptoKey | null = null;
  /** Key storage mode — uses shared detectKeyStorage() for consistency with Worker. */
  get #keyStorageMode(): KeyStorageMode {
    const mode = detectKeyStorage(this.env as Record<string, unknown>);
    if (mode === "encrypted" && !this.env.NOTME_KEK_SECRET) {
      // Fail closed, same reasoning as validateKeyStorageConfig: proceeding
      // would persist the CA private key in cleartext while the operator
      // believes it is sealed. (Before notme-41d0d3 this threw for encrypted
      // mode unconditionally, which meant setting NOTME_KEK_SECRET — the very
      // thing that selects the mode — bricked the DO on boot.)
      throw new Error(
        "encrypted key storage selected but NOTME_KEK_SECRET is unset. " +
          "See docs/design/007-secretless-local-proxy.md.",
      );
    }
    return mode;
  }

  /**
   * Cached KEK, or null when this deployment stores keys in the clear.
   *
   * Cached per DO instance because HKDF runs on every call otherwise and
   * `ensureKeys` is on the hot path for every sign. Null is a real answer, not
   * a failure: `cf-managed` and `ephemeral` both legitimately have no KEK.
   */
  #kekPromise: Promise<CryptoKey> | null = null;
  /**
   * ECMAScript #private, NOT TypeScript `private`. The latter is erased at
   * compile time, so a `private` method is live on the DO's RPC surface — the
   * same trap ADR-016 records for #getAuthority(). rpc-surface.do.test.ts
   * caught this one: `getKek` appeared as method 47 of an allow-list pinned at
   * 46. It hands back a non-extractable CryptoKey so a leaked stub could not
   * export the KEK, but a capability nobody needs should not be reachable.
   */
  #getKek(): Promise<CryptoKey> | null {
    const secret = this.env.NOTME_KEK_SECRET;
    if (!secret) return null;
    this.#kekPromise ??= deriveKek(secret);
    return this.#kekPromise;
  }

  #ensureSchema(): void {
    if (this.#initialized) return;
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
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS dpop_jtis (
        jti        TEXT PRIMARY KEY,
        expires_at INTEGER NOT NULL
      )
    `);
    // Retired authority public keys, by epoch (ADR-014).
    //
    // `rotate()` DELETEs the keypair row and keeps a single prevKeyId/prevPubKey
    // slot, which the next rotation overwrites — retention depth one. That is
    // correct for 5-minute access tokens, where an old epoch is simply dead.
    //
    // Receipts are the first artifact whose verifiability must OUTLIVE
    // rotation. Interlace RECEIPTS.md §2.3 makes historical resolution a MUST
    // and names the failure mode: "without that, A can defeat audits by
    // aggressive key rotation." Under depth-one retention, two rotations make
    // every receipt naming epoch N permanently unverifiable — the actor voids
    // its own evidence with two administrative actions, and an auditor cannot
    // tell that apart from a forgery.
    //
    // PUBLIC KEYS ONLY. Nothing here is secret; the private key is still
    // destroyed on rotation, which is the point of rotating.
    //
    // Never pruned. Retention is the irreversible half — a key deleted is gone
    // for good, while a discovery endpoint can be added at any time. Serving
    // these at /.well-known/interlace/index.json per §2.3 is tracked
    // separately; persisting them cannot wait for it.
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS retired_keys (
        epoch      INTEGER PRIMARY KEY,
        key_id     TEXT NOT NULL,
        public_raw TEXT NOT NULL,
        retired_at INTEGER NOT NULL
      )
    `);
    // Delegated JWT signing keys, one per issuer (ADR-015).
    //
    // SEPARATE from the CA master, and that separation is the entire security
    // control. notme's own access tokens are at+jwt signed by the master with
    // iss=https://auth.notme.bot, and the SDK leaves `issuer` unchecked by
    // default — so an endpoint that signed a delegated caller's JWT with the
    // master key would let that caller mint a token every notme resource
    // server accepts, for any subject and any scope. A distinct key makes such
    // a token cryptographically unrelated to notme's own, rather than merely
    // wrongly-claimed and hopefully-noticed.
    //
    // Unlike receipts (ADR-014), nothing pins the key here: cloister's JWKS
    // publishes whatever pubkey its manifest binding holds and takes `kid`
    // from the manifest, so it is indifferent to which key it publishes. That
    // freedom is what makes separation possible; receipts had none.
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS delegated_jwt_keys (
        issuer      TEXT PRIMARY KEY,
        private_jwk TEXT NOT NULL,
        public_raw  TEXT NOT NULL,
        kid         TEXT NOT NULL,
        created_at  INTEGER NOT NULL
      )
    `);
    // Authorization codes for the /authorize redirect (ADR-013).
    //
    // Keyed by SHA-256 of the code, never the code itself: a code is a live
    // credential until redeemed, so a read of this storage must not yield
    // redeemable codes. Lookup is by hash, so this is also not a timing
    // oracle on the code value.
    //
    // `redirect_uri` is stored so redemption can require the presented one to
    // match (RFC 6749 §4.1.3) — that is what stops a code minted for one
    // destination being redeemed toward another. `code_challenge` is the
    // PKCE S256 challenge; it is what makes a code read out of a log inert
    // rather than merely short-lived.
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS auth_codes (
        code_hash      TEXT PRIMARY KEY,
        principal_id   TEXT NOT NULL,
        scopes         TEXT NOT NULL,
        audience       TEXT NOT NULL,
        redirect_uri   TEXT NOT NULL,
        code_challenge TEXT NOT NULL,
        expires_at     INTEGER NOT NULL
      )
    `);
    this.#initialized = true;
  }

  static async #keyIdFromSpki(spkiB64: string): Promise<string> {
    return keyIdFromSpki(spkiB64);
  }

  // Load or generate the authority keypair. Cached in memory for the DO lifetime.
  async getOrCreateSigningKey(): Promise<{
    signingKey: CryptoKey;
    verifyKey: CryptoKey;
    keyId: string;
  }> {
    if (this.#signingKey && this.#verifyKey) {
      const kid = this.#getKeyId();
      return {
        signingKey: this.#signingKey,
        verifyKey: this.#verifyKey,
        keyId: kid,
      };
    }

    this.#ensureSchema();

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
        // May be a sealed envelope or a legacy bare JWK — readStoredJwk
        // discriminates on an explicit marker and throws if a sealed row is
        // met with no KEK, rather than falling through to key generation and
        // silently invalidating every cert and token ever issued.
        const kek = this.#getKek();
        const resolvedKek = kek ? await kek : null;
        const { jwk, wasSealed } = await readStoredJwk(
          row.private_jwk,
          resolvedKek,
        );

        // Migrate in place. An operator who sets NOTME_KEK_SECRET on an
        // existing deployment expects the key to become sealed; without this
        // it would stay in cleartext until the next rotation, which may be
        // never. Best-effort: a failure here must not take down signing, since
        // the key itself is loaded fine either way.
        if (!wasSealed && resolvedKek) {
          try {
            this.ctx.storage.sql.exec(
              "UPDATE keys SET private_jwk = ? WHERE id = 'authority'",
              await serialiseJwkForStorage(jwk, resolvedKek),
            );
          } catch (e) {
            console.error("authority key re-seal failed (key still usable)", e);
          }
        }

        this.#signingKey = await crypto.subtle.importKey(
          "jwk",
          jwk,
          ED25519,
          false, // NON-EXTRACTABLE after import
          ["sign"],
        );
        const spkiBytes = Uint8Array.from(atob(row.public_spki), (c) =>
          c.charCodeAt(0),
        );
        this.#verifyKey = await crypto.subtle.importKey(
          "spki",
          spkiBytes,
          ED25519,
          true, // public key stays extractable (needed for JWKS, raw export)
          ["verify"],
        );
        let keyId = row.key_id;
        if (!keyId) {
          keyId = await SigningAuthority.#keyIdFromSpki(row.public_spki);
          this.ctx.storage.sql.exec(
            "UPDATE keys SET key_id = ? WHERE id = 'authority'",
            keyId,
          );
        }
        return {
          signingKey: this.#signingKey,
          verifyKey: this.#verifyKey,
          keyId,
        };
      }
    }

    // Generate the authority keypair
    const isEphemeral = this.#keyStorageMode === "ephemeral";
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
    const keyId = await SigningAuthority.#keyIdFromSpki(publicSpkiB64);

    if (isEphemeral) {
      // Store public key + key ID only — no private key material on disk
      this.ctx.storage.sql.exec(
        "INSERT OR REPLACE INTO keys (id, private_jwk, public_spki, key_id) VALUES ('authority', '', ?, ?)",
        publicSpkiB64,
        keyId,
      );
      this.#signingKey = kp.privateKey;
      this.#verifyKey = kp.publicKey;
    } else {
      // Persistent: export JWK, store, then re-import as non-extractable.
      // Sealed when a KEK is configured (notme-41d0d3); a bare JWK otherwise,
      // which is the pre-existing cf-managed behaviour and relies solely on
      // Cloudflare's encryption at rest.
      const privateJwk = (await crypto.subtle.exportKey(
        "jwk",
        kp.privateKey,
      )) as JsonWebKey;
      const kekForWrite = this.#getKek();
      this.ctx.storage.sql.exec(
        "INSERT INTO keys (id, private_jwk, public_spki, key_id) VALUES ('authority', ?, ?, ?)",
        await serialiseJwkForStorage(
          privateJwk,
          kekForWrite ? await kekForWrite : null,
        ),
        publicSpkiB64,
        keyId,
      );
      // Re-import as non-extractable — JWK is stored, no need to keep extractable
      this.#signingKey = await crypto.subtle.importKey(
        "jwk",
        privateJwk,
        ED25519,
        false,
        ["sign"],
      );
      this.#verifyKey = kp.publicKey;
    }

    await this.scheduleNextRefresh();
    return { signingKey: this.#signingKey, verifyKey: this.#verifyKey, keyId };
  }

  #getKeyId(): string {
    this.#ensureSchema();
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
    return {
      kty: "OKP",
      crv: "Ed25519",
      x,
      kid: keyId,
      use: "sig",
      alg: "EdDSA",
    };
  }

  // Self-signed X.509 CA certificate for CF mTLS trust store.
  // Cached in DO SQLite; invalidated on key rotation (key_id mismatch).
  async getCACertificatePem(): Promise<string> {
    this.#ensureSchema();
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS ca_cert (
        id     TEXT PRIMARY KEY DEFAULT 'cert',
        pem    TEXT NOT NULL,
        key_id TEXT NOT NULL
      )
    `);
    const currentKeyId = this.#getKeyId();
    const cached = this.ctx.storage.sql
      .exec("SELECT pem, key_id FROM ca_cert WHERE id = 'cert'")
      .toArray() as Array<{ pem: string; key_id: string }>;
    // v2: require CA:TRUE in cached cert (invalidate v1 certs without BasicConstraints)
    if (
      cached.length > 0 &&
      cached[0]!.key_id === currentKeyId &&
      cached[0]!.pem.includes("BEGIN CERTIFICATE")
    ) {
      // Check if cached cert has BasicConstraints by looking for the extension marker
      // If it was generated without extensions (v1), regenerate
      try {
        const { X509Certificate } = await import("@peculiar/x509");
        const x = new X509Certificate(cached[0]!.pem);
        const bc = x.getExtension("2.5.29.19"); // BasicConstraints OID
        if (bc) return cached[0]!.pem;
      } catch {
        /* regenerate */
      }
    }

    const { signingKey, verifyKey } = await this.getOrCreateSigningKey();
    const now = new Date();
    const notAfter = new Date(
      now.getTime() + 10 * 365.25 * 24 * 60 * 60 * 1000,
    );
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
        new KeyUsagesExtension(
          KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign,
          true,
        ),
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

  // `sign(data: ArrayBuffer)` — "sign arbitrary data with the authority key" —
  // was DELETED here (ADR-014, found in adversarial review of PR #61).
  //
  // It was exactly the universal forgery oracle that ADR-014 argues must not
  // exist: hand it a DER TBSCertificate and it returns a signature that
  // assembles into a certificate chaining to this authority, for any identity
  // and any scopes. It had zero callers — `grep -rn "\.sign("` over worker/
  // and packages/ found none outside its own tests — so nothing is lost.
  //
  // Not left in place with a warning comment, deliberately. An unused method
  // on a DO is one `env.X.sign(bytes)` away from being reachable, and it sat
  // adjacent to the carefully-gated `signReceiptCommitment` below where it
  // reads as the simpler, more general alternative. Signing must stay
  // format-specific: every path that touches the master key validates what it
  // is about to sign.

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

  /**
   * Atomically consume a DPoP proof JTI and mint its bound access token.
   *
   * SQLite statements run synchronously before the first await, so concurrent
   * RPCs against this singleton DO cannot both observe a fresh JTI. If minting
   * fails after insertion, the proof remains consumed and the client must retry
   * with a new proof.
   */
  async mintDPoPTokenOnce(params: {
    sub: string;
    scope: string;
    audience: string;
    jkt: string;
    proofJti: string;
    replayTtlSeconds?: number;
  }): Promise<
    { ok: true; accessToken: string } | { ok: false; reason: "proof_reused" }
  > {
    this.#ensureSchema();
    const now = Math.floor(Date.now() / 1000);
    const replayTtlSeconds = params.replayTtlSeconds ?? 600;

    this.ctx.storage.sql.exec(
      "DELETE FROM dpop_jtis WHERE expires_at <= ?",
      now,
    );
    this.ctx.storage.sql.exec(
      "INSERT OR IGNORE INTO dpop_jtis (jti, expires_at) VALUES (?, ?)",
      params.proofJti,
      now + replayTtlSeconds,
    );
    const [change] = [
      ...this.ctx.storage.sql.exec<{ inserted: number }>(
        "SELECT changes() AS inserted",
      ),
    ];
    if (change.inserted !== 1) {
      return { ok: false, reason: "proof_reused" };
    }

    const accessToken = await this.mintDPoPToken(params);
    return { ok: true, accessToken };
  }

  /**
   * Sign an Interlace 0.2.0 receipt commitment with the master key (ADR-014).
   *
   * SIGN-ONLY, and deliberately NOT a general signing primitive. The bytes are
   * validated and canonically re-encoded by `validateCommitment` before they
   * reach `crypto.subtle.sign`, because this same key signs X.509
   * `TBSCertificate` DER and `at+jwt` access tokens and the Interlace spec
   * signs the commitment with no domain separator. A method here that signed
   * whatever it was handed would let a caller submit a crafted
   * `TBSCertificate` and assemble a certificate chaining to this authority for
   * any identity and any scopes.
   *
   * `actor_fp` and `epoch` are DERIVED here from the authority's own state and
   * the commitment is rejected if it disagrees — the notme-6ad276 invariant:
   * facts about this authority are never taken from the caller.
   *
   * Returns the signature and the epoch. It cannot return key material:
   * `CryptoKey` is not Structured Cloneable and cannot cross the RPC boundary.
   */

  /**
   * The two commitment fields that are facts about THIS authority (ADR-014).
   *
   * Cloister needs both to construct a commitment, and `signReceiptCommitment`
   * rejects any commitment that disagrees — so without this it would have to
   * source them from `.well-known` and stay in sync with rotation on its own.
   * Serving them from the same place that enforces them removes a class of
   * "receipt rejected, epoch drifted" failures entirely.
   *
   * Cacheable, and worth caching — this is a DO round-trip that would
   * otherwise run on every proxied response. Only two things invalidate it:
   * an EPOCH_MISMATCH from signing, and an operator `rotate()`.
   *
   * Do NOT poll. `alarm()` calls `generateBundle()`, never `rotate()`, so the
   * epoch does not move on a timer. (An earlier version of this comment said
   * rotation was "alarm-driven" — that was wrong.)
   */
  /**
   * Resolve the public key that signed a given epoch's receipts (ADR-014).
   *
   * Answers the question RECEIPTS.md §2.2.2 step 2 asks at audit time: which
   * key verifies a receipt naming epoch N? The live `keys` table can only
   * answer for the current epoch, and it is keyed by keyId rather than epoch,
   * so historical resolution needs its own lookup.
   *
   * Returns raw base64 Ed25519 public key bytes — the same form `actor_fp` is
   * computed over — or null when the epoch is unknown. Null is honest rather
   * than an error: an auditor must be able to distinguish "notme does not have
   * this" from a transport failure.
   */
  async getEpochPublicKey(
    epoch: number,
  ): Promise<{
    keyId: string;
    publicRawB64: string;
    retiredAt: number | null;
  } | null> {
    this.#ensureSchema();

    const current = this.ctx.storage.sql
      .exec("SELECT epoch FROM state WHERE id = 'authority'")
      .toArray() as Array<{ epoch: number }>;
    if (current[0]?.epoch === epoch) {
      return {
        keyId: this.#getKeyId(),
        publicRawB64: await this.getPublicKeyRawB64(),
        retiredAt: null, // still active
      };
    }

    const rows = this.ctx.storage.sql
      .exec(
        "SELECT key_id, public_raw, retired_at FROM retired_keys WHERE epoch = ?",
        epoch,
      )
      .toArray() as Array<{
      key_id: string;
      public_raw: string;
      retired_at: number;
    }>;
    const row = rows[0];
    if (!row) return null;
    return {
      keyId: row.key_id,
      publicRawB64: row.public_raw,
      retiredAt: row.retired_at,
    };
  }

  async getReceiptFacts(): Promise<{ actorFp: Uint8Array; epoch: number }> {
    this.#ensureSchema();
    const { verifyKey } = await this.getOrCreateSigningKey();

    // actor_fp per RECEIPTS.md §2.1: SHA-256 of the actor's master PUBLIC key.
    // Over the RAW Ed25519 key, which is what a verifier resolving
    // `.well-known` gets — hashing a PEM or SPKI wrapper instead would yield a
    // fingerprint no verifier can reproduce.
    const rawPub = new Uint8Array(
      (await crypto.subtle.exportKey("raw", verifyKey)) as ArrayBuffer,
    );
    const actorFp = new Uint8Array(
      await crypto.subtle.digest("SHA-256", rawPub),
    );

    const rows = this.ctx.storage.sql
      .exec("SELECT epoch FROM state WHERE id = 'authority'")
      .toArray() as Array<{ epoch: number }>;

    return { actorFp, epoch: rows[0]!.epoch };
  }

  /**
   * Get (or create on first use) the delegated signing key for `issuer`.
   *
   * Returns PUBLIC material only — the raw public key for cloister to publish
   * in its JWKS, and the kid. The private half is generated here, stored as a
   * non-extractable JWK, and never crosses the RPC boundary.
   *
   * Created lazily rather than provisioned: the operator's act of allowlisting
   * an issuer is the authorization, and a separate provisioning step would be
   * one more place for the allowlist and the keyring to disagree.
   */
  async getDelegatedJwtKey(
    issuer: string,
  ): Promise<{ publicRawB64: string; kid: string }> {
    this.#ensureSchema();

    const rows = this.ctx.storage.sql
      .exec(
        "SELECT public_raw, kid FROM delegated_jwt_keys WHERE issuer = ?",
        issuer,
      )
      .toArray() as Array<{ public_raw: string; kid: string }>;
    if (rows[0]) {
      return { publicRawB64: rows[0].public_raw, kid: rows[0].kid };
    }

    const kp = (await crypto.subtle.generateKey(ED25519, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const privJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
    const delegatedKek = this.#getKek();
    const rawPub = new Uint8Array(
      (await crypto.subtle.exportKey("raw", kp.publicKey)) as ArrayBuffer,
    );
    const publicRawB64 = btoa(String.fromCharCode(...rawPub));
    const spki = new Uint8Array(
      (await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer,
    );
    const kid = await keyIdFromSpki(btoa(String.fromCharCode(...spki)));

    this.ctx.storage.sql.exec(
      `INSERT OR IGNORE INTO delegated_jwt_keys
         (issuer, private_jwk, public_raw, kid, created_at) VALUES (?, ?, ?, ?, ?)`,
      issuer,
      // Sealed alongside the CA master (notme-41d0d3). ADR-015 added this
      // table into the same plaintext-at-rest posture it inherited; the
      // separate-key control still held cryptographically, but at rest both
      // keys were equally exposed.
      await serialiseJwkForStorage(
        privJwk as JsonWebKey,
        delegatedKek ? await delegatedKek : null,
      ),
      publicRawB64,
      kid,
      Math.floor(Date.now() / 1000),
    );

    // Re-read rather than returning what we just generated: INSERT OR IGNORE
    // means a concurrent first-use may have won, and both callers must see the
    // same key or they publish different JWKS for one issuer.
    const after = this.ctx.storage.sql
      .exec(
        "SELECT public_raw, kid FROM delegated_jwt_keys WHERE issuer = ?",
        issuer,
      )
      .toArray() as Array<{ public_raw: string; kid: string }>;
    return { publicRawB64: after[0]!.public_raw, kid: after[0]!.kid };
  }

  /**
   * Sign a JWS signing input on a delegated issuer's behalf (ADR-015).
   *
   * NEVER uses the CA master key. The header and payload are validated first —
   * see src/jwt/delegated-claims.ts for which footguns each check closes — and
   * the signing input is returned by the validator rather than re-derived
   * here, so there is no gap between what was checked and what gets signed.
   */
  async signDelegatedJwt(params: {
    issuer: string;
    headerB64: string;
    payloadB64: string;
  }): Promise<DelegatedJwtSignResult> {
    this.#ensureSchema();
    const { kid } = await this.getDelegatedJwtKey(params.issuer);

    const rows = this.ctx.storage.sql
      .exec(
        "SELECT private_jwk FROM delegated_jwt_keys WHERE issuer = ?",
        params.issuer,
      )
      .toArray() as Array<{ private_jwk: string }>;

    const { validateDelegatedJws, DelegatedJwtError } = await import(
      "./jwt/delegated-claims"
    );
    let signingInput: Uint8Array;
    try {
      signingInput = validateDelegatedJws(params.headerB64, params.payloadB64, {
        issuer: params.issuer,
        kid,
      });
    } catch (e: any) {
      if (e instanceof DelegatedJwtError) {
        return { ok: false, code: e.code, message: e.message };
      }
      throw e;
    }

    // Same dual-shape read as the CA master: sealed for deployments with a
    // KEK, bare JWK for legacy rows. No in-place re-seal here — unlike the
    // master this runs inside a request-path sign, and a storage write on the
    // signing path is a failure mode not worth adding. Delegated rows migrate
    // when getDelegatedJwtKey next creates one, or via the master's path.
    const delegatedReadKek = this.#getKek();
    const { jwk: delegatedJwk } = await readStoredJwk(
      rows[0]!.private_jwk,
      delegatedReadKek ? await delegatedReadKek : null,
    );
    const signingKey = await crypto.subtle.importKey(
      "jwk",
      delegatedJwk,
      ED25519,
      false, // non-extractable once imported
      ["sign"],
    );
    const sig = new Uint8Array(
      await crypto.subtle.sign(ED25519, signingKey, signingInput),
    );
    return { ok: true, signature: sig, kid };
  }

  async signReceiptCommitment(
    commitment: Uint8Array,
  ): Promise<ReceiptSignResult> {
    const { signingKey } = await this.getOrCreateSigningKey();
    const { actorFp, epoch } = await this.getReceiptFacts();

    const { validateCommitment, CommitmentError } =
      await import("./receipts/commitment");

    let canonical: Uint8Array;
    try {
      canonical = validateCommitment(commitment, {
        actorFp,
        epoch,
        nowMs: Date.now(),
      });
    } catch (e: any) {
      // A discriminated union, not a throw, and not merely for tidiness.
      //
      // Rejecting across an RPC boundary surfaces as an uncaught exception in
      // the callee's context even when the caller handles it — enough to fail
      // the test run outright. It also stringifies the error, so a caller
      // cannot branch on anything but message text.
      //
      // Returning a code is what makes the documented recovery possible:
      // cloister re-reads getReceiptFacts() on EPOCH_MISMATCH rather than
      // polling for rotation. Matches `mintDPoPTokenOnce` above.
      if (e instanceof CommitmentError) {
        return { ok: false, code: e.code, message: e.message };
      }
      throw e; // not a validation failure — a real fault, let it surface
    }

    const signature = new Uint8Array(
      await crypto.subtle.sign(ED25519, signingKey, canonical),
    );
    return { ok: true, signature, epoch };
  }

  /**
   * Issue an authorization code for the /authorize redirect (ADR-013).
   *
   * Returns the code in the clear exactly once — to the caller that will put
   * it in the redirect URL. Only its SHA-256 is persisted.
   *
   * TTL is 60s, not the RFC 6749 §4.1.2 maximum of 600s: the code is redeemed
   * by a server that already holds the PKCE verifier, so the window that
   * needs covering is one round-trip. A short TTL is the cheapest defense and
   * costs nothing a correct client will notice.
   */
  async createAuthorizationCode(params: {
    principalId: string;
    scopes: string[];
    audience: string;
    redirectUri: string;
    codeChallenge: string;
    ttlSeconds?: number;
  }): Promise<{ code: string; expiresAt: number }> {
    this.#ensureSchema();
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + (params.ttlSeconds ?? 60);

    // 32 bytes of CSPRNG. The code is the only thing standing between a log
    // reader and a redemption attempt (PKCE stands behind it), so it must not
    // be guessable.
    const raw = new Uint8Array(32);
    crypto.getRandomValues(raw);
    const code = encodeBase64urlNoPadding(raw);

    this.ctx.storage.sql.exec(
      "DELETE FROM auth_codes WHERE expires_at <= ?",
      now,
    );
    this.ctx.storage.sql.exec(
      `INSERT INTO auth_codes
         (code_hash, principal_id, scopes, audience, redirect_uri, code_challenge, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      await sha256Base64url(code),
      params.principalId,
      params.scopes.join(" "),
      params.audience,
      params.redirectUri,
      params.codeChallenge,
      expiresAt,
    );

    return { code, expiresAt };
  }

  /**
   * Atomically redeem an authorization code and mint its access token.
   *
   * Single-use is enforced by DELETE-then-check-changes() rather than
   * SELECT-then-DELETE: the delete and its `changes()` read both run
   * synchronously before the first await, so two concurrent redemptions of
   * the same code cannot both see it present. Same discipline as
   * `mintDPoPTokenOnce`. A SELECT-first shape would be a TOCTOU window, and
   * the whole point of a code is that it works exactly once.
   *
   * The row is consumed BEFORE PKCE is checked, deliberately: a code whose
   * verifier fails is a code that has been observed by someone who should not
   * have it, so burning it is the correct response, not a bug. The caller
   * restarts the flow.
   */
  async redeemAuthorizationCode(params: {
    code: string;
    codeVerifier: string;
    redirectUri: string;
  }): Promise<
    | { ok: true; accessToken: string }
    | { ok: false; reason: "invalid_grant" | "invalid_request" }
  > {
    this.#ensureSchema();
    const now = Math.floor(Date.now() / 1000);
    const codeHash = await sha256Base64url(params.code);

    const rows = [
      ...this.ctx.storage.sql.exec<{
        principal_id: string;
        scopes: string;
        audience: string;
        redirect_uri: string;
        code_challenge: string;
        expires_at: number;
      }>(
        `DELETE FROM auth_codes WHERE code_hash = ? RETURNING
           principal_id, scopes, audience, redirect_uri, code_challenge, expires_at`,
        codeHash,
      ),
    ];
    const row = rows[0];
    // Unknown, already-redeemed and expired all collapse to one answer.
    // Distinguishing them would tell an attacker probing with harvested codes
    // which ones were real.
    if (!row || row.expires_at <= now) {
      return { ok: false, reason: "invalid_grant" };
    }

    // RFC 6749 §4.1.3 — the redirect_uri presented at redemption must equal
    // the one the code was issued against, so a code cannot be walked to a
    // different destination.
    if (row.redirect_uri !== params.redirectUri) {
      return { ok: false, reason: "invalid_grant" };
    }

    // PKCE S256 (RFC 7636 §4.6). This is what makes a code read out of a log
    // useless: the verifier never left the client that started the flow.
    const challenge = await sha256Base64url(params.codeVerifier);
    if (challenge !== row.code_challenge) {
      return { ok: false, reason: "invalid_grant" };
    }

    const accessToken = await this.mintRedirectToken({
      sub: row.principal_id,
      scope: row.scopes,
      audience: row.audience,
    });
    return { ok: true, accessToken };
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
    const result = await mintGHABridgeCert(
      subject,
      publicKeyPem,
      signingKey,
      ttlMs,
    );
    return {
      ...result,
      authority: { epoch: state.epoch, key_id: state.keyId },
    };
  }

  // Mint a bridge cert PAIR (P-256 mTLS + Ed25519 signing) — 008 PoP exchange.
  // Both certs carry the same WIMSE identity, scopes, epoch, and peer binding.
  async mintBridgeCertPair(params: {
    subject: string;
    identity: string;
    mtlsPublicKeyPem: string;
    signingPublicKeyPem: string;
    scopes: string[];
    authMethod: string;
    ttlMs?: number;
  }): Promise<
    import("./cert-authority").BridgeCertPairResult & {
      authority: { epoch: number; key_id: string };
    }
  > {
    const { signingKey } = await this.getOrCreateSigningKey();
    const state = await this.getAuthorityState();
    const { mintBridgeCertPair } = await import("./cert-authority");
    const result = await mintBridgeCertPair(
      params.subject,
      params.identity,
      params.mtlsPublicKeyPem,
      params.signingPublicKeyPem,
      signingKey,
      {
        scopes: params.scopes,
        epoch: state.epoch,
        authMethod: params.authMethod,
        ttlMs: params.ttlMs,
      },
    );
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
    this.#ensureSchema();
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

    this.#ensureSchema();

    // Advance seqno
    this.ctx.storage.sql.exec(
      "UPDATE state SET seqno = seqno + 1 WHERE id = 'authority'",
    );
    const rows = this.ctx.storage.sql
      .exec("SELECT epoch, seqno FROM state WHERE id = 'authority'")
      .toArray() as Array<{ epoch: number; seqno: number }>;
    const { epoch, seqno } = rows[0]!;

    // Build the unsigned bundle. During a rotation grace window we ALSO publish
    // the previous key + its keyId, so tokens the old key signed still verify
    // until they drain (notme-54f84b). rotate() preserves the old kid + its
    // public key; both must appear in the SIGNED bundle — bundleCanonical covers
    // `keys` and `prevKeyId`, so consumers can resolve the prev key AND the
    // revocation check (token.keyId === bundle.prevKeyId) sees it.
    const keys: Record<string, string> = { [keyId]: pubKeyB64 };
    const prevKeyId =
      (await this.ctx.storage.get<string>("prevKeyId")) ?? undefined;
    const prevPubKey =
      (await this.ctx.storage.get<string>("prevPubKey")) ?? undefined;
    const hasPrev = !!prevKeyId && prevKeyId !== keyId && !!prevPubKey;
    if (hasPrev) keys[prevKeyId] = prevPubKey;

    const bundle: Omit<CABundle, "signature"> & { signature?: string } = {
      epoch,
      seqno,
      keys,
      keyId,
      ...(hasPrev ? { prevKeyId } : {}),
      issuedAt: Math.floor(Date.now() / 1000),
    };

    // Canonical bytes for signing — single source of truth in revocation.ts.
    // Per ADR-010: canonical CBOR (RFC 8949 §4.2), matching signet protocol.
    // bundleCanonical takes Omit<CABundle, "signature">; pre-signature bundle
    // is assignable directly (no cast).
    const canonical = bundleCanonical(bundle);

    // Sign
    const sig = await crypto.subtle.sign(ED25519, signingKey, canonical);
    const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));

    return { ...bundle, signature: sigB64 } as CABundle;
  }

  // Rotate the CA key. Increments epoch, generates new keypair.
  // Previous keyId is preserved in the bundle as prevKeyId for graceful transition.
  async rotate(): Promise<{ newKeyId: string; epoch: number }> {
    this.#ensureSchema();
    const oldKeyId = this.#getKeyId();
    // Capture the old PUBLIC key BEFORE deleting it. The grace window needs it
    // published (generateBundle above) so tokens the old key signed still verify
    // until they expire; storing only the id (prevKeyId) left the pubkey gone
    // and the grace window broken (notme-54f84b).
    const oldPubKeyB64 = await this.getPublicKeyRawB64();

    // Archive the outgoing PUBLIC key by epoch BEFORE the delete (ADR-014).
    //
    // Ordering is the whole point: after the DELETE below there is nothing
    // left to archive, and the prevPubKey slot written further down holds
    // exactly one generation. Receipts must stay verifiable for arbitrary
    // later audit (RECEIPTS.md §2.3), so the key that signed epoch N has to
    // survive epochs N+2, N+3, … — otherwise the actor voids its own evidence
    // by rotating twice.
    //
    // INSERT OR IGNORE, not REPLACE: an epoch's public key is immutable once
    // recorded. Overwriting one would rewrite history, which is precisely the
    // capability an audit trail exists to deny.
    const oldEpochRows = this.ctx.storage.sql
      .exec("SELECT epoch FROM state WHERE id = 'authority'")
      .toArray() as Array<{ epoch: number }>;
    this.ctx.storage.sql.exec(
      "INSERT OR IGNORE INTO retired_keys (epoch, key_id, public_raw, retired_at) VALUES (?, ?, ?, ?)",
      oldEpochRows[0]!.epoch,
      oldKeyId,
      oldPubKeyB64,
      Math.floor(Date.now() / 1000),
    );

    // Delete old key
    this.ctx.storage.sql.exec("DELETE FROM keys WHERE id = 'authority'");
    this.#signingKey = null;
    this.#verifyKey = null;

    // Increment epoch
    this.ctx.storage.sql.exec(
      "UPDATE state SET epoch = epoch + 1, seqno = seqno + 1 WHERE id = 'authority'",
    );

    // Generate new key (getOrCreateSigningKey will create since we deleted)
    const { keyId: newKeyId } = await this.getOrCreateSigningKey();

    // Store prevKeyId + prevPubKey for the transition window (both needed so
    // generateBundle can republish the previous key for grace-window verify).
    await this.ctx.storage.put("prevKeyId", oldKeyId);
    await this.ctx.storage.put("prevPubKey", oldPubKeyB64);

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
    this.#ensureSchema();
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
    const invite = createInvite(
      this.ctx.storage.sql,
      createdBy,
      scopes,
      ttlSeconds,
    );
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
    const { createPrincipal, grantCapability } =
      await import("./auth/principals");
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
    linkFederatedIdentity(
      this.ctx.storage.sql,
      principalId,
      provider,
      providerSub,
    );
  }

  async findPrincipalByOIDC(
    provider: string,
    providerSub: string,
  ): Promise<string | null> {
    const { findPrincipalByFederated } = await import("./auth/principals");
    return findPrincipalByFederated(
      this.ctx.storage.sql,
      provider,
      providerSub,
    );
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
  ): Promise<
    Array<{ provider: string; subject: string; connectedAt: string }>
  > {
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
    this.ctx.storage.sql.exec(
      "UPDATE bootstrap SET used = 1 WHERE id = 'code'",
    );
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
    console.log(
      [
        "",
        "=".repeat(50),
        "BOOTSTRAP CODE: " + code,
        "Enter this at auth.notme.bot/login to register the admin passkey.",
        "Single-use. Expires in 15 minutes.",
        "=".repeat(50),
        "",
      ].join("\n"),
    );
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
      .exec(
        "SELECT code, created_at FROM bootstrap WHERE id = 'code' AND used = 0",
      )
      .toArray() as Array<{ code: string; created_at: string }>;

    const { timingSafeEqual } = await import("./auth/timing-safe");
    if (rows.length === 0 || !(await timingSafeEqual(rows[0]!.code, code)))
      return false;

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
  //
  // Hardening (notme-5c2511 EPIC, post 2026-05-10 cautionary-tale review):
  //   - alarm_health table tracks failure_count, total_fires, last_fire_at,
  //     last_outcome, first_fire_at.
  //   - Circuit breaker: after MAX_CONSECUTIVE_ALARM_FAILURES consecutive
  //     failures, alarm() stops re-arming. Manual recovery via
  //     resetAlarmHealth() RPC.
  //   - Defense-in-depth: re-arm goes through getAlarm() check first
  //     (mirrors scheduleNextRefresh's pattern).

  #alarmHealthInitialized = false;

  #ensureAlarmHealthSchema(): void {
    if (this.#alarmHealthInitialized) return;
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS alarm_health (
        id              TEXT PRIMARY KEY DEFAULT 'authority',
        failure_count   INTEGER NOT NULL DEFAULT 0,
        total_fires     INTEGER NOT NULL DEFAULT 0,
        last_fire_at    INTEGER NOT NULL DEFAULT 0,
        last_outcome    TEXT    NOT NULL DEFAULT '',
        first_fire_at   INTEGER NOT NULL DEFAULT 0
      )
    `);
    this.ctx.storage.sql.exec(
      "INSERT OR IGNORE INTO alarm_health (id) VALUES ('authority')",
    );
    this.#alarmHealthInitialized = true;
  }

  #readAlarmHealthRow(): {
    failure_count: number;
    total_fires: number;
    last_fire_at: number;
    last_outcome: string;
    first_fire_at: number;
  } {
    this.#ensureAlarmHealthSchema();
    const rows = this.ctx.storage.sql
      .exec(
        "SELECT failure_count, total_fires, last_fire_at, last_outcome, first_fire_at FROM alarm_health WHERE id = 'authority'",
      )
      .toArray() as Array<{
      failure_count: number;
      total_fires: number;
      last_fire_at: number;
      last_outcome: string;
      first_fire_at: number;
    }>;
    return (
      rows[0] ?? {
        failure_count: 0,
        total_fires: 0,
        last_fire_at: 0,
        last_outcome: "",
        first_fire_at: 0,
      }
    );
  }

  async scheduleNextRefresh(): Promise<void> {
    const current = await this.ctx.storage.getAlarm();
    if (!current) {
      await this.ctx.storage.setAlarm(Date.now() + BUNDLE_REFRESH_MS);
    }
  }

  override async alarm(): Promise<void> {
    const now = Date.now();
    this.#ensureAlarmHealthSchema();

    // Read pre-fire state for the breaker decision.
    // Note: counters are written via atomic SQL increments below
    // (`field = field + 1`), not via TS-computed read-modify-write — so
    // concurrent fires (per the comments below on workerd-local quirks)
    // can't lose counter increments.
    const preRows = this.ctx.storage.sql
      .exec(
        "SELECT failure_count, last_outcome, first_fire_at FROM alarm_health WHERE id = 'authority'",
      )
      .toArray() as Array<{
      failure_count: number;
      last_outcome: string;
      first_fire_at: number;
    }>;
    const pre = preRows[0] ?? {
      failure_count: 0,
      last_outcome: "",
      first_fire_at: 0,
    };

    // Circuit breaker — stop re-arming if too many consecutive failures.
    // Operator must call resetAlarmHealth() to recover.
    //
    // Even though we early-return without doing the bundle work, we DO
    // record the fire in alarm_health (atomic increment). Otherwise total_fires
    // would undercount the actual alarm fires that occurred — important for
    // post-mortem ("how many fires did we eat after the breaker tripped").
    if (pre.failure_count >= MAX_CONSECUTIVE_ALARM_FAILURES) {
      console.error(
        `[signing-authority] CIRCUIT BREAKER OPEN: ${pre.failure_count} consecutive ` +
          `alarm failures. Last outcome: "${pre.last_outcome}". ` +
          `Not re-arming. Manual recovery via resetAlarmHealth() RPC.`,
      );
      this.ctx.storage.sql.exec(
        "UPDATE alarm_health SET total_fires = total_fires + 1, last_fire_at = ?, last_outcome = 'skipped: circuit breaker open' WHERE id = 'authority'",
        now,
      );
      return; // do NOT re-arm
    }

    // Set first_fire_at on the very first fire (idempotent: only updates
    // when first_fire_at is still 0).
    if (pre.first_fire_at === 0) {
      this.ctx.storage.sql.exec(
        "UPDATE alarm_health SET first_fire_at = ? WHERE id = 'authority' AND first_fire_at = 0",
        now,
      );
    }

    let success = false;
    let outcome: string;
    try {
      const bundle = await this.generateBundle();
      if (this.env.CA_BUNDLE_CACHE) {
        await this.env.CA_BUNDLE_CACHE.put(
          "bundle:current",
          JSON.stringify(bundle),
        );
      }
      success = true;
      outcome = "success";
    } catch (e) {
      console.error("[signing-authority] bundle refresh failed:", e);
      const msg = (e as Error)?.message ?? "unknown";
      outcome = `error: ${msg.slice(0, 200)}`;
    }

    // Atomic update — `total_fires = total_fires + 1` and (on failure)
    // `failure_count = failure_count + 1` happen in SQL, so concurrent fires
    // can't drop increments. failure_count resets to 0 on success.
    if (success) {
      this.ctx.storage.sql.exec(
        "UPDATE alarm_health SET failure_count = 0, total_fires = total_fires + 1, last_fire_at = ?, last_outcome = ? WHERE id = 'authority'",
        now,
        outcome,
      );
    } else {
      this.ctx.storage.sql.exec(
        "UPDATE alarm_health SET failure_count = failure_count + 1, total_fires = total_fires + 1, last_fire_at = ?, last_outcome = ? WHERE id = 'authority'",
        now,
        outcome,
      );
    }

    // Re-read failure_count after the atomic update so we can detect
    // a just-tripped breaker on THIS fire (off-by-one fix). If the
    // increment from THIS fire pushed us to >= threshold, do not re-arm.
    // Without this re-check, the breaker would only trip on the NEXT fire,
    // leaking one extra alarm cycle past the policy threshold.
    const postRows = this.ctx.storage.sql
      .exec("SELECT failure_count FROM alarm_health WHERE id = 'authority'")
      .toArray() as Array<{ failure_count: number }>;
    const postFailureCount = postRows[0]?.failure_count ?? 0;
    if (postFailureCount >= MAX_CONSECUTIVE_ALARM_FAILURES) {
      console.error(
        `[signing-authority] CIRCUIT BREAKER TRIPPED on this fire: ` +
          `${postFailureCount} consecutive failures. ` +
          `Not re-arming. Manual recovery via resetAlarmHealth() RPC.`,
      );
      return; // do NOT re-arm — breaker tripped on this fire
    }

    // Re-arm with defense-in-depth getAlarm() check.
    // CF's contract says alarm() consumed the prior alarm so getAlarm() returns
    // null here — but checking first costs nothing and protects against
    // unforeseen runtime quirks (manual alarm() calls in tests, future CF
    // runtime changes, parallel-execution edge cases in workerd-local mode).
    if (!(await this.ctx.storage.getAlarm())) {
      await this.ctx.storage.setAlarm(Date.now() + BUNDLE_REFRESH_MS);
    }
  }

  /**
   * Manual recovery from the circuit-breaker tripped state.
   * Resets failure_count to 0 and re-arms one cycle.
   * Total fires + first_fire_at are preserved for audit history.
   */
  async resetAlarmHealth(): Promise<{
    reset: true;
    rearmed: boolean;
    previousFailureCount: number;
  }> {
    const before = this.#readAlarmHealthRow();
    // Reset failure_count + outcome but DO NOT update last_fire_at — a reset
    // is not an alarm fire, and observability/audit consumers reading
    // last_fire_at expect "when did alarm() last fire," not "when was the
    // last administrative action." If a "last reset at" timestamp is wanted
    // later, add it as a separate column.
    this.ctx.storage.sql.exec(
      "UPDATE alarm_health SET failure_count = 0, last_outcome = 'manually_reset' WHERE id = 'authority'",
    );
    let rearmed = false;
    if (!(await this.ctx.storage.getAlarm())) {
      await this.ctx.storage.setAlarm(Date.now() + BUNDLE_REFRESH_MS);
      rearmed = true;
    }
    return {
      reset: true,
      rearmed,
      previousFailureCount: before.failure_count,
    };
  }

  /**
   * Minimum total_fires for `driftRatio` to be considered meaningful.
   * Below this, the average is too noisy (single fire over short elapsed
   * time → arbitrarily large rate). At 3 fires the average is anchored
   * by ~12 minutes of cadence-paced data, enough for sustained drift to
   * surface above startup noise.
   */
  static readonly DRIFT_RATIO_WARMUP_FIRES = 3;

  /**
   * DO-internal alarm-loop observability.
   *
   * Returns the current alarm_health row plus derived rates for
   * runaway-alarm detection. The driftRatio is the runaway smoking gun —
   * BUT only after warmup. During startup (first ~12 minutes / 3 fires)
   * the average over a small denominator produces noisy values; consumers
   * MUST gate runaway alerts on `warmupComplete === true` before treating
   * `driftRatio > 1` as an anomaly. After warmup, sustained driftRatio
   * above ~1.2 indicates the alarm is firing faster than the
   * BUNDLE_REFRESH_MS cadence prescribes.
   */
  async getAlarmHealth(): Promise<{
    totalFires: number;
    failureCount: number;
    lastFireAt: number;
    lastOutcome: string;
    firstFireAt: number;
    firesPerHour: number;
    expectedFiresPerHour: number;
    driftRatio: number;
    warmupComplete: boolean;
    circuitBreakerOpen: boolean;
  }> {
    const health = this.#readAlarmHealthRow();
    const now = Date.now();
    const elapsedHours =
      health.first_fire_at > 0
        ? Math.max((now - health.first_fire_at) / 3_600_000, 1 / 3600)
        : 0;
    const firesPerHour =
      elapsedHours > 0 ? health.total_fires / elapsedHours : 0;
    const expectedFiresPerHour = 3_600_000 / BUNDLE_REFRESH_MS;
    const driftRatio =
      expectedFiresPerHour > 0 ? firesPerHour / expectedFiresPerHour : 0;
    return {
      totalFires: health.total_fires,
      failureCount: health.failure_count,
      lastFireAt: health.last_fire_at,
      lastOutcome: health.last_outcome,
      firstFireAt: health.first_fire_at,
      firesPerHour,
      expectedFiresPerHour,
      driftRatio,
      warmupComplete:
        health.total_fires >= SigningAuthority.DRIFT_RATIO_WARMUP_FIRES,
      circuitBreakerOpen:
        health.failure_count >= MAX_CONSECUTIVE_ALARM_FAILURES,
    };
  }
}
