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
  bootstrapAttestedSubject,
  mayBootstrapFromAttestation,
} from "./auth/bootstrap-policy";
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
  /**
   * Expected `aud` for a GitHub OIDC token presented to `mintBridgeCert`.
   *
   * READ FROM THE DO'S OWN ENV, never from the caller's proof envelope
   * (notme-51ccd7). An audience a caller can supply is an audience a caller
   * can widen, which would hand back the whole defect in a new wrapper —
   * so `MintBridgeCertProof` deliberately has no `audience` field. Same
   * default as the route's `getConfig` so the two cannot disagree.
   */
  GHA_CERT_AUDIENCE?: string;
  NOTME_KEY_STORAGE?: string;
  NOTME_KEK_SECRET?: string;
  /**
   * Operator-set first-boot secret (notme-addef9). A SECRET, never a `[vars]`
   * entry — it grants `authorityManage`, and vars are readable from the
   * dashboard and printed in deploy output.
   *
   * Its purpose is that setting it requires control of the DEPLOYMENT, where
   * the mechanism it replaces required only the ability to send an
   * unauthenticated HTTP request and read a log.
   */
  BOOTSTRAP_CODE?: string;
  /**
   * The one GitHub workflow identity permitted to bootstrap this authority —
   * the full OIDC `sub`, e.g. `repo:owner/name:ref:refs/heads/main`.
   *
   * A `[vars]` entry, NOT a secret, and the distinction is the point: it is
   * an identity, so there is nothing to leak and nothing to read out of a
   * log. Security comes from GitHub's signature over the token, not from
   * hiding this value — which is exactly the posture notme argues for
   * everywhere else and did not practise at first boot (notme-addef9).
   */
  BOOTSTRAP_GHA_SUBJECT?: string;
  /**
   * This deployment's authority origin. Tokens minted here carry it as `iss`
   * (notme-28baf2) — a DO that hardcoded the issuer made staging assert the
   * production one while signing with the staging key.
   */
  SIGNET_AUTHORITY_URL?: string;
  /**
   * CSV of resource servers this deployment's tokens may be addressed to.
   * Read here, not only in the routes, because `mintBridgeCert`'s
   * `notme-access-token` proof accepts a token WITHOUT a route in front of it
   * (rig-098326) — and src/allowed-audiences.ts's rule is that every path
   * which mints or spends an access token checks this set. Empty or absent
   * falls back to DEFAULT_ALLOWED_AUDIENCES.
   */
  ALLOWED_AUDIENCES?: string;
}

/**
 * The self-signed CA certificate's subject DN.
 *
 * Production keeps the exact historical literal, because the CA cert is
 * generated once per authority and anything pinning the existing subject must
 * keep matching. A NON-production authority gets its host appended, so a
 * verifier inspecting the issuing CA can tell the two apart — previously both
 * environments minted "CN=signet-authority,O=notme" byte-identically, and the
 * only difference between a staging cert and a production one was which key
 * signed it (notme-1532eb).
 *
 * Takes effect only for NEWLY created authorities: the CA cert is created once
 * and stored, so an existing staging DO keeps its production-shaped subject
 * until recreated.
 */
export function caSubjectForEnv(env: { SIGNET_AUTHORITY_URL?: string }): string {
  const PRODUCTION_SUBJECT = "CN=signet-authority,O=notme";
  if (!env.SIGNET_AUTHORITY_URL) return PRODUCTION_SUBJECT;
  let host: string;
  try {
    host = new URL(env.SIGNET_AUTHORITY_URL).host;
  } catch {
    return PRODUCTION_SUBJECT;
  }
  if (!host || host === "auth.notme.bot") return PRODUCTION_SUBJECT;
  return `CN=signet-authority ${host},O=notme`;
}

/**
 * Whether a bootstrap code is available, and if so what it is.
 *
 * A bare `string | null` let the caller DISCARD the result: worker.ts called
 * this for its side effect (mint + log) and then answered "bootstrap code
 * required — check Worker logs" unconditionally. In the closed case nothing
 * was logged, so an operator was sent to hunt for a UUID that does not exist
 * (notme-addef9). Making the two states a discriminated union means a caller
 * has to look at which one it got.
 */
export type BootstrapState =
  | { status: "issued"; code: string }
  | { status: "closed" };

/**
 * The operator-set bootstrap secret, or null.
 *
 * Trimmed and length-checked: `wrangler secret put` with an empty or
 * whitespace value would otherwise arm an authority with a secret that a
 * caller could guess by sending nothing. A minimum length matters because
 * this value grants `authorityManage` — the review of notme-976385 already
 * established that a bootstrap credential is an admin credential.
 */
function bootstrapSecret(env: { BOOTSTRAP_CODE?: string }): string | null {
  const raw = env.BOOTSTRAP_CODE?.trim();
  return raw && raw.length >= 16 ? raw : null;
}



/**
 * What a caller may learn about bootstrap WITHOUT causing anything to happen
 * (notme-addef9).
 *
 * Deliberately carries no code in any variant. This is the answer given to an
 * unauthenticated request, and the whole point of the split is that asking
 * cannot produce a credential.
 */
export type BootstrapReadState =
  /** An authenticator exists; bootstrap is over. */
  | { status: "closed" }
  /** No authenticator, and no operator has armed one. Nobody can bootstrap. */
  | { status: "unconfigured" }
  /**
   * No authenticator, and at least one bootstrap mechanism is armed.
   *
   * `methods` says WHICH, because the register/options 401 is written from
   * this and used to name a path that could not do the job: it told a fresh
   * deployer to "bootstrap via GitHub OIDC at /cert/gha" when that route
   * granted bridgeCert and created no principal at all. A message may only
   * offer what is actually armed (notme-addef9).
   */
  | { status: "armed"; methods: BootstrapMethod[] };

/** `secret` = BOOTSTRAP_CODE; `gha-oidc` = an attested workflow identity. */
export type BootstrapMethod = "secret" | "gha-oidc";

/** GitHub's OIDC issuer — the provider recorded for an attested bootstrap. */
const GHA_OIDC_ISSUER = "https://token.actions.githubusercontent.com";

/**
 * Evidence that entitles a caller to a subject — NOT the subject itself
 * (notme-51ccd7).
 *
 * `mintBridgeCert` used to take `subject: string`, so a holder of the AUTH
 * service binding could name any subject and get a certificate for it.
 * Measured before the fix: it returned
 * `MINTED subject="wimse://notme.bot/i-am-whoever"`. The docstring said "for
 * a verified subject" — an assumption about the caller standing in for a
 * check.
 *
 * WHY THAT MATTERS, AND IT IS NOT ABOUT CODE STYLE. signet verifies a
 * release by pinning the identity URI and requiring EQUALITY
 * (`cosign verify-blob --certificate-identity`). Its security therefore
 * rests entirely on that URI being unforgeable. If a binding holder can
 * assert the subject, it can mint a certificate whose identity equals
 * signet's pin for a key it controls, and the documented verification
 * PASSES for an artifact that holder signed. That is a forged release
 * signature, not a convenience.
 *
 * Keeping the capability and merely bounding it does not work either: the
 * only namespace notme emits is `principal/<sub>`, which is exactly what a
 * verifier pins, so "refuse the reserved namespaces" leaves nothing useful
 * to assert.
 *
 * NO `audience` FIELD, deliberately — see `GHA_CERT_AUDIENCE` above.
 */
export type MintBridgeCertProof =
  | { kind: "gha-oidc"; token: string }
  | { kind: "session-cookie"; cookie: string }
  /**
   * An `at+jwt` THIS authority signed, presented back to it (rig-098326).
   *
   * The kind exists because a bound Worker legitimately has nothing else to
   * present. rig/web holds an AUTH binding and used to pass a `userId`; it has
   * no GitHub Actions token, and `notme_session` is scoped to notme.bot so a
   * browser never sends it to rosary.bot. What it can hold is a token notme
   * already minted to an authenticated principal — session-gated and
   * audience-checked at `/token` and `/authorize/token` — which the DO
   * re-verifies against its own key, reading the subject out of the claims.
   *
   * NOT SAFE BEFORE notme-d68da8. `AuthService.mintDPoPToken` let a binding
   * holder sign a caller-chosen `sub` with the master key, so a token could be
   * forged and fed straight back in here. Deleting that method is what makes
   * a signature mean something; the two changes ship together on purpose.
   */
  | { kind: "notme-access-token"; token: string };

/**
 * Why a mint was refused. Exhaustive; switch on it.
 *
 * A RETURNED REASON, NOT A THROWN ERROR, for two reasons.
 *
 * The house pattern: `mintDPoPTokenOnce` returns
 * `{ ok: false, reason: "proof_reused" }` and `signReceiptCommitment`
 * returns a code union. A failed proof is an EXPECTED outcome of a
 * well-formed call, not programmer error, and the caller needs to map it to
 * a status code rather than parse an error string.
 *
 * And the runtime forces it: when a DO RPC method throws, workerd delivers
 * the rejection to the caller AND raises it in the DO's own isolate. The
 * caller's `.catch()` cannot own the second one, so vitest counted them as
 * unhandled errors and the workers suite exited 1 with all 300 tests
 * passing. Measured across three runs. Returning leaves nothing to reject.
 *
 * Deliberately COARSE: a caller learns that its evidence was rejected, not
 * which claim failed. `validateGHAToken` throws messages like
 * "wrong audience: <value>", and echoing those back to whoever supplied the
 * token is free reconnaissance. The detail goes to the log.
 */
export type BridgeCertRefusal =
  | "invalid_gha_token"
  | "invalid_session"
  | "invalid_access_token"
  | "unknown_proof_kind";

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
import { ADMIN_SCOPES, PRIOR_ADMIN_SCOPES, SIGNING_SCOPES } from "./auth/admin-scopes";
import { ensurePrincipalSchema, grantCapability } from "./auth/principals";
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

/**
 * The root's pathLenConstraint: room for exactly ONE intermediate tier
 * (CA → Issuing CA → task; ADR-008 §BasicConstraints, ADR-019 D4). The
 * served root must carry this value, not just "some BasicConstraints" —
 * getCACertificatePem re-issues under the same key when it does not.
 */
const CA_PATH_LEN = 1;

const CLAIM_REGISTRATION_TTL_S = 600; // options → verify of one WebAuthn ceremony
const CLAIM_CODE_TTL_S = 1800; // long enough to go run a workflow
const CLAIM_CAP = 100; // pending claim registrations; storage-exhaustion bound
const POP_NONCE_TTL_S = 120; // fetched and spent in one page interaction
const TIER_ENROLMENT_TTL_S = 600; // RFC 8628 device codes are minutes, not hours
const TIER_ENROLMENT_CAP = 500; // pending + approved rows; storage-exhaustion bound
const USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ"; // RFC 8628 §6.1: no vowels

function hex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

function b64url(b: Uint8Array): string {
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function randomUserCode(): string {
  // Rejection-free: 20 symbols, so take each byte mod 20 only when it falls
  // below 240 (the largest multiple of 20 under 256), avoiding modulo bias.
  const out: string[] = [];
  while (out.length < 8) {
    for (const byte of crypto.getRandomValues(new Uint8Array(16))) {
      if (byte < 240 && out.length < 8) out.push(USER_CODE_ALPHABET[byte % 20]!);
    }
  }
  return `${out.slice(0, 4).join("")}-${out.slice(4).join("")}`;
}

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
    // Migration (v2 → v3): which epoch the LIVE key started serving.
    //
    // Needed because epoch and key identity were decoupled (notme-77a024):
    // one key may now serve several epochs, so "the epoch" is no longer a
    // property of the key and has to be recorded as the span it covered.
    //
    // The backfill is the current epoch, not 1. Under the old coupling
    // `rotate()` bumped the epoch in the same statement that replaced the
    // key, so an existing key began serving exactly at the epoch now
    // current — and for a deployment that never rotated, that is epoch 1
    // anyway. Defaulting to 1 instead would claim the live key served every
    // earlier epoch too, which over-matches: `getEpochPublicKey(1)` would
    // offer today's key for an epoch an archived key actually signed.
    try {
      this.ctx.storage.sql.exec("SELECT from_epoch FROM keys LIMIT 0");
    } catch {
      this.ctx.storage.sql.exec(
        "ALTER TABLE keys ADD COLUMN from_epoch INTEGER NOT NULL DEFAULT 0",
      );
      this.ctx.storage.sql.exec(
        "UPDATE keys SET from_epoch = (SELECT epoch FROM state WHERE id = 'authority') WHERE from_epoch = 0",
      );
    }
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
    //
    // KEYED ON THE KEY, NOT THE EPOCH (notme-77a024). The original shape was
    // `epoch INTEGER PRIMARY KEY`, which is only sound while a rotation and
    // an epoch bump are the same event. They are not any more: epoch is the
    // revocation generation and moves only on `revokeEpoch()`, so a second
    // rotation inside one epoch would collide on that primary key — and the
    // archive write is `INSERT OR IGNORE`, so the collision is SILENT and the
    // second key's bytes are simply lost. That is precisely the audit-defeat
    // failure §2.3 names, reintroduced by the decoupling if the key stays.
    //
    // `from_epoch`/`until_epoch` are the inclusive span of epochs the key
    // served. One key may cover several (it keeps signing across a
    // revocation), and one epoch may have been served by several keys (it
    // survives rotations) — so neither side is a function of the other, and
    // resolution at audit time is by `actor_fp`, with the span as the filter.
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS retired_keys (
        key_id      TEXT PRIMARY KEY,
        public_raw  TEXT NOT NULL,
        from_epoch  INTEGER NOT NULL,
        until_epoch INTEGER NOT NULL,
        retired_at  INTEGER NOT NULL
      )
    `);
    // Migration (v1 → v2): rebuild an epoch-keyed archive onto the key.
    //
    // `CREATE TABLE IF NOT EXISTS` above is a no-op when the v1 table is
    // already there, so the old shape has to be detected and rewritten.
    // from_epoch = until_epoch = the recorded epoch is EXACT for v1 rows
    // rather than a guess: under the coupling that wrote them, a key served
    // exactly the one epoch it was retired at.
    let retiredKeysIsV1 = false;
    try {
      this.ctx.storage.sql.exec("SELECT until_epoch FROM retired_keys LIMIT 0");
    } catch {
      retiredKeysIsV1 = true;
    }
    if (retiredKeysIsV1) {
      this.ctx.storage.sql.exec(`
        CREATE TABLE retired_keys_v2 (
          key_id      TEXT PRIMARY KEY,
          public_raw  TEXT NOT NULL,
          from_epoch  INTEGER NOT NULL,
          until_epoch INTEGER NOT NULL,
          retired_at  INTEGER NOT NULL
        )
      `);
      this.ctx.storage.sql.exec(
        "INSERT OR IGNORE INTO retired_keys_v2 (key_id, public_raw, from_epoch, until_epoch, retired_at) " +
          "SELECT key_id, public_raw, epoch, epoch, retired_at FROM retired_keys",
      );
      this.ctx.storage.sql.exec("DROP TABLE retired_keys");
      this.ctx.storage.sql.exec(
        "ALTER TABLE retired_keys_v2 RENAME TO retired_keys",
      );
    }
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
    // Once per DO start: existing deployers get the signing scopes the admin
    // set now includes (notme-486e8a). Idempotent and revocation-respecting.
    this.#migrateAdminSigningScopes();
  }

  static async #keyIdFromSpki(spkiB64: string): Promise<string> {
    return keyIdFromSpki(spkiB64);
  }

  // Load or generate the authority keypair. Cached in memory for the DO lifetime.
  async #getOrCreateSigningKey(): Promise<{
    signingKey: CryptoKey;
    verifyKey: CryptoKey;
    keyId: string;
  }> {
    if (this.#signingKey && this.#verifyKey) {
      const kid = this.#getKeyId();
      // ARM THE ALARM ON THE WARM PATH TOO (notme-4896d8).
      //
      // scheduleNextRefresh() lived only at the END of this method, after the
      // cold-start key load. This early return skips it — so on any isolate
      // that already held the key in memory, the bundle-refresh alarm was
      // never scheduled. Production measured totalFires: 0 with the circuit
      // breaker CLOSED: the alarm had never fired in the object's entire
      // history, which is why the published CA bundle sat unrefreshed for 130
      // days (notme-77a024).
      //
      // Safe to call here because scheduleNextRefresh() checks getAlarm()
      // before setAlarm() — the idempotence THREAT_MODEL.md:52 requires
      // against compounding alarms (the 20-trillion-DO-reads cautionary
      // tale). Calling it on every warm hit is a no-op once one is pending.
      await this.scheduleNextRefresh();
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

    // The epoch this key begins serving (notme-77a024). The epoch moves on
    // `revokeEpoch()` alone, so a new key INHERITS the current generation
    // rather than defining one — which is what lets `rotate()` leave the
    // revocation state untouched.
    const startEpoch =
      (
        this.ctx.storage.sql
          .exec("SELECT epoch FROM state WHERE id = 'authority'")
          .toArray() as Array<{ epoch: number }>
      )[0]?.epoch ?? 1;

    if (isEphemeral) {
      // Store public key + key ID only — no private key material on disk
      this.ctx.storage.sql.exec(
        "INSERT OR REPLACE INTO keys (id, private_jwk, public_spki, key_id, from_epoch) VALUES ('authority', '', ?, ?, ?)",
        publicSpkiB64,
        keyId,
        startEpoch,
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
        "INSERT INTO keys (id, private_jwk, public_spki, key_id, from_epoch) VALUES ('authority', ?, ?, ?, ?)",
        await serialiseJwkForStorage(
          privateJwk,
          kekForWrite ? await kekForWrite : null,
        ),
        publicSpkiB64,
        keyId,
        startEpoch,
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

  /**
   * When the current authority key began signing, from `keys.created_at`.
   *
   * SQLite's `datetime('now')` is "YYYY-MM-DD HH:MM:SS" in UTC with no zone
   * marker, so it is normalised to ISO-8601 before parsing. null when there
   * is no key row or the value does not parse — never a guess, because a
   * wrong start date is exactly the defect this exists to prevent.
   *
   * Every write that keeps a key keeps its created_at: re-sealing under a KEK
   * and the key_id backfill are UPDATEs of other columns, and the only
   * INSERT OR REPLACE is the ephemeral mode, whose key is genuinely new on
   * each start.
   */
  #keyStart(): Date | null {
    this.#ensureSchema();
    const row = this.ctx.storage.sql
      .exec("SELECT created_at FROM keys WHERE id = 'authority'")
      .toArray()[0] as { created_at?: string } | undefined;
    if (!row?.created_at) return null;
    const d = new Date(row.created_at.replace(" ", "T") + "Z");
    return Number.isNaN(d.getTime()) ? null : d;
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
    const { verifyKey } = await this.#getOrCreateSigningKey();
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
    const { verifyKey, keyId } = await this.#getOrCreateSigningKey();
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
    // The root's validity window belongs to the KEY, not to the moment the
    // root happens to be (re-)issued (notme-0c494f). See keyStart below.
    const keyStart = this.#keyStart();
    const cached = this.ctx.storage.sql
      .exec("SELECT pem, key_id FROM ca_cert WHERE id = 'cert'")
      .toArray() as Array<{ pem: string; key_id: string }>;
    // v2: require CA:TRUE in cached cert (invalidate v1 certs without BasicConstraints)
    if (
      cached.length > 0 &&
      cached[0]!.key_id === currentKeyId &&
      cached[0]!.pem.includes("BEGIN CERTIFICATE")
    ) {
      // The cached cert must carry the budget the CODE mints, not merely a
      // BasicConstraints extension. The previous check asked only whether
      // the extension existed (the v1→v2 guard) — so when 9c75d93 moved the
      // root to pathlen=1, production kept serving its March-2026 pathlen:0
      // cert for five months, and every Issuing CA tier minted under it was
      // unverifiable by any stock validator (notme-1b1db4). Re-issuing here
      // keeps the key and the epoch. It is only non-destructive because the
      // re-issued root keeps the KEY's notBefore — this comment used to say
      // "leaves verify by key, so nothing in flight is invalidated", and the
      // heal minted with notBefore=now, which stranded every signature made
      // before it under RFC 5280 path validation (notme-0c494f).
      try {
        const { X509Certificate, BasicConstraintsExtension } = await import(
          "@peculiar/x509"
        );
        const x = new X509Certificate(cached[0]!.pem);
        const bc = x.getExtension(BasicConstraintsExtension);
        // A root that starts AFTER its key began signing strands everything
        // signed in between: RFC 5280 path validation requires the anchor to
        // be valid at the verification time, and cosign verifies at the
        // signing time. Production served exactly that — the heal below had
        // minted with `notBefore: now` (notme-0c494f) — so this check is also
        // what makes production self-heal on the first fetch after deploy.
        const startsLate =
          keyStart !== null && x.notBefore.getTime() > keyStart.getTime();
        if (bc?.ca && bc.pathLength === CA_PATH_LEN && !startsLate) {
          return cached[0]!.pem;
        }
        console.warn(
          startsLate
            ? `[ca] cached root notBefore ${x.notBefore.toISOString()} is after the key's start ${keyStart!.toISOString()} — re-issuing under the same key`
            : `[ca] cached root has pathlen ${bc?.pathLength ?? "none"}, code mints ${CA_PATH_LEN} — re-issuing under the same key`,
        );
      } catch {
        /* regenerate */
      }
    }

    const { signingKey, verifyKey } = await this.#getOrCreateSigningKey();
    // notBefore = when this key began signing. Nothing it signed predates
    // that, so no re-issue under the same key can leave an earlier signature
    // outside the anchor's window. The 1b1db4 heal used `now` and called it
    // "non-destructive … leaves verify by key" — true for a signature check,
    // false for path validation, which is what cosign does. A fresh key's
    // start IS now, so the first issue is unchanged.
    //
    // Fallback is `now` only when the key row has no parseable start — a
    // fresh row always has one (`created_at DEFAULT datetime('now')`).
    const notBefore = keyStart ?? new Date();
    const notAfter = new Date(
      notBefore.getTime() + 10 * 365.25 * 24 * 60 * 60 * 1000,
    );
    const serial = crypto
      .getRandomValues(new Uint8Array(16))
      .reduce((s, b) => s + b.toString(16).padStart(2, "0"), "");

    const cert = await X509CertificateGenerator.createSelfSigned({
      name: caSubjectForEnv(this.env),
      notBefore,
      notAfter,
      signingAlgorithm: ED25519,
      keys: { privateKey: signingKey, publicKey: verifyKey },
      serialNumber: serial,
      extensions: [
        new BasicConstraintsExtension(true, CA_PATH_LEN, true),
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
    const { verifyKey } = await this.#getOrCreateSigningKey();
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
    const { signingKey, keyId } = await this.#getOrCreateSigningKey();
    const { mintAccessToken, issuerFromEnv } = await import("./auth/token");
    return mintAccessToken({
      issuer: issuerFromEnv(this.env),
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
   * Returns the signature and the epoch, and no key material.
   *
   * It used to add "`CryptoKey` is not Structured Cloneable and cannot cross
   * the RPC boundary" as though that were a standing guarantee. It is not
   * (notme-bcbd74): W3C WebCrypto marks CryptoKey `[Serializable]`, and
   * workerd merely happens to refuse it — measured by
   * `rpc.cryptokey.isolation`, a runtime behaviour no standard requires.
   *
   * That mattered because the class did not otherwise hold the line:
   * `getOrCreateSigningKey()` was RPC-reachable and returned the signing
   * CryptoKey, so the serializer was the only thing between a stub holder
   * and a key that still signs as this CA (non-extractability stops byte
   * export, not USE). It is `#getOrCreateSigningKey()` now — off the surface
   * entirely, so the property is "not returnable" rather than "undeliverable
   * by a quirk" (notme-eedc9c). The serializer test stays as a backstop.
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
   * Returns EVERY key that served the epoch, raw base64 Ed25519 public key
   * bytes — the same form `actor_fp` is computed over — and an empty array
   * when none did. Empty is honest rather than an error: an auditor must be
   * able to distinguish "notme does not have this" from a transport failure.
   *
   * A SET, not one key, since notme-77a024 decoupled the epoch from key
   * identity: rotations no longer move the epoch, so several keys can have
   * signed under one generation. The caller disambiguates by `actor_fp` =
   * SHA-256(public key), which the receipt carries — so the fingerprint was
   * always the real index and the epoch is the filter. Returning any single
   * member would be a coin flip wearing a lookup's clothes.
   */
  /**
   * Every epoch's signing key — current and retired — for third-party
   * historical verification (notme-a0cff4).
   *
   * getEpochPublicKey answers for ONE epoch a caller already knows about. An
   * auditor holding a receipt or cert from an arbitrary epoch, or a consumer
   * backfilling an archive, needs the SET: cloister previously populated its
   * epoch index only from what it happened to observe while polling, so a
   * rotation between polls left that epoch permanently unresolvable even
   * though notme still held the key.
   *
   * Returns PUBLIC key material only, ascending by epoch. Safe to serve
   * unauthenticated — it is exactly what gets published — which is also why
   * it is safe on the RPC surface.
   */
  async listEpochKeys(): Promise<
    Array<{
      epoch: number;
      untilEpoch: number | null;
      keyId: string;
      publicRawB64: string;
      retiredAt: number | null;
    }>
  > {
    this.#ensureSchema();

    const retired = this.ctx.storage.sql
      .exec(
        "SELECT key_id, public_raw, from_epoch, until_epoch, retired_at FROM retired_keys ORDER BY from_epoch ASC, key_id ASC",
      )
      .toArray() as Array<{
      key_id: string;
      public_raw: string;
      from_epoch: number;
      until_epoch: number;
      retired_at: number;
    }>;

    const out: Array<{
      epoch: number;
      untilEpoch: number | null;
      keyId: string;
      publicRawB64: string;
      retiredAt: number | null;
    }> = retired.map((r) => ({
      epoch: r.from_epoch,
      untilEpoch: r.until_epoch,
      keyId: r.key_id,
      publicRawB64: r.public_raw,
      retiredAt: r.retired_at,
    }));

    // The live key is not in retired_keys — it has not been retired. Its span
    // is open-ended: `untilEpoch: null` means "still serving", which is
    // different from "served up to the current epoch" and will stay true
    // through the next revokeEpoch().
    const live = this.ctx.storage.sql
      .exec("SELECT from_epoch FROM keys WHERE id = 'authority'")
      .toArray() as Array<{ from_epoch: number }>;
    const liveFrom = live[0]?.from_epoch;
    if (typeof liveFrom === "number") {
      out.push({
        epoch: liveFrom,
        untilEpoch: null,
        keyId: this.#getKeyId(),
        publicRawB64: await this.getPublicKeyRawB64(),
        retiredAt: null,
      });
    }
    return out;
  }

  async getEpochPublicKey(epoch: number): Promise<
    Array<{
      keyId: string;
      publicRawB64: string;
      retiredAt: number | null;
    }>
  > {
    this.#ensureSchema();
    // An epoch the authority has never reached has no keys, even though the
    // live key's span is open-ended. `untilEpoch: null` means "has not
    // retired", NOT "serves every number" — and answering for a future epoch
    // would hand a verifier a working key for a generation that does not
    // exist, which is the over-matching half of the same mistake the archive
    // schema made in the other direction.
    const current = this.ctx.storage.sql
      .exec("SELECT epoch FROM state WHERE id = 'authority'")
      .toArray() as Array<{ epoch: number }>;
    if (epoch > (current[0]?.epoch ?? 0)) return [];

    const keys = await this.listEpochKeys();
    return keys
      .filter(
        (k) =>
          epoch >= k.epoch && (k.untilEpoch === null || epoch <= k.untilEpoch),
      )
      .map((k) => ({
        keyId: k.keyId,
        publicRawB64: k.publicRawB64,
        retiredAt: k.retiredAt,
      }));
  }

  async getReceiptFacts(): Promise<{ actorFp: Uint8Array; epoch: number }> {
    this.#ensureSchema();
    const { verifyKey } = await this.#getOrCreateSigningKey();

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
    const { signingKey } = await this.#getOrCreateSigningKey();
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
    const { signingKey, keyId } = await this.#getOrCreateSigningKey();
    const { mintAccessToken, issuerFromEnv } = await import("./auth/token");
    return mintAccessToken({
      issuer: issuerFromEnv(this.env),
      sub: params.sub,
      scope: params.scope,
      audience: params.audience,
      // No jkt — unbound token, accepted by verifyAccessToken
      signingKey,
      keyId,
    });
  }

  // Mint a bridge cert inside the DO — CryptoKey never crosses the RPC boundary.
  /**
   * Mint a bridge cert for the subject the EVIDENCE names (notme-51ccd7).
   *
   * The DO re-verifies the proof inside its own method body and derives the
   * subject from the verified claims. A caller cannot assert a subject, and
   * there is no overload that lets it.
   *
   * DOUBLE-VERIFY IS INTENTIONAL. The worker in front of this may already
   * have validated the same token or cookie; that check exists for early
   * rejection and clean 401/403 responses. This one is the trust kernel. If
   * only one may be trusted it is this one, because the worker is reachable
   * by anything holding the binding and the DO is not.
   *
   * FORWARD-PORTED from the private agentic-research/notme.bot repo, which
   * diagnosed and fixed the same defect on 2026-05-18 (commit 1d1ec7e, bead
   * notme.bot-69a3a9) in a repo whose code never ran. Verified against
   * signet's documented verification before porting rather than taken on
   * that repo's authority — see the `MintBridgeCertProof` docstring.
   */
  async mintBridgeCert(
    proof: MintBridgeCertProof,
    publicKeyPem: string,
    ttlMs?: number,
  ): Promise<
    | {
        ok: true;
        certificate: string;
        expires_at: number;
        subject: string;
        authority: { epoch: number; key_id: string };
      }
    | { ok: false; reason: BridgeCertRefusal }
  > {
    // Derive the subject. Every branch ends in a value this DO computed from
    // something it checked itself, or in a refusal.
    let subject: string;
    if (proof?.kind === "gha-oidc") {
      // Audience from OUR env, never the envelope (notme-51ccd7).
      const expectedAudience = this.env.GHA_CERT_AUDIENCE ?? "notme.bot";
      const { validateGHAToken } = await import("./gha-oidc");
      try {
        const claims = await validateGHAToken(proof.token, expectedAudience);
        subject = claims.sub;
      } catch (e) {
        console.warn({
          event: "mint.gha_proof_rejected",
          detail: (e as Error)?.message,
        });
        return { ok: false, reason: "invalid_gha_token" };
      }
    } else if (proof?.kind === "session-cookie") {
      // The secret is read inside the DO and does not leave it.
      const { verifySessionCookie } = await import("./auth/session");
      const session = await verifySessionCookie(
        proof.cookie,
        await this.getSessionSecret(),
      );
      if (!session) {
        console.warn({ event: "mint.session_proof_rejected" });
        return { ok: false, reason: "invalid_session" };
      }
      subject = session.principalId;
    } else if (proof?.kind === "notme-access-token") {
      // Verified against THIS authority's own key, so a token from another
      // deployment (or another DO id, which owns a different master key) is
      // refused on signature rather than believed on its claims.
      //
      // AUDIENCE AND SCOPE ARE CHECKED HERE, not upstream, because this path
      // has no route in front of it. `/token` and `/authorize/token` both call
      // getAllowedAudiences(env) and both require a session cookie first; a
      // service binding goes around both. Without these two checks a token
      // minted for one resource server is spendable at every other, and a
      // read-only token becomes a certificate.
      const { verifyKey } = await this.#getOrCreateSigningKey();
      const { verifyAccessToken, issuerFromEnv } = await import("./auth/token");
      const { getAllowedAudiences } = await import("./allowed-audiences");
      try {
        const claims = await verifyAccessToken(
          proof.token,
          verifyKey,
          issuerFromEnv(this.env),
        );
        // Every mint site asserts a subject; a token without one must not
        // become a certificate named "".
        if (!claims.sub) throw new Error("missing sub");
        if (!getAllowedAudiences(this.env).has(claims.aud)) {
          throw new Error("audience not allowed");
        }
        // `scope` is a space-delimited list (RFC 6749 §3.3). SPLIT it — a
        // substring test would accept "notbridgeCertish".
        if (!(claims.scope ?? "").split(" ").includes("bridgeCert")) {
          throw new Error("missing bridgeCert scope");
        }
        subject = claims.sub;
      } catch (e) {
        console.warn({
          event: "mint.access_token_proof_rejected",
          detail: (e as Error)?.message,
        });
        return { ok: false, reason: "invalid_access_token" };
      }
    } else {
      // Exhaustive at RUNTIME as well as in the type. A caller reaching this
      // DO over RPC is not bound by our types — `proof` may be a string, as
      // it was under the old signature, or a shape invented today — so a
      // third kind is refused rather than falling through to an undefined
      // subject. `proof?.kind` rather than `proof.kind` because a string
      // argument has no `kind` and a null one would throw on the read.
      console.warn({
        event: "mint.unknown_proof_kind",
        kind: typeof proof === "object" ? (proof as { kind?: unknown })?.kind : typeof proof,
      });
      return { ok: false, reason: "unknown_proof_kind" };
    }

    const { signingKey } = await this.#getOrCreateSigningKey();
    const state = await this.getAuthorityState();
    const { mintGHABridgeCert } = await import("./cert-authority");
    const result = await mintGHABridgeCert(
      subject,
      publicKeyPem,
      signingKey,
      ttlMs,
    );
    return {
      ok: true,
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
    const { signingKey } = await this.#getOrCreateSigningKey();
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

  /**
   * Mint the Issuing CA tier (ADR-019 D4): CA=true, pathlen=0, keyCertSign.
   * Same shape as mintBridgeCertPair — the DO supplies the key and the
   * epoch, never the policy: WHO may request this and WHAT scopes it may
   * carry are decided at the route, which is the only caller.
   */
  async mintIssuingCa(params: {
    subject: string;
    identity: string;
    publicKeyPem: string;
    scopes: string[];
    authMethod: string;
    ttlMs?: number;
  }): Promise<
    import("./cert-authority").IssuingCaCertResult & {
      authority: { epoch: number; key_id: string };
    }
  > {
    // A leaked stub is already full-CA capability, but an Issuing CA cert is
    // POST-LEAK PERSISTENCE: it keeps signing task certs after stub access is
    // lost, for its whole lifetime. Refuse rather than clamp — no legitimate
    // caller sends a long TTL (the route sends none), so a long TTL is
    // evidence of misuse, and clamping would hide it.
    const MAX_ISSUING_TTL_MS = 24 * 60 * 60 * 1000;
    if (params.ttlMs !== undefined && params.ttlMs > MAX_ISSUING_TTL_MS) {
      throw new Error(
        `issuing tier ttl capped at 24h, got ${params.ttlMs}ms`,
      );
    }
    const { signingKey } = await this.#getOrCreateSigningKey();
    const state = await this.getAuthorityState();
    const { mintIssuingCaCert } = await import("./cert-authority");
    const result = await mintIssuingCaCert(
      params.subject,
      params.identity,
      params.publicKeyPem,
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

  // ── Session-bound PoP nonces (notme-486e8a) ────────────────────────────
  //
  // The session term in a cert-pair binding. Issued to a principal, single
  // use, short-lived. Replaces SHA-256 of the HttpOnly session cookie, which
  // no browser could compute.

  #ensurePopNonceSchema(): void {
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS pop_nonces (
        nonce_hash   TEXT PRIMARY KEY,
        principal_id TEXT NOT NULL,
        expires_at   INTEGER NOT NULL
      )
    `);
  }

  async issuePopNonce(principalId: string): Promise<{ nonce: string; expiresIn: number }> {
    this.#ensurePopNonceSchema();
    const now = Math.floor(Date.now() / 1000);
    this.ctx.storage.sql.exec("DELETE FROM pop_nonces WHERE expires_at <= ?", now);
    const nonce = b64url(crypto.getRandomValues(new Uint8Array(32)));
    const hash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(nonce))));
    this.ctx.storage.sql.exec(
      "INSERT INTO pop_nonces (nonce_hash, principal_id, expires_at) VALUES (?, ?, ?)",
      hash,
      principalId,
      now + POP_NONCE_TTL_S,
    );
    return { nonce, expiresIn: POP_NONCE_TTL_S };
  }

  /**
   * Spend a nonce for this principal. Atomic: the DELETE is the check, so of
   * two concurrent spends exactly one sees changes() = 1. A nonce issued to a
   * DIFFERENT principal does not match — which is what defeats replay under
   * another session.
   */
  async consumePopNonce(nonce: string, principalId: string): Promise<boolean> {
    this.#ensurePopNonceSchema();
    if (typeof nonce !== "string" || !nonce) return false;
    const hash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(nonce))));
    this.ctx.storage.sql.exec(
      "DELETE FROM pop_nonces WHERE nonce_hash = ? AND principal_id = ? AND expires_at > ?",
      hash,
      principalId,
      Math.floor(Date.now() / 1000),
    );
    const [c] = [...this.ctx.storage.sql.exec<{ n: number }>("SELECT changes() AS n")];
    return c.n === 1;
  }

  // ── Tier enrolment by device authorization (notme-486e8a) ──────────────
  //
  // /cert/issuing-ca bound its proof to SHA-256 of the HttpOnly session
  // cookie, which no client can read, so a tier was never enrollable. This is
  // the RFC 8628 shape instead: the MACHINE holds the tier key and the device
  // code; the HUMAN approves a short user code in a passkey session, after
  // comparing the key fingerprint; the machine collects with a proof over the
  // device code, which never appears in a browser.
  //
  // State lives here, not in KV, so approval and collection are atomic and
  // collection is single-use — the same reason mintDPoPTokenOnce consumes in
  // SQLite.

  #ensureTierEnrolmentSchema(): void {
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS tier_enrolments (
        device_code_hash TEXT PRIMARY KEY,
        user_code        TEXT NOT NULL UNIQUE,
        public_key_pem   TEXT NOT NULL,
        key_fingerprint  TEXT NOT NULL,
        requested_scopes TEXT NOT NULL,
        status           TEXT NOT NULL,
        principal_id     TEXT,
        identity         TEXT,
        auth_method      TEXT,
        granted_scopes   TEXT,
        expires_at       INTEGER NOT NULL
      )
    `);
  }

  /**
   * Record a machine's request for a tier. Unauthenticated BY NATURE — the
   * machine has no credential yet — so it grants nothing: it stores a public
   * key and waits for a human. Bounded, because an open endpoint that writes
   * rows is a storage-exhaustion vector: expired rows are pruned on every
   * start and the pending set is capped.
   */
  async startTierEnrolment(params: {
    publicKeyPem: string;
    requestedScopes: string[];
  }): Promise<
    | { ok: true; deviceCode: string; userCode: string; keyFingerprint: string; expiresIn: number }
    | { ok: false; reason: "invalid_key" | "busy" }
  > {
    this.#ensureTierEnrolmentSchema();
    const { importPublicKey } = await import("./cert-authority");
    let key: CryptoKey;
    try {
      key = await importPublicKey(params.publicKeyPem);
    } catch {
      return { ok: false, reason: "invalid_key" };
    }
    if (key.algorithm.name !== "Ed25519") return { ok: false, reason: "invalid_key" };
    const spki = new Uint8Array((await crypto.subtle.exportKey("spki", key)) as ArrayBuffer);
    const keyFingerprint = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", spki)));

    const now = Math.floor(Date.now() / 1000);
    const sql = this.ctx.storage.sql;
    sql.exec("DELETE FROM tier_enrolments WHERE expires_at <= ?", now);
    const [{ n }] = [
      ...sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM tier_enrolments"),
    ];
    if (n >= TIER_ENROLMENT_CAP) return { ok: false, reason: "busy" };

    const deviceCode = b64url(crypto.getRandomValues(new Uint8Array(32)));
    const deviceCodeHash = hex(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(deviceCode))),
    );
    // RFC 8628 §6.1: a short code from an alphabet with no vowels (no
    // accidental words) and no look-alikes, so a human can read it across.
    const userCode = randomUserCode();
    sql.exec(
      `INSERT INTO tier_enrolments
         (device_code_hash, user_code, public_key_pem, key_fingerprint,
          requested_scopes, status, expires_at)
       VALUES (?, ?, ?, ?, ?, 'pending', ?)`,
      deviceCodeHash,
      userCode,
      params.publicKeyPem,
      keyFingerprint,
      JSON.stringify(params.requestedScopes),
      now + TIER_ENROLMENT_TTL_S,
    );
    return { ok: true, deviceCode, userCode, keyFingerprint, expiresIn: TIER_ENROLMENT_TTL_S };
  }

  /** What the approval page shows. No device code, no identity. */
  async getTierEnrolment(userCode: string): Promise<
    | { keyFingerprint: string; requestedScopes: string[]; status: string; expiresAt: number }
    | null
  > {
    this.#ensureTierEnrolmentSchema();
    const row = this.ctx.storage.sql
      .exec(
        "SELECT key_fingerprint, requested_scopes, status, expires_at FROM tier_enrolments WHERE user_code = ?",
        userCode,
      )
      .toArray()[0] as
      | { key_fingerprint: string; requested_scopes: string; status: string; expires_at: number }
      | undefined;
    if (!row) return null;
    return {
      keyFingerprint: row.key_fingerprint,
      requestedScopes: JSON.parse(row.requested_scopes),
      status: row.status,
      expiresAt: row.expires_at,
    };
  }

  /**
   * Bind a pending enrolment to the approving human. The ROUTE decides who
   * may approve and what scopes survive; this records it. A leaked stub could
   * approve for any principal — and could already call mintIssuingCa for any
   * subject directly, so the capability class is unchanged.
   */
  async approveTierEnrolment(params: {
    userCode: string;
    principalId: string;
    identity: string;
    authMethod: string;
    scopes: string[];
  }): Promise<{ ok: true } | { ok: false; reason: "not_found" | "expired" | "not_pending" }> {
    this.#ensureTierEnrolmentSchema();
    const now = Math.floor(Date.now() / 1000);
    const row = this.ctx.storage.sql
      .exec("SELECT status, expires_at FROM tier_enrolments WHERE user_code = ?", params.userCode)
      .toArray()[0] as { status: string; expires_at: number } | undefined;
    if (!row) return { ok: false, reason: "not_found" };
    if (row.expires_at <= now) return { ok: false, reason: "expired" };
    if (row.status !== "pending") return { ok: false, reason: "not_pending" };
    this.ctx.storage.sql.exec(
      `UPDATE tier_enrolments
          SET status = 'approved', principal_id = ?, identity = ?, auth_method = ?, granted_scopes = ?
        WHERE user_code = ? AND status = 'pending'`,
      params.principalId,
      params.identity,
      params.authMethod,
      JSON.stringify(params.scopes),
      params.userCode,
    );
    return { ok: true };
  }

  /**
   * The machine collects its tier. The proof is verified HERE, against the
   * key recorded at start, over `"notme/tier-enrol/v1\0" || SPKI ||
   * SHA-256(device_code)`. A bad proof does not consume the enrolment — a
   * thief holding the device code but not the key must not be able to burn
   * the real holder's approval. A good one consumes it before minting.
   */
  async collectTierEnrolment(params: { deviceCode: string; proof: string }): Promise<
    | ({ ok: true; principalId: string; authMethod: string } &
        import("./cert-authority").IssuingCaCertResult & {
          authority: { epoch: number; key_id: string };
        })
    | {
        ok: false;
        reason: "authorization_pending" | "expired_token" | "invalid_grant" | "invalid_proof";
      }
  > {
    this.#ensureTierEnrolmentSchema();
    if (typeof params.deviceCode !== "string" || params.deviceCode.length === 0) {
      return { ok: false, reason: "invalid_grant" };
    }
    const deviceCodeHash = hex(
      new Uint8Array(
        await crypto.subtle.digest("SHA-256", new TextEncoder().encode(params.deviceCode)),
      ),
    );
    const row = this.ctx.storage.sql
      .exec("SELECT * FROM tier_enrolments WHERE device_code_hash = ?", deviceCodeHash)
      .toArray()[0] as
      | {
          public_key_pem: string;
          status: string;
          principal_id: string;
          identity: string;
          auth_method: string;
          granted_scopes: string;
          expires_at: number;
        }
      | undefined;
    if (!row) return { ok: false, reason: "invalid_grant" };
    if (row.expires_at <= Math.floor(Date.now() / 1000)) {
      return { ok: false, reason: "expired_token" };
    }
    if (row.status === "pending") return { ok: false, reason: "authorization_pending" };
    if (row.status !== "approved") return { ok: false, reason: "invalid_grant" };

    const { importPublicKey } = await import("./cert-authority");
    const key = await importPublicKey(row.public_key_pem);
    const spki = new Uint8Array((await crypto.subtle.exportKey("spki", key)) as ArrayBuffer);
    const { verifyEd25519PopProof } = await import("./auth/pop");
    const { tierEnrolmentBinding } = await import("./auth/tier-enrolment-binding");
    const codeHashBytes = Uint8Array.from(deviceCodeHash.match(/../g)!.map((h) => parseInt(h, 16)));
    if (!(await verifyEd25519PopProof(tierEnrolmentBinding(spki, codeHashBytes), key, params.proof))) {
      return { ok: false, reason: "invalid_proof" };
    }

    // Consume first, atomically: of two concurrent collects with a valid
    // proof, exactly one sees changes() = 1.
    this.ctx.storage.sql.exec(
      "UPDATE tier_enrolments SET status = 'consumed' WHERE device_code_hash = ? AND status = 'approved'",
      deviceCodeHash,
    );
    const [change] = [
      ...this.ctx.storage.sql.exec<{ n: number }>("SELECT changes() AS n"),
    ];
    if (change.n !== 1) return { ok: false, reason: "invalid_grant" };

    const result = await this.mintIssuingCa({
      subject: row.principal_id,
      identity: row.identity,
      publicKeyPem: row.public_key_pem,
      scopes: JSON.parse(row.granted_scopes),
      authMethod: row.auth_method,
    });
    return { ok: true, principalId: row.principal_id, authMethod: row.auth_method, ...result };
  }

  // Current epoch and keyId for embedding in issued certs.
  async getAuthorityState(): Promise<{
    epoch: number;
    seqno: number;
    keyId: string;
  }> {
    this.#ensureSchema();
    const { keyId } = await this.#getOrCreateSigningKey();
    const rows = this.ctx.storage.sql
      .exec("SELECT epoch, seqno FROM state WHERE id = 'authority'")
      .toArray() as Array<{ epoch: number; seqno: number }>;
    const state = rows[0] ?? { epoch: 1, seqno: 1 };
    return { epoch: state.epoch, seqno: state.seqno, keyId };
  }

  // Generate a signed CABundle for the revocation verifier.
  // Caller writes this to CA_BUNDLE_CACHE KV.
  async generateBundle(): Promise<CABundle> {
    const { signingKey, keyId } = await this.#getOrCreateSigningKey();
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

  /**
   * Replace the CA key. Does NOT move the epoch (notme-77a024).
   *
   * Epoch and key identity are independent axes, and conflating them cost
   * notme both levers at once:
   *
   *   - A ROUTINE ROTATION became a mass revocation nobody asked for.
   *     `checkRevocation` tests epoch (step 5) before keyId (step 6), so
   *     every token minted before the rotation died on `epoch_mismatch` and
   *     the republished `prevKeyId` grace window built for notme-54f84b
   *     guarded a branch no token could enter.
   *   - A MASS REVOCATION required destroying the signing key, the one
   *     irreversible action available — which past the archive's retention
   *     made the actor's own receipts unverifiable. A lever that costs an
   *     audit trail does not get pulled.
   *
   * So: rotation is about which key signs, `revokeEpoch()` is about which
   * credentials are still good, and the grace window now works because a
   * pre-rotation token carries the SAME epoch and a `prevKeyId` match.
   *
   * seqno still advances: the published bundle genuinely changed, and the
   * rollback-protection DO must refuse the pre-rotation bundle afterwards.
   */
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
    //
    // The span, not one epoch: this key may have signed across a
    // `revokeEpoch()`, so `from_epoch` is where it started and `until_epoch`
    // is the generation current as it retires. `INSERT OR IGNORE` still
    // guards immutability — now of one KEY's record, where before it silently
    // discarded a second key retired inside the same epoch.
    const oldEpochRows = this.ctx.storage.sql
      .exec(
        "SELECT s.epoch AS epoch, k.from_epoch AS from_epoch FROM state s, keys k WHERE s.id = 'authority' AND k.id = 'authority'",
      )
      .toArray() as Array<{ epoch: number; from_epoch: number }>;
    const untilEpoch = oldEpochRows[0]!.epoch;
    this.ctx.storage.sql.exec(
      "INSERT OR IGNORE INTO retired_keys (key_id, public_raw, from_epoch, until_epoch, retired_at) VALUES (?, ?, ?, ?, ?)",
      oldKeyId,
      oldPubKeyB64,
      oldEpochRows[0]!.from_epoch,
      untilEpoch,
      Math.floor(Date.now() / 1000),
    );

    // Delete old key
    this.ctx.storage.sql.exec("DELETE FROM keys WHERE id = 'authority'");
    this.#signingKey = null;
    this.#verifyKey = null;

    // seqno only. The epoch belongs to revokeEpoch().
    this.ctx.storage.sql.exec(
      "UPDATE state SET seqno = seqno + 1 WHERE id = 'authority'",
    );

    // Generate new key (#getOrCreateSigningKey will create since we deleted)
    const { keyId: newKeyId } = await this.#getOrCreateSigningKey();

    // Store prevKeyId + prevPubKey for the transition window (both needed so
    // generateBundle can republish the previous key for grace-window verify).
    await this.ctx.storage.put("prevKeyId", oldKeyId);
    await this.ctx.storage.put("prevPubKey", oldPubKeyB64);

    const rows = this.ctx.storage.sql
      .exec("SELECT epoch FROM state WHERE id = 'authority'")
      .toArray() as Array<{ epoch: number }>;

    return { newKeyId, epoch: rows[0]!.epoch };
  }

  /**
   * Advance the revocation generation: void every credential issued so far,
   * keep the signing key (notme-77a024).
   *
   * This is the unit between "wait for expiry" and "there is no lever". Every
   * tier of the chain already carries `OID_EPOCH` and every verifier checks
   * it, so a bump invalidates outstanding certificates and tokens at their
   * next verification without the authority enumerating them.
   *
   * WHAT IT IS NOT. Class-level, never targeted: it cannot revoke one task,
   * one tier, or one principal.
   *
   * CORRECTION to the first version of this comment, which claimed the
   * targeted job was already covered by "the chain — revoke a tier and every
   * task cert beneath it fails path validation by issuer, intrinsic X.509, no
   * index required". The X.509 mechanics are right and the LEVER DOES NOT
   * EXIST: there is no CRL, no OCSP, and no per-certificate status anywhere
   * in this repo, and the published bundle carries only epoch, seqno, keys,
   * keyId, prevKeyId and issuedAt — no revoked-serial list. Nothing can mark
   * one tier revoked, so nothing beneath one falls. That claim also
   * contradicted the paragraph directly above it in ADR-019, which had
   * always said the honest version: TTL-only for anything finer than an
   * epoch.
   *
   * So the levers that EXIST are this one and the grant (`liveScopes` at the
   * authorization gate, which governs what a session may do — not the
   * validity of a certificate already in someone's hands). Killing one task
   * or one machine is the open hole, and the shape ADR-019 D7 commits to is
   * a renewal predicate rather than a revocation list.
   *
   * THE KEY SURVIVES, deliberately. Receipts naming earlier epochs stay
   * verifiable, which is the difference between revoking credentials and
   * destroying evidence. Interlace RECEIPTS.md §2.3 makes historical
   * resolution a MUST precisely so an actor cannot defeat an audit by
   * rotating; a revocation lever that forced a rotation handed that back.
   *
   * CALLERS SEE `EPOCH_MISMATCH` and retry once against fresh
   * `getReceiptFacts()` — the one retryable code, already specified for this
   * shape (ADR-014). No operator HTTP route, matching `rotate()`: both are
   * service-binding operations, and a public door onto mass revocation is a
   * denial-of-service surface with an authentication bug away from being
   * free.
   */
  async revokeEpoch(): Promise<{ epoch: number; seqno: number }> {
    this.#ensureSchema();
    this.ctx.storage.sql.exec(
      "UPDATE state SET epoch = epoch + 1 WHERE id = 'authority'",
    );
    // Publish straight away: the bundle is how a verifier learns the epoch
    // moved, so leaving it stale makes the lever a no-op until the next
    // alarm fires — and an alarm is exactly what cannot be relied on here
    // (production once measured totalFires: 0 for 130 days, notme-4896d8).
    // The returned numbers come FROM the published bundle, because
    // generateBundle() advances seqno itself and the operator needs the
    // generation a verifier will actually read.
    const bundle = await this.#publishBundle();
    const { epoch, seqno } = bundle;
    console.warn({ event: "authority.epoch_revoked", epoch, seqno });
    return { epoch, seqno };
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

  /** Revoke one grant — the revocation unit (notme-77a024). */
  async revokeCapability(
    principalId: string,
    scope: string,
    revokedBy?: string,
  ): Promise<{ revoked: boolean }> {
    const { revokeCapability } = await import("./auth/principals");
    return revokeCapability(this.ctx.storage.sql, principalId, scope, revokedBy);
  }

  async listGrants(
    principalId: string,
  ): Promise<import("./auth/principals").Grant[]> {
    const { listGrants } = await import("./auth/principals");
    return listGrants(this.ctx.storage.sql, principalId);
  }

  /**
   * Make a passkey user a principal with GRANTS, so its authority has one
   * source and one revoke path. Idempotent: an existing principal keeps its
   * grants exactly (a returning admin whose authorityManage was revoked must
   * NOT get it back by logging in again — that is what the bead's finding (b)
   * was). Only a principal with no row at all is created, and only then does
   * `isFirstUser` decide whether the admin scopes are granted.
   */
  /**
   * Give existing deployers the signing scopes the admin set now includes
   * (notme-486e8a). Runs once per DO start and is safe to call again.
   *
   * WHO: only a principal holding the WHOLE prior deployer set
   * (bridgeCert + authorityManage + certMint, all live). A partial admin was
   * never a deployer and is left alone.
   *
   * WHAT: sign:git and sign:attestation — but only a scope the principal has
   * NO row for, live or revoked. A deliberate revocation must stick; a
   * migration that re-granted on every cold start would make revoking your
   * own signing scope impossible.
   *
   * A leaked stub calling this gains nothing a deployer could not already do:
   * it only ever grants signing purposes to principals that already hold
   * authorityManage and certMint. Recorded as granted_by
   * "migration:notme-486e8a", so listGrants shows where it came from.
   */
  async migrateAdminSigningScopes(): Promise<{ granted: number }> {
    return { granted: this.#migrateAdminSigningScopes() };
  }

  #migrateAdminSigningScopes(): number {
    const sql = this.ctx.storage.sql;
    ensurePrincipalSchema(sql);
    const live = (scope: string) =>
      new Set(
        (sql
          .exec(
            "SELECT principal_id FROM capability_grants WHERE scope = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > datetime('now'))",
            scope,
          )
          .toArray() as Array<{ principal_id: string }>).map((r) => r.principal_id),
      );
    const holders = PRIOR_ADMIN_SCOPES.map(live);
    const deployers = [...holders[0]!].filter((pid) => holders.every((h) => h.has(pid)));
    let granted = 0;
    for (const pid of deployers) {
      for (const scope of SIGNING_SCOPES) {
        const [{ n }] = [
          ...sql.exec<{ n: number }>(
            "SELECT COUNT(*) AS n FROM capability_grants WHERE principal_id = ? AND scope = ?",
            pid,
            scope,
          ),
        ];
        if (n === 0) {
          grantCapability(sql, pid, scope, "migration:notme-486e8a");
          granted++;
        }
      }
    }
    if (granted > 0) {
      console.warn({ event: "admin.signing_scopes_migrated", granted, deployers: deployers.length });
    }
    return granted;
  }

  async ensurePasskeyPrincipal(
    principalId: string,
    isFirstUser: boolean,
  ): Promise<string[]> {
    const { getPrincipal, getCapabilities } = await import("./auth/principals");
    if (!getPrincipal(this.ctx.storage.sql, principalId)) {
      await this.createPrincipalWithCapabilities(
        principalId,
        isFirstUser
          ? [...ADMIN_SCOPES]
          : ["bridgeCert"],
        "passkey-registration",
      );
    }
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
  //
  // THIS IS THE ONLY CREDENTIAL-REMOVAL PATH IN THE WORKER. Nothing else
  // deletes from passkey_credentials, federated_identities, principals, or
  // invites. Two invariants currently rest on that being true:
  //
  //   1. The known gap in #hasAuthenticator — that it does not count
  //      outstanding invites — is UNREACHABLE, because reaching "no
  //      authenticator but a live authorityManage invite" requires losing a
  //      credential, which requires this method, which requires consuming a
  //      bootstrap code, which requires already having no authenticator. The
  //      transition is circular (notme-2131e8). That last step is now
  //      ENFORCED rather than emergent: consumeBootstrapCode refuses once
  //      anyone can authenticate. The circularity used to hold only because
  //      a consumed code stayed consumed, which is a weaker reason.
  //
  //      CONSEQUENCE, stated plainly: this method is unreachable on an
  //      authority that has any authenticator, since it requires consuming a
  //      code and consumption is now gated. That was ALREADY true by
  //      accident (the code was already marked used), so nothing regressed —
  //      but "corrupted credentials" is exactly the case this method claims
  //      to serve, and corrupted rows still count as an authenticator. The
  //      dead end is pre-existing and unresolved; it needs an authenticated
  //      recovery path rather than a code.
  //   2. Rotating the session secret below is sufficient to revoke sessions,
  //      because no other route can orphan one.
  //
  // ADDING A SECOND CREDENTIAL-REMOVAL PATH — an admin "revoke device"
  // route, an account deletion, a principal-removal API — BREAKS BOTH. Such
  // a path must also revoke outstanding invites and rotate the session
  // secret, or #hasAuthenticator must start counting invites.
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

    // Rotate the session secret, invalidating every cookie issued before
    // this reset. Without it a reset revoked NOTHING: the secret was minted
    // once and never rotated, so sessions survived their credentials for the
    // full 24h TTL. A deployer who reset while logged in therefore left an
    // authority with no authenticator but a live admin session — the state
    // in which getOrCreateBootstrapCode re-arms, mistakenly, for an
    // authority that still has a working administrator.
    const rotated = new Uint8Array(32);
    crypto.getRandomValues(rotated);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS session_config (
        id     TEXT PRIMARY KEY DEFAULT 'session',
        secret TEXT NOT NULL
      )
    `);
    this.ctx.storage.sql.exec(
      "INSERT OR REPLACE INTO session_config (id, secret) VALUES ('session', ?)",
      btoa(String.fromCharCode(...rotated)),
    );
    // Mark bootstrap as used — do NOT delete it.
    //
    // Since notme-976385 a new code CAN appear after a reset: this wipe
    // removes every passkey credential, so hasAuthenticator() goes false and
    // getOrCreateBootstrapCode() re-arms rather than leaving the authority
    // permanently unadministrable. The wipe-loop this comment used to claim
    // was structurally impossible is instead bounded by what the loop yields:
    // the regenerated code never crosses the HTTP boundary (the only caller
    // discards it and answers 401), so an attacker who knows a burned code
    // can still only wipe — never read the replacement — and gains no
    // capability from repeating it.
    // CREATE IF NOT EXISTS before the UPDATE: on an authority where
    // getOrCreateBootstrapCode has never run, this table does not exist and
    // the UPDATE threw SQLITE_ERROR. Masked in practice because the register
    // flow creates the table first, so only a reset on a genuinely untouched
    // authority hit it — which is exactly when an operator is least able to
    // interpret a raw SQL error.
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS bootstrap (
        id         TEXT PRIMARY KEY DEFAULT 'code',
        code       TEXT NOT NULL,
        used       INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `);
    this.ctx.storage.sql.exec(
      "UPDATE bootstrap SET used = 1 WHERE id = 'code'",
    );
    return { deleted: count };
  }

  // ── Bootstrap code: one-time admin registration gate ──
  // Generated on first call, deleted after first passkey registration.
  // Only visible to the deployer (via wrangler tail / console).

  /**
   * Can anyone actually authenticate to this authority?
   *
   * NOT `principalCount`. The primary deployer flow — registerPasskey — writes
   * `passkey_users` + `passkey_credentials` and never creates a `principals`
   * row (see worker/src/auth/passkey.ts), so a principals-only predicate
   * reports "nobody is here" on the exact configuration that means "the
   * administrator is here", and would re-arm the bootstrap gate for an
   * authority that already has an admin. Adversarial review of PR #71 caught
   * this; the first version of bootstrap-code.do.test.ts missed it because
   * every test established the admin via createPrincipalWithCapabilities,
   * which is the one path that DOES write principals.
   *
   * Conversely a bare `principals` row — which is what POST /cert bootstrap
   * creates — is a revocation target, not a way in: it carries no credential
   * and no federated identity, and no HTTP route turns a bridge cert into a
   * session. Counting it as "someone is here" would strand the deployer with
   * an authority nobody can interactively administer, which is the very
   * failure notme-976385 exists to prevent.
   *
   * So the predicate is authenticators: a passkey credential, or a linked
   * federated identity. Session cookies are the third population, handled at
   * the source instead — resetPasskeyData rotates the session secret, so a
   * wipe leaves no valid cookie for this to have to count.
   *
   * IF YOU ADD A LOGIN PATH, COUNT IT HERE. `findByProvider` in
   * auth/connections.ts is the near miss to watch: it is a
   * provider→credential lookup that reads like a login path and is currently
   * called only from tests. Wiring it to a route makes `connections` a
   * fourth table this predicate must include.
   *
   * Synchronous by construction — the callers' schema-ensure imports are
   * passed in — so the caller's read-check-write stays free of `await` and
   * this cannot return a pre-yield snapshot.
   *
   * `#`-private, NOT TypeScript `private`: this class is RPC-reachable, and
   * TS `private` is erased at build time, so a `private` helper stays
   * callable on any stub someone obtains — a full-CA capability. The
   * rpc-surface.do.test.ts allow-list caught exactly that on the first
   * version of this method.
   */
  #hasAuthenticator(
    ensurePasskeySchema: (sql: any) => void,
    ensurePrincipalSchema: (sql: any) => void,
  ): boolean {
    const sql = this.ctx.storage.sql;
    ensurePasskeySchema(sql);
    const creds = sql
      .exec("SELECT COUNT(*) as c FROM passkey_credentials")
      .toArray() as Array<{ c: number }>;
    if ((creds[0]?.c ?? 0) > 0) return true;

    ensurePrincipalSchema(sql);
    const federated = sql
      .exec("SELECT COUNT(*) as c FROM federated_identities")
      .toArray() as Array<{ c: number }>;
    return (federated[0]?.c ?? 0) > 0;
  }

  /**
   * Report bootstrap state WITHOUT minting anything (notme-addef9).
   *
   * THE DEFECT THIS REPLACES: the public registration route called
   * `getOrCreateBootstrapCode()`, so the first unauthenticated request to a
   * fresh authority CAUSED an admin credential to be minted and logged. The
   * trigger was therefore never the deployer — any stranger could cause the
   * mint, and since notme-976385 made regeneration possible while no
   * authenticator exists, could cause it repeatedly, choosing the moment a
   * credential appeared in the log.
   *
   * The security review judged that acceptable because the code never crosses
   * the HTTP boundary, so a network-only attacker gains nothing and the
   * exposure is to whoever reads Workers Logs. That reasoning holds. It was
   * still a side channel serving as the PRIMARY onboarding path, in a repo
   * whose entire thesis is no long-lived secret on disk and attestation
   * instead of stored credentials — and this cycle showed the logs are not
   * even reliably readable (`wrangler tail` returned nothing for a
   * known-good 200 in production).
   *
   * So: reads are reads. Minting moves behind an operator action — setting
   * `BOOTSTRAP_CODE`, which requires control of the deployment rather than
   * merely the ability to send an HTTP request.
   */
  // ── Bootstrap by attested claim (notme-486e8a) ─────────────────────────
  //
  // REPLACES bootstrapFromAttestation, which made the attested WORKFLOW the
  // administrator as a side effect of /cert/gha. Its comment said the human
  // would then "attach a passkey by taking an invite from it" — but /invites
  // accepts only a browser session and a workflow never has one, so the
  // authority ended up governed by an identity no human could act as, and
  // closed to everyone else. The fix inverts the roles: the HUMAN registers a
  // passkey and holds nothing; the named workflow APPROVES that passkey's
  // claim code with its GitHub OIDC token. The human holds the credential,
  // GitHub attests the deployer, and nothing secret crosses a log.
  //
  // Gated on "no administrator exists" — a live authorityManage grant — and
  // NOT on "no credential exists". Under the old gate a stranger who
  // registered first and was never approved would close the door on the
  // deployer for good. Anyone may open a claim; only an approved one counts.

  #ensureClaimSchema(): void {
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS bootstrap_claim_registrations (
        user_id    TEXT PRIMARY KEY,
        expires_at INTEGER NOT NULL
      )
    `);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS bootstrap_claims (
        code         TEXT PRIMARY KEY,
        principal_id TEXT NOT NULL,
        expires_at   INTEGER NOT NULL
      )
    `);
  }

  #hasAdministrator(): boolean {
    const sql = this.ctx.storage.sql;
    ensurePrincipalSchema(sql);
    const [{ n }] = [
      ...sql.exec<{ n: number }>(
        "SELECT COUNT(*) AS n FROM capability_grants WHERE scope = 'authorityManage' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > datetime('now'))",
      ),
    ];
    return n > 0;
  }

  /** Does any principal hold a live authorityManage grant? */
  async hasAdministrator(): Promise<boolean> {
    return this.#hasAdministrator();
  }

  /** May an unauthenticated passkey registration open a claim right now? */
  async claimAvailable(): Promise<boolean> {
    return bootstrapAttestedSubject(this.env) !== null && !this.#hasAdministrator();
  }

  /**
   * Mark a registration (by its WebAuthn user id) as a claim, so verify knows
   * not to grant it anything. Bounded: an open endpoint that writes rows is a
   * storage-exhaustion vector.
   */
  async markClaimRegistration(userId: string): Promise<{ ok: true } | { ok: false; reason: "unavailable" | "busy" }> {
    if (!(await this.claimAvailable())) return { ok: false, reason: "unavailable" };
    this.#ensureClaimSchema();
    const now = Math.floor(Date.now() / 1000);
    const sql = this.ctx.storage.sql;
    sql.exec("DELETE FROM bootstrap_claim_registrations WHERE expires_at <= ?", now);
    sql.exec("DELETE FROM bootstrap_claims WHERE expires_at <= ?", now);
    const [{ n }] = [...sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM bootstrap_claim_registrations")];
    if (n >= CLAIM_CAP) return { ok: false, reason: "busy" };
    sql.exec(
      "INSERT OR REPLACE INTO bootstrap_claim_registrations (user_id, expires_at) VALUES (?, ?)",
      userId,
      now + CLAIM_REGISTRATION_TTL_S,
    );
    return { ok: true };
  }

  /**
   * After a claim registration's WebAuthn ceremony verifies: create the
   * principal with NO grants, clear the first-credential admin flag
   * passkey verification set, and issue the claim code. null when the
   * registration was not a claim.
   */
  async finalizeClaimRegistration(userId: string): Promise<{ code: string; expiresIn: number } | null> {
    this.#ensureClaimSchema();
    const sql = this.ctx.storage.sql;
    const now = Math.floor(Date.now() / 1000);
    sql.exec(
      "DELETE FROM bootstrap_claim_registrations WHERE user_id = ? AND expires_at > ?",
      userId,
      now,
    );
    const [c] = [...sql.exec<{ n: number }>("SELECT changes() AS n")];
    if (c.n !== 1) return null;
    const { ensurePasskeySchema } = await import("./auth/passkey");
    ensurePasskeySchema(sql);
    // verifyRegistration marks the FIRST credential is_admin=1. A claim is
    // not an admin until approved, whatever order it registered in.
    sql.exec("UPDATE passkey_users SET is_admin = 0 WHERE user_id = ?", userId);
    const { createPrincipal } = await import("./auth/principals");
    createPrincipal(sql, userId, undefined, "bootstrap-claim");
    const code = randomUserCode();
    sql.exec(
      "INSERT INTO bootstrap_claims (code, principal_id, expires_at) VALUES (?, ?, ?)",
      code,
      userId,
      now + CLAIM_CODE_TTL_S,
    );
    return { code, expiresIn: CLAIM_CODE_TTL_S };
  }

  /**
   * The named workflow approves a claim. The caller is trusted to have
   * VERIFIED the GitHub token (signature, audience, jti) — this takes an
   * attested subject, never a raw one.
   */
  async approveBootstrapClaim(
    code: string,
    attestedSubject: string,
  ): Promise<
    | { ok: true; principalId: string }
    | { ok: false; reason: "not_configured" | "subject_mismatch" | "governed" | "no_such_claim" }
  > {
    const expected = bootstrapAttestedSubject(this.env);
    if (expected === null) return { ok: false, reason: "not_configured" };
    const { timingSafeEqual } = await import("./auth/timing-safe");
    const subjectsMatch = await timingSafeEqual(attestedSubject, expected);
    if (!subjectsMatch) return { ok: false, reason: "subject_mismatch" };
    if (
      !mayBootstrapFromAttestation({
        configuredSubject: expected,
        subjectsMatch,
        authorityIsGovernable: this.#hasAdministrator(),
      })
    ) {
      return { ok: false, reason: "governed" };
    }
    this.#ensureClaimSchema();
    const sql = this.ctx.storage.sql;
    const row = sql
      .exec(
        "SELECT principal_id FROM bootstrap_claims WHERE code = ? AND expires_at > ?",
        String(code).toUpperCase(),
        Math.floor(Date.now() / 1000),
      )
      .toArray()[0] as { principal_id: string } | undefined;
    if (!row) return { ok: false, reason: "no_such_claim" };
    for (const scope of ADMIN_SCOPES) {
      grantCapability(sql, row.principal_id, scope, `gha-oidc:${attestedSubject}`);
    }
    // The door closes: every other pending claim is void. Their principals
    // keep zero grants.
    sql.exec("DELETE FROM bootstrap_claims");
    sql.exec("DELETE FROM bootstrap_claim_registrations");
    console.warn({ event: "bootstrap.claimed", principalId: row.principal_id, attestedSubject });
    return { ok: true, principalId: row.principal_id };
  }

  async getBootstrapState(): Promise<BootstrapReadState> {
    const { ensurePasskeySchema } = await import("./auth/passkey");
    const { ensurePrincipalSchema } = await import("./auth/principals");
    if (this.#hasAuthenticator(ensurePasskeySchema, ensurePrincipalSchema)) {
      return { status: "closed" };
    }
    // `armed` reports only that a mechanism EXISTS, never a value or length.
    const methods: BootstrapMethod[] = [];
    if (bootstrapSecret(this.env)) methods.push("secret");
    if (bootstrapAttestedSubject(this.env)) methods.push("gha-oidc");
    return methods.length > 0
      ? { status: "armed", methods }
      : { status: "unconfigured" };
  }

  async getOrCreateBootstrapCode(): Promise<BootstrapState> {
    // Only the IMPORTS are hoisted, not the predicate. `await import(...)`
    // is a yield point, and one between reading `used` and the DELETE/INSERT
    // below let two concurrent callers each regenerate and log a distinct
    // code, only the last of which is live — two apparently-valid admin
    // codes in the log at exactly the moment that matters.
    //
    // Evaluating the predicate up here instead would trade that for a stale
    // snapshot: a registration committing between the counts and the resume
    // would re-arm an authority that just gained an admin. The counts are
    // synchronous, so running them inline below keeps the whole
    // read-check-write free of `await` and reads current state.
    const { ensurePasskeySchema } = await import("./auth/passkey");
    const { ensurePrincipalSchema } = await import("./auth/principals");

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

    // Gate BOTH branches, not just the consumed one. An UNUSED code minted
    // before the first administrator existed stayed redeemable afterwards:
    // the used-branch check below never ran, so this returned the standing
    // code to any caller. It is TTL-bounded (15 min) and only ever reaches
    // the logs, but POST /cert consumes bootstrap codes too and would mint
    // authorityManage+certMint against one — a credential outliving its
    // purpose. Once anyone can authenticate, bootstrap is closed, full stop.
    if (this.#hasAuthenticator(ensurePasskeySchema, ensurePrincipalSchema)) {
      return { status: "closed" };
    }

    if (rows.length > 0) {
      if (rows[0]!.used) {
        // A consumed code stays consumed on an authority someone can log in
        // to. But three routes can burn it (register/options,
        // /auth/passkey/reset, POST /cert) and only registration establishes
        // a way in — so an authority could be permanently stranded with no
        // administrator and no way to ever create one (notme-976385). While
        // NOBODY can authenticate, regenerate.
        //
        // This does not reopen the wipe-loop the reset path guards against:
        // the new code is a fresh crypto.randomUUID() that never crosses the
        // HTTP boundary (the caller discards it and answers 401), so knowing
        // the burned code buys an attacker nothing it did not already have.
        // Reached only when NOBODY can authenticate (guarded above), so a
        // consumed code means a stranded authority: regenerate.
        this.ctx.storage.sql.exec("DELETE FROM bootstrap WHERE id = 'code'");
      } else {
        // Expire after 15 minutes
        const created = new Date(rows[0]!.created_at + "Z").getTime();
        const BOOTSTRAP_TTL_MS = 15 * 60 * 1000;
        if (Date.now() - created > BOOTSTRAP_TTL_MS) {
          this.ctx.storage.sql.exec("DELETE FROM bootstrap WHERE id = 'code'");
        } else {
          return { status: "issued", code: rows[0]!.code };
        }
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
    return { status: "issued", code };
  }

  async consumeBootstrapCode(code: string): Promise<boolean> {
    // THE INVARIANT, enforced here as well as at mint: a bootstrap code is
    // valid ONLY while nobody can authenticate.
    //
    // Gating getOrCreateBootstrapCode alone fixed what the authority REPORTS
    // and left what it ACCEPTS unchanged — a code minted before the first
    // administrator existed, read from the Worker logs and never redeemed,
    // stayed consumable afterwards. POST /cert consumes bootstrap codes and
    // mints authorityManage + certMint, so that was an admin credential
    // outliving its purpose, bounded only by the 15-minute TTL.
    //
    // Mint-side gating cannot cover this: the code was legitimately issued at
    // a moment when it was valid. Only the consumer knows the authority has
    // since gained a way in.
    const { ensurePasskeySchema } = await import("./auth/passkey");
    const { ensurePrincipalSchema } = await import("./auth/principals");
    // ── OPERATOR SECRET OUTRANKS THE AUTHENTICATOR GATE (notme-4838ae) ──
    //
    // Checked BEFORE #hasAuthenticator, deliberately, and this is a security
    // decision rather than an ordering detail.
    //
    // Every other path to authorityManage is gated on isFirstUser, and both
    // bootstrap paths were gated on "no authenticator exists". So once ANY
    // passkey was registered, losing the last admin credential left the
    // authority permanently ungovernable — no invites, no grants, no
    // rotation, no alarm reset. The CA kept issuing certificates and could
    // not be administered. Found live on production 2026-08-06.
    //
    // Setting BOOTSTRAP_CODE requires control of the DEPLOYMENT, which is
    // strictly STRONGER than holding a passkey: that operator can already
    // redeploy the Worker, rebind KV, or replace this Durable Object
    // outright. Refusing them admin protected nothing — it only turned
    // "recover" into "brick".
    //
    // This does NOT reopen notme-976385. That gate exists because a code was
    // MINTED INTO WORKER LOGS BY AN UNAUTHENTICATED STRANGER'S REQUEST — a
    // mechanism removed in notme-addef9. The stored-code path below keeps the
    // gate; only an explicitly-set secret bypasses it.
    //
    // LOUD, because silent admin acquisition is the thing the gate guarded.
    const operatorSecret = bootstrapSecret(this.env);
    if (operatorSecret) {
      const { timingSafeEqual } = await import("./auth/timing-safe");
      if (await timingSafeEqual(code, operatorSecret)) {
        console.warn(
          "[bootstrap] ADMIN RECOVERY: operator secret accepted while authenticators exist (notme-4838ae)",
        );
        return true;
      }
    }

    if (this.#hasAuthenticator(ensurePasskeySchema, ensurePrincipalSchema)) {
      return false;
    }

    // PREFERRED PATH: an operator-set secret (notme-addef9). Checked before
    // the stored code because it is the one that requires control of the
    // DEPLOYMENT rather than the ability to read a log, and because on a
    // fresh authority no stored code exists at all — the public route no
    // longer mints one.
    //
    // Compared timing-safe: this grants authorityManage, so a comparison that
    // leaked position would let a caller recover it byte by byte.
    const secret = bootstrapSecret(this.env);
    if (secret) {
      const { timingSafeEqual } = await import("./auth/timing-safe");
      if (await timingSafeEqual(code, secret)) return true;
      // Fall through rather than returning false. An authority can hold BOTH
      // an operator secret and a legacy stored code (armed deliberately via
      // getOrCreateBootstrapCode before this change), and refusing the stored
      // one here would strand it.
    }

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
  // Scheduled on first #getOrCreateSigningKey() and re-arms after each fire.
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

  /**
   * Sign the current bundle and publish it to the KV the edge reads.
   *
   * ECMAScript #private: a `private` method stays live on the DO's RPC
   * surface (ADR-016), and nothing outside this object should be able to
   * force a republish. Shared by `alarm()` and `revokeEpoch()` so the two
   * cannot drift — a revocation that published a differently-shaped bundle
   * than the refresh path would be a very bad day to debug.
   *
   * No CA_BUNDLE_CACHE binding is a real configuration, not a failure: the
   * bundle is still signed and the state still advances.
   */
  async #publishBundle(): Promise<CABundle> {
    const bundle = await this.generateBundle();
    if (this.env.CA_BUNDLE_CACHE) {
      await this.env.CA_BUNDLE_CACHE.put(
        "bundle:current",
        JSON.stringify(bundle),
      );
    }
    return bundle;
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
      await this.#publishBundle();
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
