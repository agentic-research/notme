// notme.bot — minimal Worker shell
// Static assets served via ASSETS binding. Add routes here as needed.

export { RevocationAuthority } from "./src/revocation";
export { SigningAuthority } from "./src/signing-authority";
import type { MintBridgeCertProof } from "./src/signing-authority";

import { WorkerEntrypoint } from "cloudflare:workers";
import {
  AUTHORITY_GRANT_TYPES,
  buildAsMetadata,
  getSigningAlgs,
} from "./src/as-metadata";
import {
  ensureCurrentCABundle,
  handleInternalCABundle,
} from "./src/internal-ca-bundle";
import { ED25519, type Platform } from "./src/platform";

// ── Private RPC surface — only callable via service binding ──
// Consuming Workers bind to this entrypoint:
//   [[services]]
//   binding = "AUTH"
//   service = "notme-bot"
//   entrypoint = "AuthService"
//
// Then call, passing EVIDENCE rather than a subject (notme-51ccd7):
//   await env.AUTH.mintBridgeCert({ kind: "gha-oidc", token }, publicKeyPem)
//   await env.AUTH.mintBridgeCert({ kind: "session-cookie", cookie }, pem)
// The authority re-verifies the proof and derives the subject itself, so a
// binding holder cannot mint a certificate for an identity it has not
// proved. No HTTP, no public URL, no CORS, no tokens needed.

// ── Held credentials type ─────────────────────────────────────────────────
// Per-RPC-session — stored on `this.#heldCerts` so concurrent / sequential
// callers never see each other's principals. See contract test
// "authenticate must not leak credentials across RPC sessions".
type HeldCerts = {
  mtlsCert: string;
  signingCert: string;
  mtlsKey: CryptoKey;
  signingKey: CryptoKey;
  identity: string;
  scopes: string[];
  expiresAt: number;
};

// Cloud metadata endpoints — hard-denied, not configurable
const DENIED_HOSTS = new Set([
  "169.254.169.254", // AWS/GCP metadata
  "metadata.google.internal", // GCP metadata
  "100.100.100.200", // Alibaba metadata
]);

// Audience allowlist — every endpoint that mints an access token must check
// the requested audience against this set. Hoisted to module scope so /token
// and /authorize/token (and any future minting route) share one source of
// truth — drift here is how confused-deputy bugs slip in.
// Implementation in src/allowed-audiences.ts so unit tests can import it
// without pulling in cloudflare:workers via worker.ts.
import { getAllowedAudiences } from "./src/allowed-audiences";
import { dpopNonceRequired } from "./src/auth/dpop-nonce";
import { verifyPopProofs } from "./src/auth/pop";
import { principalIdentity } from "./src/cert-authority";
import { buildInfo } from "./src/build-version";
import { cacheKey, setCacheBuild, wantsJson } from "./src/cache-key";

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

/**
 * ReceiptSigner — Interlace 0.2.0 receipt signing for cloister (ADR-014).
 *
 * An RPC entrypoint, NOT a fetch route, and that is the whole point. The
 * requirement was that this "must not be externally routable". The existing
 * `/internal/ca-bundle` route does not achieve that — it is registered before
 * host enforcement and answers from the public internet, which is fine for a
 * public CA bundle and a trap for anything else. No header, shared secret, or
 * `request.cf` inspection reliably distinguishes a service-binding fetch from
 * an internet request, and the CA master key is not the place to bet on one.
 * An RPC method has no URL: non-routability is structural, not enforced.
 *
 * A separate entrypoint rather than a method on AuthService keeps least
 * privilege — a binding to ReceiptSigner grants receipt signing and nothing
 * else, not `proxy()`/`sign()`/`authenticate()`.
 *
 * BINDING: this needs its OWN service binding, e.g.
 *
 *     ( name = "NOTME_RECEIPTS", service = "notme-bot", entrypoint = "ReceiptSigner" )
 *
 * NOT an `entrypoint` added to an existing plain binding. Cloister's `NOTME`
 * binding is live for the `/identity/*` fetch proxy (cloister config.capnp:207,
 * typed `Fetcher` at types.ts:113); pinning an entrypoint on it would redirect
 * that traffic to this class, which has no `fetch` handler, and break identity.
 * An earlier draft of this comment said to add the entrypoint to `NOTME` — that
 * instruction would have broken the first integrator to follow it.
 *
 * Both methods live on THIS entrypoint, so one dedicated binding is enough.
 */
export class ReceiptSigner extends WorkerEntrypoint<any> {
  /**
   * Sign a canonical Interlace commitment with the authority master key.
   *
   * @param commitment Canonical CBOR commitment bytes (RECEIPTS.md §2.1).
   *   NOT trusted: validated, canonically re-encoded, and required to match
   *   byte-for-byte before anything is signed. See src/receipts/commitment.ts
   *   for why signing caller-supplied bytes with this key would be a CA
   *   compromise rather than merely sloppy.
   *
   * @returns `{ signature, epoch }`. `epoch` is the authority's, so cloister
   *   does not have to track it separately — and cannot assert it.
   *
   *   On failure returns `{ ok: false, code, message }` rather than throwing:
   *   an RPC rejection stringifies, leaving a caller nothing but message text
   *   to branch on. `EPOCH_MISMATCH` specifically means re-read
   *   `receiptFacts()` — key rotation moved underneath you.
   */
  /**
   * The `actor_fp` and `epoch` a commitment must carry.
   *
   * Cloister needs both to build a commitment and `signReceipt` rejects any
   * that disagree, so serving them from the same authority that enforces them
   * removes a whole class of "receipt rejected, epoch drifted" failures.
   * Cache it, but re-read on an EPOCH_MISMATCH rather than polling — rotation
   * here is alarm-driven.
   */
  async receiptFacts(): Promise<{
    /**
     * ALREADY HASHED: SHA-256 of the raw Ed25519 master public key, 32 bytes,
     * ready to place in the commitment's `actor_fp` field verbatim.
     *
     * Returned hashed rather than as the pubkey deliberately. If the caller
     * hashed it, the caller would own a derivation this authority then
     * validates against — reintroducing exactly the drift this method exists
     * to remove.
     */
    actorFp: Uint8Array;
    epoch: number;
  }> {
    const id = this.env.SIGNING_AUTHORITY.idFromName("default");
    return this.env.SIGNING_AUTHORITY.get(id).getReceiptFacts();
  }

  async signReceipt(
    commitment: Uint8Array | ArrayBuffer,
  ): Promise<import("./src/signing-authority").ReceiptSignResult> {
    const bytes =
      commitment instanceof ArrayBuffer
        ? new Uint8Array(commitment)
        : new Uint8Array(
            commitment.buffer,
            commitment.byteOffset,
            commitment.byteLength,
          );
    // Copy when the view is not the whole buffer: `validateCommitment`
    // re-encodes and compares against exactly these bytes, and a view over a
    // larger buffer would otherwise compare against neighbouring data.
    const owned =
      bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength
        ? bytes
        : new Uint8Array(bytes);

    const id = this.env.SIGNING_AUTHORITY.idFromName("default");
    const authority = this.env.SIGNING_AUTHORITY.get(id);
    return authority.signReceiptCommitment(owned);
  }
}

/**
 * JwtSigner — delegated OAuth token signing for cloister (ADR-015).
 *
 * Separate entrypoint AND separate key. The key separation is the security
 * control: notme's own access tokens are `at+jwt` signed by the CA master with
 * `iss: https://auth.notme.bot`, and `verifyAccessToken` leaves `issuer`
 * unchecked by default — so signing a delegated caller's JWT with the master
 * key would hand that caller a token every notme resource server accepts, for
 * any subject and any scope. That is an authentication bypass, not merely a
 * forgery oracle, and no amount of claim validation fixes it. A distinct key
 * makes such a token cryptographically unrelated to notme's own.
 *
 * BINDING: needs its OWN dedicated binding, for the same reason ReceiptSigner
 * does —
 *
 *     ( name = "NOTME_JWT", service = "notme-bot", entrypoint = "JwtSigner" )
 *
 * NOT an `entrypoint` on the existing `NOTME` binding, which is live for the
 * /identity/* fetch proxy.
 */
export class JwtSigner extends WorkerEntrypoint<any> {
  /**
   * Operator-configured delegated issuers, CSV in `DELEGATED_JWT_ISSUERS`.
   *
   * An allowlist rather than caller-supplied, because a caller that could
   * register an issuer could register `https://auth.notme.bot` and be handed a
   * key that mints tokens under this authority's own name.
   */
  #allowedIssuers(): Set<string> {
    const raw = (this.env.DELEGATED_JWT_ISSUERS ?? "").trim();
    return new Set(
      raw
        .split(",")
        .map((s: string) => s.trim())
        .filter((s: string) => s.length > 0),
    );
  }

  #authority() {
    return this.env.SIGNING_AUTHORITY.get(
      this.env.SIGNING_AUTHORITY.idFromName("default"),
    );
  }

  /**
   * The public key and kid for a delegated issuer, for the caller to publish
   * in its own JWKS.
   *
   * Cloister must point `manifest.actor.pubkeyBinding` at THIS key, not at
   * notme's master. Publishing the master while signing with the delegated key
   * makes every issued token fail verification — the right failure direction,
   * but worth doing in the right order.
   */
  async issuerPublicKey(
    issuer: string,
  ): Promise<
    | { ok: true; publicRawB64: string; kid: string }
    | { ok: false; code: "ISSUER_NOT_DELEGATED"; message: string }
  > {
    if (!this.#allowedIssuers().has(issuer)) {
      return {
        ok: false,
        code: "ISSUER_NOT_DELEGATED",
        message: `issuer ${JSON.stringify(issuer)} is not in DELEGATED_JWT_ISSUERS`,
      };
    }
    const { publicRawB64, kid } =
      await this.#authority().getDelegatedJwtKey(issuer);
    return { ok: true, publicRawB64, kid };
  }

  /**
   * Sign a JWS signing input (RFC 7515 §3.1) for a delegated issuer.
   *
   * @returns raw 64-byte Ed25519 signature + the delegated kid. The caller
   *   assembles `header.payload.signature` itself — notme does not build the
   *   compact serialization, for the same reason it does not build receipt
   *   envelopes: one wire format, one implementation.
   */
  async signJwt(params: {
    issuer: string;
    headerB64: string;
    payloadB64: string;
  }): Promise<import("./src/signing-authority").DelegatedJwtSignResult> {
    if (!this.#allowedIssuers().has(params.issuer)) {
      return {
        ok: false,
        code: "ISSUER_NOT_DELEGATED",
        message: `issuer ${JSON.stringify(params.issuer)} is not in DELEGATED_JWT_ISSUERS`,
      };
    }
    return this.#authority().signDelegatedJwt(params);
  }
}

export class AuthService extends WorkerEntrypoint<any> {
  // RPC-session-scoped credentials. WorkerEntrypoint creates a fresh `this`
  // per RPC session in workerd, so this field is naturally per-caller.
  // DO NOT hoist to module scope — see notme/worker review Finding 1.
  // `#`-private, NOT TypeScript `private`: this class is RPC-reachable, and
  // TS `private` is erased at build time, so the field would stay readable on
  // any stub someone obtains. The runtime mitigations are real — workerd gives
  // a fresh `this` per RPC session, so a caller sees only their own, and
  // workerd's serializer refuses CryptoKey (measured by
  // rpc.cryptokey.isolation; note this is a WORKERD behaviour, not the W3C
  // one — CryptoKey is `[Serializable]` in the IDL, notme-bcbd74) — but they
  // are properties of the RUNTIME, not of the declaration (notme-2154b8).
  #heldCerts: HeldCerts | null = null;

  /**
   * ECMAScript #private, NOT TypeScript `private`.
   *
   * TS `private` is erased at compile time. This is a prototype method on a
   * WorkerEntrypoint, and workerd exposes those over RPC — so as `private` it
   * was a live RPC method handing any caller the raw SigningAuthority stub,
   * and with it the whole DO: mintBridgeCertPair() with caller-chosen identity
   * and scopes, rotate(), getSessionSecret(), createPrincipalWithCapabilities().
   * A complete CA compromise for anyone holding an AUTH binding, which per
   * ADR-009 is every agent Worker.
   *
   * That also falsified ADR-014's least-privilege rationale for putting
   * receipt signing on its own entrypoint: the separation was real for
   * ReceiptSigner and undone next door.
   *
   * `#` is enforced by the runtime, not the type system. Never rely on TS
   * `private` at an RPC boundary.
   */
  #getAuthority() {
    const id = this.env.SIGNING_AUTHORITY.idFromName("default");
    return this.env.SIGNING_AUTHORITY.get(id);
  }

  /**
   * Mint a bridge cert for the subject the PROOF names (notme-51ccd7).
   *
   * This used to read "for a verified subject" and take that subject as a
   * string — nothing verified it, and the word was doing the work a check
   * should have. A holder of this binding could name any subject; per
   * ADR-009 that is every agent Worker.
   *
   * The envelope is passed through unexamined ON PURPOSE. This entrypoint
   * must not be the thing that decides the subject is genuine, because it is
   * the surface an attacker reaches; the DO re-verifies and derives it.
   *
   * Returns `{ ok: false, reason }` rather than throwing — switch on it. A
   * rejected proof is an expected outcome, and a DO method that throws is
   * double-reported by workerd (see `BridgeCertRefusal`).
   */
  async mintBridgeCert(
    proof: MintBridgeCertProof,
    publicKeyPem: string,
    ttlMs?: number,
  ) {
    const authority = this.#getAuthority();
    return authority.mintBridgeCert(proof, publicKeyPem, ttlMs);
  }

  /*
   * mintDPoPToken WAS HERE AND IS DELETED (notme-d68da8).
   *
   * Its signature was `{ sub, scope, audience, jkt }` and it forwarded all
   * four to the DO, which signed them with the master Ed25519 key. So a
   * holder of this binding — per ADR-009, every agent Worker — named the
   * subject, the scope AND the audience of a genuine `at+jwt` carrying
   * notme's real issuer. src/allowed-audiences.ts states the rule it went
   * around in its own docstring: "every endpoint that mints an access token
   * must check the requested audience against this set." /token and
   * /authorize/token both do, and both require a notme_session first.
   *
   * Measured, not hypothesised: rig/web verifies notme tokens on signature
   * and exp alone — no aud, no iss, and cnf.jkt unread on the token-only
   * path — sets `identity.id = claims.sub`, then compares that id to
   * ADMIN_USER_ID. One call named rig's admin.
   *
   * THE SAME DEFECT AS mintBridgeCert ABOVE (notme-51ccd7), one method down,
   * and the pin in rpc-surface.do.test.ts had already written the standard
   * that catches it: reachability asks who may call, argument trust asks what
   * the method concludes from what it is handed. That standard was stated for
   * mintBridgeCert and not then applied to the rest of the list.
   *
   * Deleted rather than given a proof envelope, per the ADR-014 precedent for
   * the arbitrary-sign() oracle: zero callers in notme, rig, signet, cloister,
   * ley-line, ley-line-open, rosary or mache, and the live /token route calls
   * the DO's own mintDPoPTokenOnce directly. An unused minting method here is
   * one `env.AUTH.mintDPoPToken()` away from being reachable again, so it does
   * not stay with a warning comment.
   */

  /** Get the CA public key PEM. */
  async getPublicKeyPem() {
    const authority = this.#getAuthority();
    return authority.getPublicKeyPem();
  }

  /** Get the X.509 CA certificate PEM (for mTLS trust store). */
  async getCACertificatePem() {
    const authority = this.#getAuthority();
    return authority.getCACertificatePem();
  }

  /** Get authority state (epoch, seqno, keyId). */
  async getAuthorityState() {
    const authority = this.#getAuthority();
    return authority.getAuthorityState();
  }

  /** Verify a session cookie, return principal info. */
  async verifySession(cookie: string) {
    const authority = this.#getAuthority();
    const { verifySessionCookie } = await import("./src/auth/session");
    const secret = await authority.getSessionSecret();
    return verifySessionCookie(cookie, secret);
  }

  // ── 009: Identity-gated runtime methods ──────────────────────────────────

  /**
   * Store credentials for proxy/sign operations.
   * Called after a successful 008 PoP exchange. Keys must be CryptoKey objects
   * (non-extractable). Certs are PEM strings (public data).
   *
   * `identity`, `scopes` and `expiresAt` are NOT parameters, deliberately.
   * This method is reachable by any Worker holding an `AUTH` service binding,
   * and it used to accept all three as caller-supplied fields and assign them
   * verbatim — so a bound Worker could name itself any WIMSE principal and
   * grant itself any scope, while `proxy()` gated on those scopes and the
   * audit log recorded that identity as fact (notme-6ad276).
   *
   * The certs are the only unforgeable thing a caller can present: they are
   * CA-signed and already carry the subject and granted scopes. So the
   * principal is DERIVED from them here and the caller's opinion of who it is
   * never enters. Extra fields on the argument are structurally ignored.
   *
   * @throws if either cert fails CA verification, is outside its validity
   *         window, or names a different principal than its partner. On throw
   *         the session stays unauthenticated — a failed authenticate() must
   *         not leave stale creds from a previous successful one.
   *
   * CALLING CONVENTION, measured (notme-bcbd74): this signature cannot be
   * satisfied over a service binding today. workerd's RPC serializer refuses
   * `CryptoKey` — the whole argument fails with a DataCloneError before the
   * method runs, nested or not (`rpc.cryptokey.isolation`). Every caller in
   * this repo constructs an AuthService directly, in-isolate, where that does
   * not apply.
   *
   * The reachability reasoning above still holds and the derivation is still
   * required: a bound Worker CAN reach this method, and can pass the cert
   * strings — which serialize fine — with the key fields absent. That call
   * would set credentials whose identity and scopes came from certs, which is
   * the point; it simply could not then sign. Do not read "unreachable in
   * practice" into a serializer limitation.
   */
  async authenticate(creds: {
    mtlsCert: string;
    signingCert: string;
    mtlsKey: CryptoKey;
    signingKey: CryptoKey;
  }) {
    const { deriveCredentialsFromCerts } =
      await import("./src/auth/derive-credentials");
    const authority = this.#getAuthority();
    const caPublicKeyPem = await authority.getPublicKeyPem();

    // Clear first: if verification throws, the session must not keep whatever
    // it held before. Re-authenticating with a bad cert would otherwise leave
    // the previous identity in place and look like it succeeded.
    this.#heldCerts = null;

    const derived = await deriveCredentialsFromCerts(
      creds.signingCert,
      creds.mtlsCert,
      caPublicKeyPem,
    );

    this.#heldCerts = {
      mtlsCert: creds.mtlsCert,
      signingCert: creds.signingCert,
      mtlsKey: creds.mtlsKey,
      signingKey: creds.signingKey,
      identity: derived.identity,
      scopes: derived.scopes,
      expiresAt: derived.expiresAt,
    };
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
    if (!this.#heldCerts) {
      throw new Error("not authenticated — call authenticate() first");
    }
    if (this.#heldCerts.expiresAt <= Math.floor(Date.now() / 1000)) {
      throw new Error("credentials expired — re-authenticate");
    }

    // Destination check
    if (isDeniedDestination(request.url)) {
      throw new Error(
        "destination denied — cloud metadata endpoints are blocked",
      );
    }

    // Scope check
    if (!this.#heldCerts.scopes.includes("bridgeCert")) {
      throw new Error("scope insufficient — bridgeCert required for proxy");
    }

    // Make the request
    const start = Date.now();
    const res = await fetch(request.url, {
      method: request.method || "GET",
      headers: request.headers || {},
      body: request.body,
    });

    const responseHeaders: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      responseHeaders[k] = v;
    });
    const body = await res.text();

    // Audit log — structured JSON, feeds into APAS attestations
    console.log(
      JSON.stringify({
        ts: new Date().toISOString(),
        type: "proxy",
        identity: this.#heldCerts.identity,
        destination: request.url,
        method: request.method || "GET",
        scope_checked: "bridgeCert",
        allowed: true,
        response_status: res.status,
        duration_ms: Date.now() - start,
      }),
    );

    return { status: res.status, headers: responseHeaders, body };
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
    if (!this.#heldCerts) {
      throw new Error("not authenticated — call authenticate() first");
    }

    // Scope check for signing
    const signingScopes = ["sign:git", "sign:attestation"];
    const hasSignScope =
      format === "raw"
        ? true // raw signing doesn't require a specific scope
        : this.#heldCerts.scopes.some((s) => signingScopes.includes(s));
    if (!hasSignScope) {
      throw new Error(
        `scope insufficient — ${format} requires one of: ${signingScopes.join(", ")}`,
      );
    }

    const signature = await crypto.subtle.sign(
      ED25519,
      this.#heldCerts.signingKey,
      payload,
    );

    // Audit log
    const payloadHash = Array.from(
      new Uint8Array(await crypto.subtle.digest("SHA-256", payload)),
    )
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    console.log(
      JSON.stringify({
        ts: new Date().toISOString(),
        type: "sign",
        identity: this.#heldCerts.identity,
        format,
        payload_hash: `sha256:${payloadHash}`,
        scope_checked:
          format === "raw"
            ? "none"
            : signingScopes.find((s) => this.#heldCerts!.scopes.includes(s)),
        allowed: true,
      }),
    );

    return {
      signature,
      certificate: this.#heldCerts.signingCert,
      identity: this.#heldCerts.identity,
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
    if (!this.#heldCerts) {
      return {
        identity: "",
        scopes: [],
        certificates: { mtls: "", signing: "" },
        expires_at: 0,
        authenticated: false,
      };
    }
    return {
      identity: this.#heldCerts.identity,
      scopes: this.#heldCerts.scopes,
      certificates: {
        mtls: this.#heldCerts.mtlsCert,
        signing: this.#heldCerts.signingCert,
      },
      expires_at: this.#heldCerts.expiresAt,
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
    // NO rate-limit tunables here. They existed for the KV limiter that the
    // CERT_LIMITER binding replaced, and nothing read them afterwards — so
    // RATE_LIMIT_MAX_CERTS=50 in a self-hosted wrangler.toml changed nothing
    // while reading as the knob that set the limit. Their 1-hour/10-cert
    // defaults are also where THREAT_MODEL's "10 certs/repo/hour" came from;
    // the binding enforces 10 per 60 SECONDS (wrangler.toml [[ratelimits]]).
    // notme-900e28.
  };
}
/**
 * GitHub owners permitted to exchange an OIDC token for a bridge cert.
 *
 * NO DEFAULT — an unset or empty value yields the empty set, which refuses
 * every exchange. It previously defaulted to "agentic-research", so a
 * deployment that DELETED the variable silently re-supplied the production
 * org: staging could mint certs for production's org precisely because its
 * config said nothing (notme-1532eb). An authority that has not declared
 * whose workflows it trusts must trust none.
 */
export function getAllowedOwners(env: {
  GHA_ALLOWED_OWNERS?: string;
}): Set<string> {
  const raw: string = env.GHA_ALLOWED_OWNERS ?? "";
  return new Set(
    raw
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  );
}

const TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";

function jsonErr(message: string, status: number): Response {
  return Response.json({ error: message }, { status });
}

async function handleCertGHA(
  request: Request,
  env: any,
  platform: Platform,
): Promise<Response> {
  if (request.method !== "POST") {
    return jsonErr("method not allowed", 405);
  }

  const cfg = getConfig(env);

  try {
    // Ensure CA bundle is published to KV (lazy init — first request bootstraps)
    await ensureCurrentCABundle(env, platform);
  } catch (e: any) {
    return jsonErr("authority unavailable: " + e.message, 503);
  }

  // Get authority DO stub (signing happens inside the DO — CryptoKey can't cross RPC)
  const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
  const authority = env.SIGNING_AUTHORITY.get(authorityId);

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
    const ttl = Math.max(
      cfg.jtiMinTtlSeconds,
      claims.exp - Math.floor(Date.now() / 1000),
    );
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
    return jsonErr(
      "public_keys.mtls and public_keys.signing required (SPKI PEM)",
      400,
    );
  }
  if (!body.proofs?.mtls || !body.proofs?.signing) {
    return jsonErr(
      "proofs.mtls and proofs.signing required (signatures over binding payload)",
      400,
    );
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
  const mtlsSpki = (await crypto.subtle.exportKey(
    "spki",
    mtlsPubKey,
  )) as ArrayBuffer;
  const signingSpki = (await crypto.subtle.exportKey(
    "spki",
    signingPubKey,
  )) as ArrayBuffer;
  const oidcHash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token),
  );
  const bindingInput = new Uint8Array(
    mtlsSpki.byteLength + signingSpki.byteLength + 32,
  );
  bindingInput.set(new Uint8Array(mtlsSpki), 0);
  bindingInput.set(new Uint8Array(signingSpki), mtlsSpki.byteLength);
  bindingInput.set(
    new Uint8Array(oidcHash),
    mtlsSpki.byteLength + signingSpki.byteLength,
  );
  // Verify PoP over the binding PRE-IMAGE — never its digest (notme-a011d2).
  const pop = await verifyPopProofs(
    bindingInput,
    mtlsPubKey,
    signingPubKey,
    body.proofs,
  );
  if (!pop.ok) {
    return jsonErr(`${pop.algorithm} proof-of-possession failed`, 401);
  }

  // Build WIMSE identity URI
  // The identity names the stable subject — the OIDC `sub`, which is also
  // the cert CN — rather than /gha/<owner>/<repo>, which encoded the
  // ATTESTATION MECHANISM in the slot other routes filled with a ceremony
  // (ADR-019 D2, notme-77438b). Owner and repo remain readable from `sub`
  // and from the workflow claims; principal_kind = "workload" is stamped as
  // its own extension.
  // NO BOOTSTRAP HERE any more (notme-486e8a). This route used to make the
  // attested workflow the administrator as a side effect of a cert request —
  // and since a release job typically shares the bootstrap subject, the first
  // /cert/gha on a fresh authority installed an admin no human could act as
  // and closed registration to everyone. Bootstrap is now POST
  // /bootstrap/claim: the workflow APPROVES a human's passkey claim.

  const identity = principalIdentity(wimseTrustDomain(env), claims.sub);

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
    // Present only when THIS call bootstrapped the authority. The cert still
    // carries bridgeCert alone — capabilities live on the principal, and a
    // cert carries only what is safe to export (passkey-cert-scopes.ts).
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

  if (env.PASSKEY_LIMITER) {
    const ip = request.headers.get("cf-connecting-ip") || "unknown";
    const { success } = await env.PASSKEY_LIMITER.limit({
      key: `passkey:${ip}`,
    });
    if (!success) {
      return jsonErr("rate_limited", 429);
    }
  }

  const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
  const authority = env.SIGNING_AUTHORITY.get(authorityId);
  // Derive origin from SITE_URL (env), not from attacker-controlled Host header.
  // Host header can be spoofed in non-CF environments (local dev, proxies).
  const siteUrl =
    env.SIGNET_AUTHORITY_URL || env.SITE_URL || "https://auth.notme.bot";
  const host = new URL(siteUrl).hostname;
  const origin = siteUrl;

  try {
    if (pathname === "/auth/passkey/register/options") {
      const body = (await request.json()) as {
        bootstrapCode?: string;
        inviteToken?: string;
      };
      const userId = crypto.randomUUID();
      const result = await authority.passkeyRegistrationOptions(
        userId,
        "user",
        host,
      );

      // CLAIM REGISTRATION (notme-486e8a). No bootstrap code, no invite, and
      // the authority has NO administrator while the attested-claim mechanism
      // is armed: register the passkey as a claim holding nothing, to be
      // approved by the workflow named in BOOTSTRAP_GHA_SUBJECT. Gated on "no
      // administrator", not "first user" — otherwise whoever registered first
      // and was never approved would lock the deployer out for good.
      if (!body.bootstrapCode && !body.inviteToken && (await authority.claimAvailable())) {
        const mark = await authority.markClaimRegistration(userId);
        if (!mark.ok) {
          return jsonErr(
            mark.reason === "busy" ? "too many pending claims — retry shortly" : "claim unavailable",
            mark.reason === "busy" ? 503 : 409,
          );
        }
        return Response.json({ ...result, userId, scopes: [], claim: true });
      }
      // First user requires bootstrap code (proves deployer ownership)
      // Everyone else can register freely — gets bridgeCert scope only
      if (result.isFirstUser && !body.bootstrapCode) {
        // A READ, not a mint (notme-addef9). This route is unauthenticated,
        // so calling getOrCreateBootstrapCode() here meant any stranger's
        // first request caused an admin credential to be minted and logged —
        // the trigger was never the deployer, and it could be repeated at a
        // moment of the caller's choosing.
        //
        // Each branch says what the operator should actually DO, and none of
        // them says "read a secret out of the logs". That path was both the
        // wrong posture for this repo and unreliable in practice: `wrangler
        // tail` produced nothing for a known-good 200 in production this
        // cycle, so the documented recovery could simply fail.
        const bootstrap = await authority.getBootstrapState();
        switch (bootstrap.status) {
          case "armed": {
            // Name only the mechanisms actually armed. This branch used to
            // say "bootstrap code required" unconditionally, and the
            // unconfigured branch pointed at /cert/gha — a route that
            // granted bridgeCert and created no principal, so the advice
            // could not work (notme-addef9).
            // Each offer is a standalone clause; the conjunction is added
            // when joining. Baking "or " into the second one read as
            // "bootstrap required — or run the workflow…" whenever gha-oidc
            // was the only armed mechanism, which sounds like a first option
            // went missing. Caught by running the thing and reading what it
            // says, which is the only way this class of defect surfaces.
            const offers: string[] = [];
            if (bootstrap.methods.includes("secret")) {
              offers.push(
                "supply the BOOTSTRAP_CODE this deployment was configured with",
              );
            }
            if (bootstrap.methods.includes("gha-oidc")) {
              // Normally unreachable: with gha-oidc armed and no administrator,
              // an unauthenticated registration becomes a claim above. Kept
              // accurate for the one way here — a claim that was refused.
              offers.push(
                "register a passkey as a claim and approve it with the workflow named by BOOTSTRAP_GHA_SUBJECT (claim-authority.yml)",
              );
            }
            return jsonErr(`bootstrap required — ${offers.join(", or ")}`, 401);
          }
          case "unconfigured":
            // Fail closed AND fail informative. An authority nobody can
            // bootstrap is a recoverable operator error; one that silently
            // mints a credential into a log is not.
            return jsonErr(
              "this authority has no administrator and no bootstrap mechanism is armed — the deployer must either set BOOTSTRAP_GHA_SUBJECT to the GitHub workflow identity allowed to bootstrap it (a var, not a secret: nothing to leak, nothing to read out of a log), or `wrangler secret put BOOTSTRAP_CODE`, and retry",
              401,
            );
          case "closed":
            return jsonErr(
              "this authority already has an administrator — sign in with a passkey, or ask an admin for an invite",
              401,
            );
        }
      }
      if (result.isFirstUser) {
        const valid = await authority.consumeBootstrapCode(body.bootstrapCode!);
        if (!valid) {
          return jsonErr("invalid or already-used bootstrap code", 403);
        }
      }

      // REGISTRATION IS GATED (notme-2c4209, ADR-021). Until now everyone
      // after the first user registered freely and walked away with a
      // CA-signed cert pair — an open-registration certificate authority,
      // written down nowhere but a comment.
      //
      // The invite is the mechanism TODAY. The decision is that registration
      // is a policy question, and the eventual answer is signet's trust
      // policy bundle (sigpol, ADR-011 §5.3: is this subject provisioned,
      // is it active, what capabilities do its groups resolve to). notme
      // must not grow a second subject registry to answer it — ADR-011 §2.1
      // argues that case, and ADR-020 forbids it here.
      //
      // Scopes come from the INVITE, never from the request: a caller that
      // could name its own scopes would make the gate decorative.
      let invitedScopes: string[] | null = null;
      if (!result.isFirstUser) {
        if (!body.inviteToken) {
          return jsonErr(
            "registration is invite-only — ask an administrator for an invite link",
            403,
          );
        }
        const redeemed = await authority.redeemInviteToken(
          body.inviteToken,
          userId,
        );
        if (!redeemed) {
          return jsonErr("invalid, expired or already-used invite", 403);
        }
        invitedScopes = redeemed.scopes;
      }

      // Deployer gets all; an invited user gets exactly what the invite says.
      const scopes = result.isFirstUser
        ? [...(await import("./src/auth/admin-scopes")).ADMIN_SCOPES]
        : (invitedScopes ?? ["bridgeCert"]);

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
      // A claim registration holds NOTHING until the named workflow approves
      // it (notme-486e8a) — even if it is the first credential, which
      // verifyRegistration would otherwise treat as the admin.
      const claim = await authority.finalizeClaimRegistration(body.userId);
      if (claim) {
        const { createSessionCookie } = await import("./src/auth/session");
        const cookie = await createSessionCookie(
          { principalId: body.userId, scopes: [], authMethod: "passkey" },
          await authority.getSessionSecret(),
        );
        return new Response(
          JSON.stringify({
            verified: true,
            scopes: [],
            claim: {
              code: claim.code,
              expires_in: claim.expiresIn,
              command: `gh workflow run claim-authority.yml -f code=${claim.code}`,
              note: "Run this from the repository named by BOOTSTRAP_GHA_SUBJECT, then sign in again with this passkey.",
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json", "Set-Cookie": cookie } },
        );
      }

      // Scopes come from the GRANT STORE — never from the client body (scope
      // escalation vector) and no longer from the is_admin bit alone. The
      // passkey user becomes a principal with grants here, so its authority
      // has one source and one revoke path (notme-77a024 finding b).
      const scopes = await authority.ensurePasskeyPrincipal(
        body.userId,
        result.isAdmin,
      );

      // Issue session immediately after registration
      const { createSessionCookie } = await import("./src/auth/session");
      const sessionSecret = await authority.getSessionSecret();
      const cookie = await createSessionCookie(
        { principalId: body.userId, scopes, authMethod: "passkey" },
        sessionSecret,
      );

      return new Response(JSON.stringify({ verified: true, scopes }), {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Set-Cookie": cookie,
        },
      });
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
      // Principal model: userId is the principalId, scopes from the grant
      // store. A user registered before grants existed is enrolled on first
      // login (is_admin decides ONLY then); after that, revoking a grant is
      // what changes the answer here — logging in again does not restore it.
      const scopes = await authority.ensurePasskeyPrincipal(
        result.userId,
        result.isAdmin,
      );
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

/**
 * The tier-enrolment approval page (notme-486e8a). The fingerprint is the
 * point: device flow's known weakness is a human approving SOMEONE ELSE'S
 * code, and comparing the key fingerprint the machine printed is the check
 * that defeats it. Values reach the script as data attributes, never as
 * script text.
 */
function enrolPageHtml(
  userCode: string,
  fingerprint: string,
  scopes: string[],
  status: string,
): string {
  const esc = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const fp = fingerprint.slice(0, 16).match(/..../g)!.join(" ");
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>enroll a machine — auth.notme.bot</title>
  <style>
    body { background:#1c1810; color:#e8dcc8; font-family:ui-monospace,monospace; max-width:560px; margin:10vh auto; padding:0 20px; line-height:1.6 }
    code { color:#f0c674; font-size:1.25em }
    button { margin-top:20px; padding:10px 18px; font:inherit; background:#e8dcc8; color:#1c1810; border:0; cursor:pointer }
    .muted { color:#9a8f7c; font-size:.9em }
  </style>
</head>
<body data-code="${esc(userCode)}">
  <h1>Enroll a machine</h1>
  <p>A machine is asking to act on your behalf. It will be able to mint task certificates offline, under your identity, for up to 24 hours.</p>
  <p>Code: <code>${esc(userCode)}</code></p>
  <p>Key fingerprint: <code>${esc(fp)}</code></p>
  <p class="muted">Approve only if this fingerprint matches what the machine printed. If you did not start this, close the page.</p>
  <p class="muted">Requested scopes: ${esc(scopes.join(", ") || "bridgeCert")} — certMint is never delegated.</p>
  ${status === "pending" ? `<p>
    <label>It may renew without asking you again for
      <select id="renew">
        <option value="1">1 day</option>
        <option value="7" selected>7 days</option>
        <option value="30">30 days</option>
      </select></label>
  </p>
  <p class="muted">So a machine that pauses and resumes is not blocked on you. You can revoke it at any time; renewal stops at once.</p>
  <p>
    <label>Clone policy
      <select id="clone">
        <option value="singleton" selected>singleton — one copy of this key</option>
        <option value="replicas:2">replicas:2 (break glass)</option>
        <option value="replicas:4">replicas:4 (break glass)</option>
        <option value="replicas:8">replicas:8 (break glass)</option>
      </select></label>
  </p>
  <p class="muted">Replicas need authorityManage and a renewal horizon of at most 7 days. For now every line still acts as a singleton.</p>
  <button id="approve">approve</button>` : `<p>This enrollment is already ${esc(status)}.</p>`}
  <p id="out" class="muted"></p>
  <script>
    var b = document.getElementById('approve');
    if (b) b.addEventListener('click', async function () {
      b.disabled = true;
      var res = await fetch('/cert/issuing-ca/device/approve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_code: document.body.dataset.code,
          renew_days: Number(document.getElementById('renew').value),
          clone_policy: document.getElementById('clone').value
        })
      });
      var data = await res.json().catch(function () { return {}; });
      document.getElementById('out').textContent = res.ok
        ? 'Approved. Return to the machine — it will collect the certificate.'
        : (data.error || 'failed');
    });
  </script>
</body>
</html>`;
}

function authorizePageHtml(
  redirectUri: string,
  audience: string,
  state: string,
  // ADR-013. Empty string means the caller sent no PKCE challenge, and the
  // page takes the legacy `?token=` path. Threaded as a data attribute like
  // the others rather than inlined into script text — same no-eval rule.
  codeChallenge: string,
): string {
  // HTML-escape to prevent injection via query params
  const esc = (s: string) =>
    s
      .replace(/&/g, "&amp;")
      .replace(/"/g, "&quot;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");

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
  data-code-challenge="${esc(codeChallenge)}"
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
  var codeChallenge = el.getAttribute('data-code-challenge');
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
      var res = await fetch(codeChallenge ? '/authorize/code' : '/authorize/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(
          codeChallenge
            ? { audience: audience, redirect_uri: redirectUri, code_challenge: codeChallenge }
            : { audience: audience }
        ),
        credentials: 'same-origin'
      });

      if (!res.ok) {
        var err;
        try { err = (await res.json()).error; } catch(e) { err = res.statusText; }
        throw new Error(err || 'token request failed (' + res.status + ')');
      }

      var data = await res.json();
      var sep = redirectUri.indexOf('?') === -1 ? '?' : '&';
      var dest;

      if (codeChallenge) {
        // ADR-013: the URL carries a single-use code, not a credential. The
        // access token is fetched server-to-server by the party holding the
        // PKCE verifier, so it never enters this URL, browser history, or a
        // Referer.
        var code = data.code;
        if (!code) throw new Error('no code in response');
        addLine('authorization code issued (60s TTL, PKCE-bound)', 'ok');
        dest = redirectUri + sep + 'code=' + encodeURIComponent(code);
      } else {
        // Legacy path, removed once rig ships its side (notme-2bba44). This
        // puts a live bearer token in the URL — see THREAT_MODEL.md
        // 'token in URL logs'.
        var token = data.access_token;
        if (!token) throw new Error('no access_token in response');
        addLine('redirect token issued (5min TTL)', 'ok');
        dest = redirectUri + sep + 'token=' + encodeURIComponent(token);
      }

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
        workItemRef: {
          type: "object",
          description: "Work item reference",
          properties: {
            repo: { type: "string" },
            workItemId: { type: "string" },
            contentHash: { type: "string", pattern: "^sha256:[a-f0-9]+$" },
          },
          required: ["repo", "workItemId", "contentHash"],
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

// The authority surface is selected by hostname. `auth.notme.bot` stays the
// hardcoded production match (sub === "auth"); SIGNET_AUTHORITY_URL
// additionally selects the surface on whatever host it names, so a staging
// worker (env.staging routes auth-staging.notme.bot with
// SIGNET_AUTHORITY_URL=https://auth-staging.notme.bot) serves the authority
// from config alone. Malformed values resolve to null rather than throwing
// inside the fetch path — the hardcoded match still works when this returns
// null.
export function authorityHostFromEnv(
  signetAuthorityUrl: string | undefined,
): string | null {
  if (!signetAuthorityUrl) return null;
  try {
    const u = new URL(signetAuthorityUrl);
    // Hostless schemes (file:, data:, about:, mailto:) parse fine and yield
    // host "". Returning that would collapse the caller's `host ===
    // authorityHost` check into `host === ""`, which the bare-IP health-probe
    // path deliberately permits — a fail-OPEN guard. Require http(s) and a
    // non-empty host so a malformed value fails closed.
    if (u.protocol !== "https:" && u.protocol !== "http:") return null;
    return u.host || null;
  } catch {
    return null;
  }
}

/**
 * The WIMSE trust domain every minted identity is scoped to.
 *
 * Derived from SITE_URL, NOT a literal. The literal is why a
 * staging-minted cert was byte-identical to a production one in the only
 * field a verifier reads by name: staging has its own CA key but named
 * itself `wimse://notme.bot/...` all the same, so any consumer that trusts
 * the trust-domain string — rather than pinning the exact CA key — could be
 * handed a staging cert asserting a production identity.
 *
 * Production is unaffected: SITE_URL is https://notme.bot, so this returns
 * "notme.bot", exactly the literal it replaces. Staging returns
 * "staging.notme.bot", which makes every name-based verifier fail closed
 * without needing to know staging exists.
 */
export function wimseTrustDomain(env: { SITE_URL?: string }): string {
  // ABSENT and MALFORMED are treated differently, deliberately. Absent means
  // "no environment configured", whose documented default is production —
  // the value every mint site hardcoded before this existed. Malformed means
  // the operator configured SOMETHING and got it wrong, and silently
  // resolving that to the production trust domain would reintroduce exactly
  // the staging-impersonates-production defect this function removes. So it
  // throws, and the mint fails, rather than minting under a domain nobody
  // chose. (authorityHostFromEnv fails closed for the same reason; the two
  // were briefly inconsistent.)
  if (!env.SITE_URL) return "notme.bot";
  const u = new URL(env.SITE_URL); // throws on malformed — intentional
  if (u.protocol !== "https:" && u.protocol !== "http:") {
    throw new TypeError(
      `SITE_URL must be http(s) to derive a WIMSE trust domain; got ${u.protocol}`,
    );
  }
  if (!u.host) {
    throw new TypeError("SITE_URL has no host; cannot derive a trust domain");
  }
  return u.host;
}

/**
 * The host this deployment canonicalizes to, from SITE_URL.
 *
 * Absent → "notme.bot", the documented production default, matching
 * wimseTrustDomain's treatment of the same variable. Malformed → also
 * "notme.bot", and deliberately NOT a throw: this runs on every request
 * before any route matches, so throwing would turn one bad var into a total
 * outage. wimseTrustDomain throws because minting under a domain nobody
 * chose is worse than failing the mint; serving the wrong canonical host is
 * an SEO defect, not a trust one.
 */
export function siteHostFromEnv(siteUrl: string | undefined): string {
  if (!siteUrl) return "notme.bot";
  try {
    return new URL(siteUrl).host || "notme.bot";
  } catch {
    return "notme.bot";
  }
}

// ── CF Edge Cache helpers ──
// With run_worker_first = true, responses constructed in the Worker bypass CF
// edge cache entirely. We use the Cache API to store and serve them at the edge.
// Cache key includes Accept header for content-negotiated routes.


// Edge cache disabled when cacheApiOutbound is not configured (local workerd).
let cacheEnabled = true;

async function cachePut(
  request: Request,
  response: Response,
  vary?: string,
): Promise<Response> {
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

async function cacheMatch(
  request: Request,
  vary?: string,
): Promise<Response | undefined> {
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
    // Every cache key carries the build, so a deploy is never answered from
    // the previous version's entries (notme-486e8a, src/cache-key.ts).
    setCacheBuild(env);
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
    const corsAllowed =
      CORS_ALLOWED_ORIGINS.has(requestOrigin) ||
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

    /**
     * Mirror the preflight's origin decision onto a real response
     * (notme-0a27a6).
     *
     * The preflight above answers 204 with `Access-Control-Allow-Origin` and
     * permits the `DPoP` request header — but no non-preflight response
     * carried ACAO, so a cross-origin call passed preflight and then had its
     * response blocked with no diagnosable reason. Verified against the real
     * route: preflight 204 `ACAO: https://rosary.bot`, actual POST
     * `ACAO: null`.
     *
     * Deliberately NOT paired with `Access-Control-Allow-Credentials`.
     * THREAT_MODEL §7 records omitting it as a decision, and the session
     * cookie is `SameSite=Strict`, so a cross-origin caller sends no cookie
     * and `/token` answers 401 `session_required`. Exposing that 401 leaks
     * nothing — it is the same answer any unauthenticated caller gets — and
     * turning an opaque CORS failure into a readable status is the whole
     * point. Making cross-origin `/token` actually SUCCEED is a separate
     * design question (accept the session via an Authorization header rather
     * than a cookie), tracked on notme-0a27a6.
     *
     * `Vary: Origin` because the value depends on the request's Origin; a
     * cache that omitted it could serve one origin's ACAO to another.
     */
    const withCors = (response: Response): Response => {
      if (!corsAllowed) return response;
      const headers = new Headers(response.headers);
      headers.set("Access-Control-Allow-Origin", requestOrigin);
      headers.append("Vary", "Origin");
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers,
      });
    };

    const url = new URL(request.url);
    const pathname = url.pathname;
    const host = request.headers.get("host") || "";
    const sub = getSubdomain(host);
    const envSiteUrl: string = env.SITE_URL || "";
    const isLocal = envSiteUrl.startsWith("http://localhost");
    if (isLocal) cacheEnabled = false; // Cache API unavailable in local workerd

    // ── /health liveness probe ──
    // Host-agnostic, no auth, no DO access. Cloister + container orchestrators
    // (cluster.capnp notme-identity bundle) poll this on :8788/health.
    // GET /.well-known/version — which BUILD is serving this request
    // (notme-9f2f79, and signet's "no positive evidence" objection).
    //
    // Deploys here are manual, so the git tree does not settle what is
    // running. Before this, a consumer waiting on a fix had no way to confirm
    // it shipped except to ask, and "there is no positive evidence" was a fair
    // description. `/health` says `ok`; nothing else served was derived from
    // the build.
    //
    // It is also the discriminator ADR-018's canary gate needs. That gate
    // failed twice by silently reporting the OLD version's behaviour, and an
    // earlier attempt used the JWKS `kid` — which cannot work, because `kid`
    // is stored Durable Object state rather than something the build
    // determines, so two different builds serve the same value.
    //
    // Unauthenticated and uncached, like /health: the commit of a public repo
    // is not a secret, and a cached answer would defeat the entire purpose on
    // the request after a deploy.
    //
    // Answered before host canonicalization for the same reason as /health —
    // probes from bare-IP or in-cluster hosts must get an answer, not a 301.
    if (pathname === "/.well-known/version") {
      return Response.json(buildInfo(env), {
        status: 200,
        headers: {
          "Cache-Control": "no-store",
          "Access-Control-Allow-Origin": "*",
        },
      });
    }

    // Must respond before any host-canonicalization redirect so probes from
    // bare-IP / pod-IP / docker bridge hosts get a 200 instead of a 301.
    if (pathname === "/health" || pathname === "/healthz") {
      return new Response("ok", {
        status: 200,
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Cache-Control": "no-store",
        },
      });
    }

    const { createPlatform } = await import("./src/platform");
    const platform = createPlatform(env);

    // Internal service-binding route used by cloister to fetch Signet's signed
    // JSON CABundle. Host-agnostic by design: service bindings commonly use
    // synthetic hostnames such as https://notme-bot/.
    if (pathname === "/internal/ca-bundle") {
      return handleInternalCABundle(request, env, platform);
    }

    // Receipt signing is NOT an HTTP path (ADR-014). Refused explicitly rather
    // than left absent, for two reasons: notme-c1b7fd originally specified
    // this wire shape, so a caller built against that bead needs to be told
    // where it went; and an unhandled /internal/* path falls through to the
    // asset handler, which would answer a signing request with a 404 page and
    // no explanation.
    //
    // The route above is the cautionary tale — /internal/ is NOT a private
    // namespace. It is registered before host enforcement and answers from the
    // public internet. Harmless for a public CA bundle; a signing oracle on
    // the CA master key if copied. Hence RPC.
    if (pathname === "/internal/sign-jwt") {
      return Response.json(
        {
          error: "not_an_http_endpoint",
          error_description:
            'Delegated JWT signing is an RPC method, not a route, and signs with a DELEGATED key rather than the CA master (ADR-015). Add a dedicated binding — ( name = "NOTME_JWT", service = "notme-bot", entrypoint = "JwtSigner" ) — and call env.NOTME_JWT.signJwt({issuer, headerB64, payloadB64}). See docs/design/015-delegated-jwt-signing.md.',
        },
        { status: 404 },
      );
    }

    // The binding named here MUST be a dedicated one. This string used to say
    // `entrypoint = "ReceiptSigner"` on the NOTME binding and `env.NOTME.
    // signReceipt(...)` — the instruction ADR-014 retracted by name, because
    // setting `entrypoint` on a binding already used as a fetch proxy
    // silently routes that binding's fetch() to a class with no fetch
    // handler, breaking the integrator's existing /identity/* traffic
    // (ADR-016 rule 2). The correction reached the ADR and the ReceiptSigner
    // docstring; it never reached the string an integrator actually reads,
    // which is the only one of the three they ever see. notme-bd133e.
    if (pathname === "/internal/sign-receipt") {
      return Response.json(
        {
          error: "not_an_http_endpoint",
          error_description:
            'Receipt signing is an RPC method, not a route. Add a dedicated binding — ( name = "NOTME_RECEIPTS", service = "notme-bot", entrypoint = "ReceiptSigner" ) — and call env.NOTME_RECEIPTS.signReceipt(commitmentBytes). Do NOT add entrypoint to an existing NOTME binding: that reroutes its fetch() to a class with no fetch handler (ADR-016 rule 2). See docs/design/014-receipt-signing.md.',
        },
        { status: 404 },
      );
    }

    // ── Canonical host enforcement ──
    // Redirect a host this deployment does not serve (e.g. workers.dev) to its
    // canonical site. This prevents Google from indexing the workers.dev URL
    // as a duplicate.
    //
    // DERIVED, not the literal "notme.bot" it used to test. The old rule was
    // `!host.endsWith("notme.bot")`, which 301'd EVERY request of any
    // deployment not under that registrable domain — a self-hosted authority
    // at id.example.com answered nothing but redirects TO notme.bot, and the
    // env-derived host selection that ADR-018 and notme-1532eb added below
    // could never be reached to do its job. Found by a staging-impersonation
    // test that minted under a third domain (notme-1532eb).
    //
    // Both the site host and the authority host are legitimate, and they
    // differ (notme.bot vs auth.notme.bot). Subdomains of the site host stay
    // allowed, which is what `endsWith` was expressing for production.
    const canonicalHost = siteHostFromEnv(env.SITE_URL);
    const authorityHostForCanon = authorityHostFromEnv(env.SIGNET_AUTHORITY_URL);
    const hostIsServed =
      host === canonicalHost ||
      host.endsWith(`.${canonicalHost}`) ||
      (authorityHostForCanon !== null && host === authorityHostForCanon);
    if (!isLocal && !hostIsServed && host !== "") {
      const canonicalUrl = `https://${canonicalHost}${pathname}${url.search}`;
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
    // Also matched by SIGNET_AUTHORITY_URL's host, so non-production
    // environments (auth-staging.notme.bot) select the authority surface
    // without a code change. In production the var names auth.notme.bot,
    // which sub === "auth" already matches — no behavior change.
    const authorityHost = authorityHostFromEnv(env.SIGNET_AUTHORITY_URL);
    if (sub === "auth" || isLocal || (authorityHost !== null && host === authorityHost)) {
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
          return Response.redirect(`${authorityUrl}/login`, 302);
        }
        const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
        const authority = env.SIGNING_AUTHORITY.get(authorityId);
        const { verifySessionCookie } = await import("./src/auth/session");
        const sessionSecret = await authority.getSessionSecret();
        const session = await verifySessionCookie(cookie, sessionSecret);
        if (!session) {
          return Response.redirect(`${authorityUrl}/login`, 302);
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
        const resp = await env.ASSETS.fetch(
          new Request(`${baseUrl}/_api-docs`),
        );
        const headers = new Headers(resp.headers);
        headers.set("Cache-Control", "public, max-age=3600");
        // The asset hardcodes the production authority host. On any other
        // environment (staging), rewrite it so the docs describe the host
        // actually serving them — worker:verify treats a production URL
        // rendered on staging as a config leak.
        let body: BodyInit | null = resp.body;
        if (
          resp.ok &&
          authorityHost !== null &&
          authorityHost !== "auth.notme.bot"
        ) {
          const html = await resp.text();
          body = html.replaceAll("auth.notme.bot", authorityHost);
          // Stale after rewriting: length changed, and text() already
          // decoded any content-encoding.
          headers.delete("Content-Length");
          headers.delete("Content-Encoding");
        }
        const result = new Response(body, {
          status: resp.status,
          statusText: resp.statusText,
          headers,
        });
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
          proof: { type: string; token?: string; cert?: string; chain?: unknown };
        };
        if (!body.proof?.type) return jsonErr("proof.type required", 400);

        // Narrow the request body to the Proof discriminated union before
        // handing off to verifyProof — keeps the unsafe cast at the trust
        // boundary (request input) rather than scattered through the call.
        const { verifyProof } = await import("./src/auth/verify-proof");
        type Proof =
          | { type: "oidc"; token: string }
          | { type: "x509"; cert: string; chain?: string[] };
        let typedProof: Proof;
        if (
          body.proof.type === "oidc" &&
          typeof body.proof.token === "string"
        ) {
          typedProof = { type: "oidc", token: body.proof.token };
        } else if (
          body.proof.type === "x509" &&
          typeof body.proof.cert === "string"
        ) {
          // Optional intermediates: a cert signed by an Issuing CA tier
          // (ADR-019 D4) verifies through the chain walker, which enforces
          // pathlen, scope subsetting and the D5 namespace bound. Filtered
          // to strings so a malformed array member fails as a bad chain,
          // never as a type surprise deeper in.
          const chain = Array.isArray(body.proof.chain)
            ? body.proof.chain.filter((c: unknown): c is string => typeof c === "string")
            : undefined;
          typedProof = { type: "x509", cert: body.proof.cert, chain };
        } else {
          return jsonErr(`unsupported proof.type: ${body.proof.type}`, 400);
        }

        let identity;
        try {
          // verifyX509 (in the typedProof.type === "x509" branch) parses
          // this argument as an X.509 CERTIFICATE PEM and reads its public
          // key. The earlier code passed `getPublicKeyPem()` which returns
          // the bare SPKI ("PUBLIC KEY" PEM) — that throws inside
          // `new X509Certificate(...)`, so every X.509 connection attempt
          // returned 401 "proof verification failed". Use the actual CA
          // CERTIFICATE PEM (rosary-9b7d67).
          const caCertPem = await authority.getCACertificatePem();
          // Audience pin matches /auth/oidc/login + /join: prevents linking a
          // stolen OIDC token issued for a different app, which would silently
          // re-route the victim's later notme.bot OIDC login into the
          // attacker's principal. X.509 path ignores the audience arg.
          // The authority's CURRENT epoch, so a cert issued before a
          // rotation is refused. Read from the DO rather than cached: a
          // rotation that took effect between requests must take effect
          // HERE, which is the whole point of the lever (notme-77a024).
          const { epoch: currentEpoch } = await authority.getReceiptFacts();
          identity = await verifyProof(
            typedProof,
            caCertPem,
            "notme.bot",
            currentEpoch,
          );
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

      // GET  /admin/alarm-health        — is the bundle-refresh alarm alive?
      // POST /admin/alarm-health/reset  — clear the circuit breaker, re-arm
      //
      // The alarm republishes the CA bundle every BUNDLE_REFRESH_MS. It has a
      // circuit breaker that stops re-arming after repeated failures, and
      // recovery requires resetAlarmHealth() — which was an RPC method with NO
      // ROUTE, so the documented recovery procedure could not be invoked at
      // all. Production ran with a dead alarm for 130 days and served a bundle
      // every conformant consumer rejected (notme-77a024).
      //
      // authorityManage-gated, not public: alarm health leaks operational
      // state (how long the authority has been running, whether it is
      // failing), and reset re-arms a timer on the DO holding the CA key.
      if (pathname === "/admin/alarm-health" || pathname === "/admin/alarm-health/reset") {
        const isReset = pathname.endsWith("/reset");
        // AUTH BEFORE METHOD, deliberately. Answering 405 first tells an
        // unauthenticated caller the path exists — a free confirmation that
        // this authority has an admin surface, on the object holding the CA
        // key. Every rejection an anonymous caller can reach is a 401.
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
        // LIVE against the grant store — a revoked grant shuts this door on
        // the next request, not when the cookie expires (notme-77a024).
        const { liveScopes } = await import("./src/auth/session");
        if (!(await liveScopes(session, authority)).includes("authorityManage")) {
          return jsonErr("authorityManage scope required", 403);
        }
        // Method check now that the caller is known to be an admin.
        if (request.method !== (isReset ? "POST" : "GET")) {
          return jsonErr("method not allowed", 405);
        }

        if (isReset) {
          const result = await authority.resetAlarmHealth();
          // Return health ALONGSIDE the reset result. An operator who resets
          // needs to see the outcome without a second call — and `rearmed`
          // is the field that matters: clearing the counter without re-arming
          // looks like recovery while the bundle goes on rotting.
          return Response.json({
            ...result,
            health: await authority.getAlarmHealth(),
          });
        }
        return Response.json(await authority.getAlarmHealth());
      }

      // POST /admin/revoke-epoch — pull the mass-revocation lever
      //
      // `revokeEpoch()` advances the revocation generation and republishes
      // the CA bundle synchronously. Per ADR-019 D7 it is the ONLY mass
      // revocation notme has, and D7's whole subject was that the previous
      // mechanism "could not be operated" because revoking cost the signing
      // key and destroyed the evidence for every past receipt.
      //
      // It then shipped as an RPC method with NO ROUTE — the same defect, in
      // the same bead, that left resetAlarmHealth() uninvocable while
      // production served a rejected bundle for 130 days (see above). Fixing
      // the mechanism and leaving it unreachable is not fixing it.
      //
      // authorityManage-gated and POST-only: this invalidates every
      // outstanding credential of the current generation, so reachable
      // unauthenticated it is a denial-of-service primitive against the whole
      // authority. Gating is pinned by admin-revoke-epoch-route.do.test.ts.
      if (pathname === "/admin/revoke-epoch") {
        // AUTH BEFORE METHOD, same reason as /admin/alarm-health: answering
        // 405 first would confirm to an anonymous caller that this authority
        // exposes a mass-revocation endpoint.
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
        // LIVE against the grant store, so a revoked grant shuts this door on
        // the next request rather than when the cookie expires.
        const { liveScopes } = await import("./src/auth/session");
        if (!(await liveScopes(session, authority)).includes("authorityManage")) {
          return jsonErr("authorityManage scope required", 403);
        }
        if (request.method !== "POST") {
          return jsonErr("method not allowed", 405);
        }
        const result = await authority.revokeEpoch();
        // Dynamic import to match this file's idiom — the constant is only
        // needed on the one request that pulls the lever.
        const { BUNDLE_MAX_AGE_MS } = await import("./src/revocation");
        // Return the propagation bound with the result. An operator who pulls
        // this needs to know WHEN it takes effect, and the honest answer is
        // bounded only for verifiers that can reach the bundle — one
        // BUNDLE_MAX_AGE_MS refresh. A verifier that cannot has TTL and
        // nothing else (ADR-019 D7).
        return Response.json({
          ...result,
          propagation: {
            boundMs: BUNDLE_MAX_AGE_MS,
            note: "Verifiers that can reach the CA bundle enforce the new generation within one refresh. Offline verifiers have TTL only.",
          },
        });
      }

      // POST /invites — create an invite (requires authorityManage scope)
      // GET /invites — the form. authorityManage-gated BEFORE the asset is
      // served, so an unprivileged caller never sees it.
      //
      // POST /invites was API-only, so the only way to grant anyone authority
      // was a fetch() pasted into a devtools console. In practice that means
      // nobody does it — and an authority with one admin credential is one
      // lost laptop from ungovernable (notme-4838ae, found live). Recovery
      // exists now via BOOTSTRAP_CODE, but prevention that requires devtools
      // is not prevention.
      if ((pathname === "/invites" || pathname === "/invites/") && request.method === "GET") {
        const cookie = parseCookie(
          request.headers.get("cookie") || "",
          "notme_session",
        );
        if (!cookie) return jsonErr("sign in first", 401);
        const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
        const authority = env.SIGNING_AUTHORITY.get(authorityId);
        const { verifySessionCookie } = await import("./src/auth/session");
        const session = await verifySessionCookie(
          cookie,
          await authority.getSessionSecret(),
        );
        if (!session) return jsonErr("invalid session", 401);
        const { liveScopes } = await import("./src/auth/session");
        if (!(await liveScopes(session, authority)).includes("authorityManage")) {
          return jsonErr("authorityManage scope required", 403);
        }
        const baseUrl = env.SITE_URL || "https://notme.bot";
        return env.ASSETS.fetch(new Request(`${baseUrl}/_invite`));
      }

      if (pathname === "/invites" && request.method === "POST") {
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
        // LIVE scopes feed BOTH the gate and canGrant below: a granter whose
        // own authority was revoked must not be able to pass it on from a
        // cookie that still remembers it (notme-77a024).
        const { liveScopes } = await import("./src/auth/session");
        const granterScopes = await liveScopes(session, authority);
        if (!granterScopes.includes("authorityManage")) {
          return jsonErr("authorityManage scope required", 403);
        }

        const body = (await request.json()) as {
          scopes?: string[];
          ttl?: number;
        };
        const scopes = body.scopes ?? ["bridgeCert"];
        // Delegated authorization — granter must hold authorityManage AND
        // the specific scope being granted. canGrant() is the single source
        // of truth for the predicate (was duplicated inline pre-rosary-8119d0).
        const { canGrant } = await import("./src/auth/principals");
        for (const s of scopes) {
          if (!canGrant(granterScopes, s)) {
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

      // POST /principals/:id/revoke — revoke one grant (notme-77a024).
      //
      // The revocation UNIT, finally: finer than rotation (every credential
      // ever issued), a decision rather than expiry. Takes effect on the
      // target's next request because every authority gate reads liveScopes.
      //
      // Self-revocation of authorityManage is refused: an authority whose
      // last admin revoked themselves is ungovernable again (notme-4838ae),
      // and BOOTSTRAP_CODE recovery should be the deliberate path, not the
      // consequence of a mis-click.
      {
        const m = /^\/principals\/([^/]+)\/revoke$/.exec(pathname);
        if (m && request.method === "POST") {
          const cookie = parseCookie(
            request.headers.get("cookie") || "",
            "notme_session",
          );
          if (!cookie) return jsonErr("sign in first", 401);
          const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
          const authority = env.SIGNING_AUTHORITY.get(authorityId);
          const { verifySessionCookie, liveScopes } = await import(
            "./src/auth/session"
          );
          const session = await verifySessionCookie(
            cookie,
            await authority.getSessionSecret(),
          );
          if (!session) return jsonErr("invalid session", 401);
          if (!(await liveScopes(session, authority)).includes("authorityManage")) {
            return jsonErr("authorityManage scope required", 403);
          }
          const target = decodeURIComponent(m[1]!);
          let body: { scope?: string } = {};
          try {
            body = (await request.json()) as typeof body;
          } catch {
            /* empty body */
          }
          if (!body.scope) return jsonErr("scope required", 400);
          if (target === session.principalId && body.scope === "authorityManage") {
            return jsonErr(
              "refusing to revoke your own authorityManage — invite a second admin first",
              409,
            );
          }
          const result = await authority.revokeCapability(
            target,
            body.scope,
            session.principalId,
          );
          console.log(
            `[revoke] principal=${target} scope=${body.scope} by=${session.principalId} revoked=${result.revoked}`,
          );
          return Response.json({
            revoked: result.revoked,
            principal_id: target,
            scope: body.scope,
          });
        }
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
        const result = await authority.redeemInviteToken(
          body.token,
          principalId,
        );
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

      // Passkey reset — temporary, for fixing corrupted credential data.
      // Requires the bootstrap code (proves deployer ownership).
      //
      // consumeBootstrapCode atomically validates and marks the code used —
      // gives us constant-time compare (timing-safe.ts HMAC equality) AND
      // single-use semantics in one call. A second /reset with the same code
      // returns false and we 403, so a leaked code can't be used to repeatedly
      // wipe credentials.
      if (pathname === "/auth/passkey/reset" && request.method === "POST") {
        try {
          const body = (await request.json()) as { bootstrapCode?: string };
          const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
          const authority = env.SIGNING_AUTHORITY.get(authorityId);
          if (
            !body.bootstrapCode ||
            !(await authority.consumeBootstrapCode(body.bootstrapCode))
          ) {
            // Generic error — don't leak whether code was wrong vs already consumed.
            return jsonErr("invalid or expired bootstrap code", 403);
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
        const statusCookie = parseCookie(
          request.headers.get("cookie") || "",
          "notme_session",
        );
        if (!statusCookie) return jsonErr("unauthorized", 401);
        const statusSecret = await authDO.getSessionSecret();
        const statusSession = await verifySessionCookie(
          statusCookie,
          statusSecret,
        );
        if (!statusSession) return jsonErr("admin required", 403);
        {
          const { liveScopes } = await import("./src/auth/session");
          if (!(await liveScopes(statusSession, authDO)).includes("authorityManage")) {
            return jsonErr("admin required", 403);
          }
        }
        try {
          const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
          const authority = env.SIGNING_AUTHORITY.get(authorityId);
          const state = await authority.getAuthorityState();
          // Count users and credentials via a simple RPC (need to add this)
          const passkey = await authority.passkeyStats();
          return Response.json({
            authority: {
              epoch: state.epoch,
              seqno: state.seqno,
              keyId: state.keyId,
            },
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
        return handleCertExchange(request, env, platform);
      }

      // POST /cert/passkey — authenticated session → bridge cert pair.
      //
      // Named for its primary caller, but it accepts ANY valid session —
      // passkey, invite (/join), or OIDC (/auth/oidc/login) — and the minted
      // cert's authMethod + wimse identity are DERIVED from the session's
      // authMethod, so the cert never claims an authenticator the session
      // didn't use (notme-ebc9af).
      //
      // The passkey analogue of /cert/gha, and near-identical to it: verify an
      // authenticator, prove possession of the submitted keys, mint the pair.
      // The authenticator differs, and so does one thing that matters.
      //
      // /cert/gha hardcodes scopes:["bridgeCert"] because a GitHub OIDC token
      // carries no privilege to inherit. A passkey session DOES — the deployer's
      // carries authorityManage and certMint — so this INTERSECTS the session's
      // scopes with an allowlist rather than passing them through. A cert that
      // silently inherited certMint would turn a browser session into a minting
      // credential, valid for its whole lifetime, usable from anywhere, with
      // none of the properties that made the session acceptable (HttpOnly,
      // SameSite=Strict, revocable by clearing a cookie). See
      // src/auth/passkey-cert-scopes.ts.
      //
      // Why a passkey is the right authenticator for this: the human step that
      // legitimately remains here is an AUTHORIZATION GRANT, and a passkey is
      // what a grant should cost — a human present, one touch, unphishable,
      // nothing transcribed. It also works on a phone, where a filesystem, a
      // keychain helper and the signet binary all do not.
      // POST /cert/nonce — the session term for a cert-pair binding
      // (notme-486e8a). Same-origin; the HttpOnly cookie is sent
      // automatically, so the browser never needs to read it.
      if (pathname === "/cert/nonce" && request.method === "POST") {
        const cookie = parseCookie(request.headers.get("cookie") || "", "notme_session");
        if (!cookie) return jsonErr("session_required", 401);
        const authority = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
        const { verifySessionCookie } = await import("./src/auth/session");
        const session = await verifySessionCookie(cookie, await authority.getSessionSecret());
        if (!session) return jsonErr("invalid_session", 401);
        const { nonce, expiresIn } = await authority.issuePopNonce(session.principalId);
        return Response.json({ nonce, expires_in: expiresIn }, { headers: { "Cache-Control": "no-store" } });
      }

      if (pathname === "/cert/passkey" && request.method === "POST") {
        try {
          const cookie = parseCookie(
            request.headers.get("cookie") || "",
            "notme_session",
          );
          if (!cookie) {
            return Response.json(
              { error: "session_required" },
              { status: 401 },
            );
          }

          let body: {
            nonce?: string;
            public_keys?: { mtls?: string; signing?: string };
            proofs?: { mtls?: string; signing?: string };
          } = {};
          try {
            body = (await request.json()) as typeof body;
          } catch {
            /* empty body */
          }
          if (typeof body.nonce !== "string" || !body.nonce) {
            return jsonErr("nonce required — POST /cert/nonce first (notme-486e8a)", 400);
          }
          if (!body.public_keys?.mtls || !body.public_keys?.signing) {
            return jsonErr(
              "public_keys.mtls and public_keys.signing required (SPKI PEM)",
              400,
            );
          }
          if (!body.proofs?.mtls || !body.proofs?.signing) {
            return jsonErr(
              "proofs.mtls and proofs.signing required (signatures over the binding payload)",
              400,
            );
          }

          const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
          const authority = env.SIGNING_AUTHORITY.get(authorityId);
          const { verifySessionCookie } = await import("./src/auth/session");
          const sessionSecret = await authority.getSessionSecret();
          const session = await verifySessionCookie(cookie, sessionSecret);
          if (!session) {
            return Response.json({ error: "invalid_session" }, { status: 401 });
          }

          const { importPublicKey } = await import("./src/cert-authority");
          let mtlsPubKey: CryptoKey;
          let signingPubKey: CryptoKey;
          try {
            mtlsPubKey = await importPublicKey(body.public_keys.mtls);
            signingPubKey = await importPublicKey(body.public_keys.signing);
          } catch (e: any) {
            return jsonErr("invalid public key: " + e.message, 400);
          }

          // Binding = SHA-256(mtls_spki || signing_spki || SHA-256(session
          // cookie)). The session term is what stops a captured
          // public-keys+proofs pair being replayed under a DIFFERENT session:
          // without it the proofs are a function of the keys alone, so anyone
          // holding a valid session could submit a victim's captured pair and
          // bind the victim's key to their own identity. /cert/gha binds the
          // OIDC token for exactly this reason; the session cookie is this
          // route's equivalent single-use-ish secret.
          const mtlsSpki = (await crypto.subtle.exportKey(
            "spki",
            mtlsPubKey,
          )) as ArrayBuffer;
          const signingSpki = (await crypto.subtle.exportKey(
            "spki",
            signingPubKey,
          )) as ArrayBuffer;
          // The session term is a server-issued nonce, not SHA-256 of the
          // cookie: the cookie is HttpOnly, so no browser could ever compute
          // that, and this route was uncallable (notme-486e8a).
          const { certPairBinding } = await import("./src/auth/cert-pair-binding");
          const bindingInput = await certPairBinding(
            new Uint8Array(mtlsSpki),
            new Uint8Array(signingSpki),
            body.nonce,
          );
          // PoP over the binding PRE-IMAGE — never its digest (notme-a011d2).
          const pop = await verifyPopProofs(
            bindingInput,
            mtlsPubKey,
            signingPubKey,
            body.proofs,
          );
          if (!pop.ok) {
            return jsonErr(`${pop.algorithm} proof-of-possession failed`, 401);
          }
          // Spend the nonce only AFTER the proofs verify, so a forged request
          // cannot burn the real holder's nonce. Bound to THIS principal: a
          // nonce issued to another session does not match — which is what
          // defeats replaying a captured keys+proofs pair under it.
          if (!(await authority.consumePopNonce(body.nonce, session.principalId))) {
            return Response.json({ error: "invalid_nonce" }, { status: 401 });
          }

          // LIVE grants, not the cookie's copy (notme-486e8a).
          const { liveScopes } = await import("./src/auth/session");
          const { certScopesForSession } =
            await import("./src/auth/passkey-cert-scopes");
          const scopes = certScopesForSession(await liveScopes(session, authority));
          if (scopes.length === 0) {
            // The session holds nothing a cert may carry. Refuse rather than
            // mint an authority-less cert, which would look like success and
            // fail confusingly at first use.
            return jsonErr(
              "session holds no cert-eligible scopes (need bridgeCert)",
              403,
            );
          }

          // Provenance is DERIVED from the session, never asserted by the
          // route: /join sets authMethod "invite" and /auth/oidc/login sets
          // "oidc:<issuer>", and this route accepts those sessions — so a
          // hardcoded "passkey" told verifiers a human touched an
          // authenticator when none did (notme-ebc9af). encodeURIComponent
          // keeps an issuer-qualified method one URI path segment.
          //
          // Validated, not defaulted. verifySessionCookie JSON.parses its
          // payload with no shape check, so a future issuer that omits
          // authMethod would otherwise reach the mint as undefined —
          // stamping the literal "undefined" into a certificate's identity
          // and extension. Defaulting to "passkey" would be worse: it
          // re-creates the exact lie notme-ebc9af fixed. A cert that cannot
          // state its provenance honestly must not be minted.
          const sessionAuthMethod = session.authMethod;
          if (
            typeof sessionAuthMethod !== "string" ||
            sessionAuthMethod.length === 0
          ) {
            return jsonErr("session carries no authMethod", 401);
          }
          const result = await authority.mintBridgeCertPair({
            subject: session.principalId,
            identity: principalIdentity(wimseTrustDomain(env), session.principalId),
            mtlsPublicKeyPem: body.public_keys.mtls,
            signingPublicKeyPem: body.public_keys.signing,
            scopes,
            authMethod: sessionAuthMethod,
            ttlMs: 5 * 60 * 1000,
          });

          // Spread the mint result rather than rebuilding it field by field.
          // The first version of this reconstructed `certificates` from
          // `result.mtlsCertPem` / `result.signingCertPem`, which do not exist —
          // BridgeCertPairResult already carries `certificates`, `identity`,
          // `scopes`, `expires_at`, `subject` and `binding`. tsc did not catch
          // it because the DO stub is loosely typed, so it would have shipped a
          // 200 with `certificates.mtls: undefined`. Spreading keeps this
          // response shape tied to the mint's, so the two cannot drift.
          return Response.json({
            ...result,
            principal_id: session.principalId,
            auth_method: sessionAuthMethod,
          });
        } catch (e: any) {
          return jsonErr("passkey cert error: " + e.message, 500);
        }
      }

      // POST /cert/issuing-ca — mint the MIDDLE tier (ADR-019 D4).
      //
      // The Issuing CA: CA=true so the holder signs task certs itself,
      // offline, without asking this authority per task; pathlen=0 so every
      // task cert is terminal. This is hop 1 of the delegation chain
      // (human→machine); hop 2 (machine→task) happens client-side, which is
      // the point of issuing a CA tier at all.
      //
      // Gated on certMint — this route is the scope's FIRST enforcement site.
      // authorityManage deliberately does not suffice: administering the
      // authority and minting delegation tiers are different powers, and
      // bootstrap grants both precisely so they can diverge later.
      //
      // Scope narrowing is the leaf rule, applied harder: the tier's scopes
      // bound every task cert below it (chain rule, auth/scope-chain.ts), and
      // the artifact is long-lived and exportable — so requested scopes pass
      // narrowScopes(session, requested) then CERT_ELIGIBLE_SCOPES, same as
      // /cert and /cert/passkey. certMint itself is never carried.
      // ── Tier enrolment by device authorization (notme-486e8a) ─────────
      //
      // The way a MACHINE gets a delegation tier. /cert/issuing-ca below binds
      // its proof to SHA-256 of the HttpOnly session cookie, which no client
      // can read — so it was never callable and a tier was never enrollable.
      // Here the machine holds the key and the device code, and the human
      // approves a short user code in a passkey session after comparing the
      // key fingerprint shown on both screens (RFC 8628 shape).

      // POST /cert/issuing-ca/device — machine starts. Unauthenticated by
      // nature; it grants nothing until a human approves.
      if (pathname === "/cert/issuing-ca/device" && request.method === "POST") {
        let body: { public_key?: unknown; scopes?: unknown } = {};
        try {
          body = (await request.json()) as typeof body;
        } catch {
          /* empty body */
        }
        if (typeof body.public_key !== "string" || !body.public_key) {
          return jsonErr("public_key required (Ed25519 SPKI PEM)", 400);
        }
        const requested =
          Array.isArray(body.scopes) && body.scopes.every((x) => typeof x === "string")
            ? (body.scopes as string[])
            : ["bridgeCert"];
        const authority = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
        const r = await authority.startTierEnrolment({
          publicKeyPem: body.public_key,
          requestedScopes: requested,
        });
        if (!r.ok) {
          return r.reason === "busy"
            ? jsonErr("too many pending enrolments — retry shortly", 503)
            : jsonErr("public_key must be an Ed25519 SPKI PEM", 400);
        }
        const origin = new URL(request.url).origin;
        return Response.json({
          device_code: r.deviceCode,
          user_code: r.userCode,
          verification_uri: `${origin}/enroll?code=${r.userCode}`,
          key_fingerprint: r.keyFingerprint,
          expires_in: r.expiresIn,
          interval: 5,
        });
      }

      // GET /enroll?code=XXXX-XXXX — the human's approval page. `/enrol`
      // (the first spelling, which shipped in a live URL) stays an alias.
      if ((pathname === "/enroll" || pathname === "/enrol") && request.method === "GET") {
        const code = (new URL(request.url).searchParams.get("code") || "").toUpperCase();
        const cookie = parseCookie(request.headers.get("cookie") || "", "notme_session");
        const authority = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
        const { verifySessionCookie } = await import("./src/auth/session");
        const session = cookie
          ? await verifySessionCookie(cookie, await authority.getSessionSecret())
          : null;
        if (!session) {
          return Response.redirect(
            // The AUTHORITY's /login, not SITE_URL's (notme-486e8a): the
            // passkey ceremony and the session cookie live on this host.
            // Every login redirect here used SITE_URL — in production
            // https://notme.bot/login, a 404.
            `${authorityUrl}/login?return_to=${encodeURIComponent(`/enroll?code=${code}`)}`,
            302,
          );
        }
        if (!/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/.test(code)) {
          return jsonErr("malformed enrolment code", 400);
        }
        const e = await authority.getTierEnrolment(code);
        if (!e) return jsonErr("no such enrolment — it may have expired", 404);
        return new Response(enrolPageHtml(code, e.keyFingerprint, e.requestedScopes, e.status), {
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
            "X-Frame-Options": "DENY",
          },
        });
      }

      // POST /cert/issuing-ca/device/approve — the human approves. Same-origin
      // with a SameSite=Strict session, so a cross-site page cannot submit it.
      if (pathname === "/cert/issuing-ca/device/approve" && request.method === "POST") {
        const cookie = parseCookie(request.headers.get("cookie") || "", "notme_session");
        if (!cookie) return jsonErr("session_required", 401);
        const authority = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
        const { verifySessionCookie, liveScopes } = await import("./src/auth/session");
        const session = await verifySessionCookie(cookie, await authority.getSessionSecret());
        if (!session) return jsonErr("invalid_session", 401);
        // LIVE grants, not the cookie's copy: a revoked certMint stops
        // working now, not when the cookie expires.
        const live = await liveScopes(session, authority);
        if (!live.includes("certMint")) return jsonErr("certMint scope required", 403);
        if (typeof session.authMethod !== "string" || !session.authMethod) {
          return jsonErr("session carries no authMethod", 401);
        }
        let body: { user_code?: unknown; renew_days?: unknown; clone_policy?: unknown } = {};
        try {
          body = (await request.json()) as typeof body;
        } catch {
          /* empty body */
        }
        const userCode = typeof body.user_code === "string" ? body.user_code.toUpperCase() : "";
        // The renewal horizon (notme-337d82): how long this machine may renew
        // its tier WITHOUT a human — so a VM that pauses and resumes is not
        // blocked on a person for an action already approved. A fixed menu,
        // default 7 days (survives a weekend pause); not a free number.
        const renewDays = body.renew_days === undefined ? 7 : body.renew_days;
        if (renewDays !== 1 && renewDays !== 7 && renewDays !== 30) {
          return jsonErr("renew_days must be 1, 7 or 30", 400);
        }
        // Clone policy (notme-747cc7): singleton unless the approver, holding
        // LIVE authorityManage, says otherwise. Phase 1 only records it.
        const clonePolicy = body.clone_policy === undefined ? "singleton" : body.clone_policy;
        if (
          clonePolicy !== "singleton" &&
          clonePolicy !== "replicas:2" &&
          clonePolicy !== "replicas:4" &&
          clonePolicy !== "replicas:8"
        ) {
          return jsonErr("clone_policy must be singleton, replicas:2, replicas:4 or replicas:8", 400);
        }
        if (clonePolicy !== "singleton") {
          if (!live.includes("authorityManage")) return jsonErr("replicas requires authorityManage", 403);
          if (renewDays === 30) return jsonErr("replicas allows a renewal horizon of at most 7 days", 400);
        }
        const pending = await authority.getTierEnrolment(userCode);
        if (!pending) return jsonErr("no such enrolment", 404);
        const { narrowScopes } = await import("./src/auth/scope-chain");
        const { certScopesForSession } = await import("./src/auth/passkey-cert-scopes");
        // The tier is exportable and long-lived relative to a session, so it
        // carries only what is safe to export — never certMint itself.
        const scopes = certScopesForSession(narrowScopes(live, pending.requestedScopes));
        if (scopes.length === 0) {
          return jsonErr("no requested scope is cert-eligible and held (need bridgeCert)", 403);
        }
        const r = await authority.approveTierEnrolment({
          userCode,
          principalId: session.principalId,
          identity: principalIdentity(wimseTrustDomain(env), session.principalId),
          authMethod: session.authMethod,
          scopes,
          renewDays,
          clonePolicy,
        });
        if (!r.ok) {
          return jsonErr(
            r.reason === "expired" ? "enrolment expired" : r.reason === "not_found" ? "no such enrolment" : "enrolment already decided",
            r.reason === "not_found" ? 404 : 409,
          );
        }
        return Response.json({ ok: true, scopes, clone_policy: clonePolicy });
      }

      // POST /cert/issuing-ca/device/token — the machine collects. Error
      // names are RFC 8628 §3.5's, so a generic device-flow client can poll.
      if (pathname === "/cert/issuing-ca/device/token" && request.method === "POST") {
        let body: { device_code?: unknown; proof?: unknown } = {};
        try {
          body = (await request.json()) as typeof body;
        } catch {
          /* empty body */
        }
        const authority = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
        const r = await authority.collectTierEnrolment({
          deviceCode: typeof body.device_code === "string" ? body.device_code : "",
          proof: typeof body.proof === "string" ? body.proof : "",
        });
        if (!r.ok) {
          return Response.json(
            { error: r.reason === "invalid_proof" ? "invalid_proof" : r.reason },
            { status: r.reason === "invalid_proof" ? 401 : 400 },
          );
        }
        const { ok: _ok, principalId, authMethod, renewUntil, generation, ...tier } = r;
        return Response.json({
          ...tier,
          principal_id: principalId,
          auth_method: authMethod,
          renew_until: renewUntil,
          generation,
        });
      }

      // POST /cert/issuing-ca/renew — a machine renews its tier with no
      // human, while the approval holds (notme-337d82). Body
      // { public_key, iat, proof }; proof = Ed25519 over
      // "notme/tier-renew/v1\0" || SPKI || uint64be(iat). v2 adds
      // `generation` and signs "notme/tier-renew/v2\0" || SPKI ||
      // uint64be(iat) || uint64be(generation); success returns the
      // generation to sign next, and a copied key renewing is a 403
      // fork_detected (notme-747cc7). Unauthenticated BY
      // DESIGN: the proof of possession is the authentication, and the result
      // is a public certificate for a key only the renewer holds.
      if (pathname === "/cert/issuing-ca/renew" && request.method === "POST") {
        let body: { public_key?: unknown; iat?: unknown; proof?: unknown; generation?: unknown } = {};
        try {
          body = (await request.json()) as typeof body;
        } catch {
          /* empty body */
        }
        const authority = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
        const r = await authority.renewTier({
          publicKeyPem: typeof body.public_key === "string" ? body.public_key : "",
          iat: typeof body.iat === "number" ? body.iat : NaN,
          proof: typeof body.proof === "string" ? body.proof : "",
          // v2 (notme-747cc7): a generation in the body selects the v2
          // binding; without one the request is v1.
          ...(typeof body.generation === "number" ? { generation: body.generation } : {}),
        });
        if (!r.ok) {
          const status =
            r.reason === "unknown_key" ? 404
            : r.reason === "invalid_key" ? 400
            : r.reason === "stale_proof" || r.reason === "invalid_proof" ? 401
            : 403;
          // revoked / horizon_passed / epoch_changed / approval_withdrawn /
          // fork_detected all mean "a human must approve again" — named, so
          // the machine can say which.
          return Response.json({ error: r.reason }, { status });
        }
        const { ok: _ok, renewUntil, generation, ...tier } = r;
        return Response.json({ ...tier, renew_until: renewUntil, generation });
      }

      // GET /cert/issuing-ca/enrollments — the signed-in human's machines.
      // POST /cert/issuing-ca/enrollments/revoke { key_fingerprint } — stop
      // one renewing. Its own approver may; an administrator may revoke any.
      if (pathname === "/cert/issuing-ca/enrollments" || pathname === "/cert/issuing-ca/enrollments/revoke") {
        const cookie = parseCookie(request.headers.get("cookie") || "", "notme_session");
        if (!cookie) return jsonErr("session_required", 401);
        const authority = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
        const { verifySessionCookie, liveScopes } = await import("./src/auth/session");
        const session = await verifySessionCookie(cookie, await authority.getSessionSecret());
        if (!session) return jsonErr("invalid_session", 401);
        if (pathname === "/cert/issuing-ca/enrollments" && request.method === "GET") {
          return Response.json(await authority.listTierEnrolments(session.principalId));
        }
        if (pathname === "/cert/issuing-ca/enrollments/revoke" && request.method === "POST") {
          let body: { key_fingerprint?: unknown } = {};
          try {
            body = (await request.json()) as typeof body;
          } catch {
            /* empty body */
          }
          const fingerprint = typeof body.key_fingerprint === "string" ? body.key_fingerprint.toLowerCase() : "";
          const isAdmin = (await liveScopes(session, authority)).includes("authorityManage");
          const r = await authority.revokeTierEnrolment({
            keyFingerprint: fingerprint,
            byPrincipal: session.principalId,
            anyPrincipal: isAdmin,
          });
          // 404, not 403, for someone else's machine: whether a fingerprint
          // is enrolled under another principal is not this caller's business.
          return r.ok ? Response.json({ ok: true }) : jsonErr("no such enrollment", 404);
        }
        return jsonErr("method not allowed", 405);
      }

      if (pathname === "/cert/issuing-ca" && request.method === "POST") {
        try {
          const cookie = parseCookie(
            request.headers.get("cookie") || "",
            "notme_session",
          );
          if (!cookie) {
            return Response.json(
              { error: "session_required" },
              { status: 401 },
            );
          }
          const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
          const authority = env.SIGNING_AUTHORITY.get(authorityId);
          const { verifySessionCookie } = await import("./src/auth/session");
          const sessionSecret = await authority.getSessionSecret();
          const session = await verifySessionCookie(cookie, sessionSecret);
          if (!session) {
            return Response.json({ error: "invalid_session" }, { status: 401 });
          }
          // LIVE grant, not the cookie's copy (notme-486e8a). This read
          // session.scopes, so a revoked certMint kept minting tiers until
          // the cookie expired.
          const { liveScopes } = await import("./src/auth/session");
          if (!(await liveScopes(session, authority)).includes("certMint")) {
            return jsonErr("certMint scope required", 403);
          }

          let body: {
            public_key?: string;
            proof?: string;
            scopes?: string[];
          } = {};
          try {
            body = (await request.json()) as typeof body;
          } catch {
            /* empty body */
          }
          if (!body.public_key) {
            return jsonErr("public_key required (Ed25519 SPKI PEM)", 400);
          }
          if (!body.proof) {
            return jsonErr(
              "proof required (Ed25519 signature over the binding payload)",
              400,
            );
          }

          const { importPublicKey } = await import("./src/cert-authority");
          let publicKey: CryptoKey;
          try {
            publicKey = await importPublicKey(body.public_key);
          } catch (e: any) {
            return jsonErr("invalid public key: " + e.message, 400);
          }
          if (publicKey.algorithm.name !== "Ed25519") {
            // The tier signs certificates and the chain is Ed25519
            // end-to-end; mintIssuingCaCert would refuse this anyway, but a
            // 400 with the reason beats a 500 with a stack trace.
            return jsonErr("issuing tier requires an Ed25519 key", 400);
          }

          // Binding = spki || SHA-256(session cookie) — the session term
          // stops a captured public_key+proof pair being replayed under a
          // different session, same construction as /cert/passkey. Pre-image
          // only: this path is new, so no legacy digest window exists.
          const spki = (await crypto.subtle.exportKey(
            "spki",
            publicKey,
          )) as ArrayBuffer;
          const cookieHash = await crypto.subtle.digest(
            "SHA-256",
            new TextEncoder().encode(cookie),
          );
          const bindingInput = new Uint8Array(spki.byteLength + 32);
          bindingInput.set(new Uint8Array(spki), 0);
          bindingInput.set(new Uint8Array(cookieHash), spki.byteLength);
          const { verifyEd25519PopProof } = await import("./src/auth/pop");
          if (!(await verifyEd25519PopProof(bindingInput, publicKey, body.proof))) {
            return jsonErr("Ed25519 proof-of-possession failed", 401);
          }

          const { narrowScopes } = await import("./src/auth/scope-chain");
          const { certScopesForSession } = await import(
            "./src/auth/passkey-cert-scopes"
          );
          const scopes = certScopesForSession(
            narrowScopes(session.scopes ?? [], body.scopes ?? ["bridgeCert"]),
          );
          if (scopes.length === 0) {
            return jsonErr(
              "no requested scope is cert-eligible and held (need bridgeCert)",
              403,
            );
          }

          const sessionAuthMethod = session.authMethod;
          if (
            typeof sessionAuthMethod !== "string" ||
            sessionAuthMethod.length === 0
          ) {
            return jsonErr("session carries no authMethod", 401);
          }

          const result = await authority.mintIssuingCa({
            subject: session.principalId,
            identity: principalIdentity(wimseTrustDomain(env), session.principalId),
            publicKeyPem: body.public_key,
            scopes,
            authMethod: sessionAuthMethod,
          });
          return Response.json({
            ...result,
            principal_id: session.principalId,
            auth_method: sessionAuthMethod,
          });
        } catch (e: any) {
          return jsonErr("issuing-ca error: " + e.message, 500);
        }
      }

      // POST /cert/gha — GHA OIDC JWT → bridge cert (legacy, kept for compat)
      // POST /bootstrap/claim — the named workflow approves a passkey claim
      // (notme-486e8a). `Authorization: Bearer <GitHub Actions OIDC token,
      // aud=GHA_CERT_AUDIENCE>`, body `{ code }`. Run by
      // .github/workflows/claim-authority.yml. The token is verified HERE
      // (signature, audience, jti) and the DO checks the subject against
      // BOOTSTRAP_GHA_SUBJECT, so the attestation is never decorative.
      if (pathname === "/bootstrap/claim" && request.method === "POST") {
        const auth = request.headers.get("authorization") || "";
        const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
        if (!token) return jsonErr("Bearer GitHub Actions OIDC token required", 401);
        const cfg = getConfig(env);
        const { validateGHAToken } = await import("./src/gha-oidc");
        let claims: any;
        try {
          claims = await validateGHAToken(token, cfg.ghaCertAudience);
        } catch {
          return jsonErr("invalid token", 401);
        }
        if (!claims.jti) return jsonErr("jti claim required for replay protection", 400);
        // Same keyspace as /cert/gha, /cert and /token: one token, one spend.
        const jtiKey = `jti:${claims.jti}`;
        if (await platform.cache.get(jtiKey)) return jsonErr("token already used", 401);
        await platform.cache.put(jtiKey, "1", {
          expirationTtl: Math.max(cfg.jtiMinTtlSeconds, claims.exp - Math.floor(Date.now() / 1000)),
        });
        let body: { code?: unknown } = {};
        try {
          body = (await request.json()) as typeof body;
        } catch {
          /* empty body */
        }
        const authority = env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName("default"));
        const r = await authority.approveBootstrapClaim(
          typeof body.code === "string" ? body.code : "",
          claims.sub,
        );
        if (!r.ok) {
          const map = {
            not_configured: [403, "BOOTSTRAP_GHA_SUBJECT is not set on this deployment"],
            subject_mismatch: [403, "this workflow is not the one BOOTSTRAP_GHA_SUBJECT names"],
            governed: [409, "this authority already has an administrator"],
            no_such_claim: [404, "no such claim code — it may have expired; register again"],
          } as const;
          const [status, msg] = map[r.reason as keyof typeof map];
          return jsonErr(msg, status);
        }
        return Response.json({ ok: true, principal_id: r.principalId });
      }

      if (pathname === "/cert/gha") {
        return handleCertGHA(request, env, platform);
      }

      // GET /authorize — OAuth-style redirect for cross-origin DPoP token issuance
      if (pathname === "/authorize" && request.method === "GET") {
        const url = new URL(request.url);
        const redirectUri = url.searchParams.get("redirect_uri") || "";
        const audience =
          url.searchParams.get("audience") || "https://rosary.bot";
        const state = url.searchParams.get("state") || "";

        // ADR-013: capability negotiation, not a feature flag. A client that
        // sends a PKCE challenge gets the authorization-code completion
        // (`?code=`); one that does not gets the legacy `?token=`. This exists
        // solely so rig can be migrated without a flag day — and a flag day is
        // unacceptable here for a specific reason: /admin/setup-github is the
        // flow used to RECOVER admin access, so breaking it costs more than
        // the exposure being closed.
        //
        // The legacy branch has no reason to outlive rig's deploy. Deleting it
        // is tracked on notme-2bba44.
        const codeChallenge = url.searchParams.get("code_challenge") || "";
        const codeChallengeMethod =
          url.searchParams.get("code_challenge_method") || "";

        const { isValidCodeChallenge } = await import("@agentic-research/dpop");
        if (codeChallenge) {
          // S256 only. RFC 7636 §4.2 also defines "plain", where the verifier
          // IS the challenge — which would put the verifier in the redirect
          // URL and reintroduce precisely the leak this flow removes.
          if (codeChallengeMethod !== "S256") {
            return jsonErr("code_challenge_method must be S256", 400);
          }
          if (!isValidCodeChallenge(codeChallenge)) {
            // Fail at flow START, where the error is diagnosable, rather than
            // one round-trip later as an opaque invalid_grant.
            return jsonErr("malformed code_challenge", 400);
          }
        }

        // Validate redirect_uri via the shared helper — keeps the matrix
        // (required / parsable / https-or-localhost / allowlist) under
        // unit tests in worker/src/auth/redirect-uri.ts rather than
        // re-implementing the rules in every consumer.
        const { validateRedirectUri } = await import("./src/auth/redirect-uri");
        const v = validateRedirectUri(redirectUri);
        if (!v.ok) return jsonErr(v.reason, v.status);

        // Check session
        const cookie = parseCookie(
          request.headers.get("cookie") || "",
          "notme_session",
        );
        if (!cookie) {
          // No session — redirect to login, then come back
          const returnTo = `/authorize?${url.searchParams.toString()}`;
          return Response.redirect(
            `${authorityUrl}/login?return_to=${encodeURIComponent(returnTo)}`,
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
            `${authorityUrl}/login?return_to=${encodeURIComponent(returnTo)}`,
            302,
          );
        }

        // Session valid — serve the authorize page
        // Params are injected into a data attribute and read by JS (no inline eval)
        return new Response(
          authorizePageHtml(redirectUri, audience, state, codeChallenge),
          {
            headers: {
              "Content-Type": "text/html; charset=utf-8",
              // Scope this precisely, because it is easy to overclaim (an
              // earlier draft of this comment did): a Referrer-Policy on THIS
              // document governs the Referer THIS document sends — on its own
              // subresource loads, and on the navigation away to redirect_uri.
              // It does NOT govern what the DESTINATION page sends once the
              // browser is sitting on `${redirect_uri}?token=...`; that is the
              // destination's own Referrer-Policy (rig's, today), and it is the
              // vector that actually leaks the ACCESS TOKEN onward. notme
              // cannot close that from here.
              //
              // What this DOES protect is the authorize URL itself — which
              // carries `state`, a CSRF value — from being handed to the
              // destination as a Referer. Modern browsers default to
              // strict-origin-when-cross-origin and would send only the origin
              // anyway, so treat this as making an existing default explicit
              // and covering the same-origin case, not as a fix for the token.
              //
              // The token-in-URL exposure is untouched by this header. See
              // THREAT_MODEL.md `token in URL logs` / notme-07204f for the real
              // residual and the three delivery changes that would remove it.
              "Referrer-Policy": "no-referrer",
            },
          },
        );
      }

      // POST /authorize/code — mint a single-use authorization code (ADR-013).
      //
      // Called by the /authorize page JS, same-origin, with the session
      // cookie. Returns a code that goes in the redirect URL INSTEAD of an
      // access token: a code in a log is worthless once redeemed, and PKCE
      // means an attacker who reads one cannot redeem it at all.
      if (pathname === "/authorize/code" && request.method === "POST") {
        try {
          const cookie = parseCookie(
            request.headers.get("cookie") || "",
            "notme_session",
          );
          if (!cookie) {
            return Response.json(
              { error: "session_required" },
              { status: 401 },
            );
          }

          let body: {
            audience?: string;
            redirect_uri?: string;
            code_challenge?: string;
          } = {};
          try {
            body = (await request.json()) as typeof body;
          } catch {
            /* empty body */
          }

          const audience = body.audience || "";
          if (!audience) {
            return Response.json(
              { error: "audience_required" },
              { status: 400 },
            );
          }
          const allowedAudiences = getAllowedAudiences(env);
          if (!allowedAudiences.has(audience)) {
            return Response.json(
              { error: "invalid_audience", allowed: [...allowedAudiences] },
              { status: 400 },
            );
          }

          // The redirect_uri is re-validated here, not trusted from the page.
          // This endpoint is reachable directly, so the allowlist has to hold
          // at the point the code is BOUND to a destination — otherwise a
          // caller could bind a code to an arbitrary URI and the check on
          // /authorize would be decorative.
          const { validateRedirectUri } =
            await import("./src/auth/redirect-uri");
          const v = validateRedirectUri(body.redirect_uri || "");
          if (!v.ok) return jsonErr(v.reason, v.status);

          const { isValidCodeChallenge } =
            await import("@agentic-research/dpop");
          if (!isValidCodeChallenge(body.code_challenge)) {
            return jsonErr("malformed or missing code_challenge", 400);
          }

          const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
          const authority = env.SIGNING_AUTHORITY.get(authorityId);
          const { verifySessionCookie } = await import("./src/auth/session");
          const sessionSecret = await authority.getSessionSecret();
          const session = await verifySessionCookie(cookie, sessionSecret);
          if (!session) {
            return Response.json({ error: "invalid_session" }, { status: 401 });
          }

          const { code, expiresAt } = await authority.createAuthorizationCode({
            principalId: session.principalId,
            scopes: session.scopes,
            audience,
            redirectUri: body.redirect_uri!,
            codeChallenge: body.code_challenge,
          });

          return Response.json({
            code,
            expires_in: expiresAt - Math.floor(Date.now() / 1000),
          });
        } catch (e: any) {
          return jsonErr("authorize code error: " + e.message, 500);
        }
      }

      // POST /authorize/redeem — exchange an authorization code for a token
      // (ADR-013, RFC 6749 §4.1.3 shape).
      //
      // Server-to-server: the caller is the party that started the flow and
      // holds the PKCE verifier. NO session cookie — this is not a browser
      // call, and requiring one would defeat the point (the whole reason the
      // code exists is that the browser hands off to a backend).
      //
      // Authentication IS the PKCE verifier plus possession of the code. That
      // is why no client_secret appears here: the redirect-host allowlist is
      // the client registry (ADR-013 "deliberately not in scope"), and PKCE
      // binds the redemption to whoever started the flow.
      if (pathname === "/authorize/redeem" && request.method === "POST") {
        try {
          let body: {
            code?: string;
            code_verifier?: string;
            redirect_uri?: string;
          } = {};
          try {
            body = (await request.json()) as typeof body;
          } catch {
            /* empty body */
          }

          const { isValidCodeVerifier } =
            await import("@agentic-research/dpop");
          if (!body.code || typeof body.code !== "string") {
            return Response.json(
              { error: "invalid_request", error_description: "code required" },
              { status: 400 },
            );
          }
          if (!isValidCodeVerifier(body.code_verifier)) {
            // Checked rather than trusted: PKCE's security argument IS the
            // verifier's entropy, so accepting a short one would hand back a
            // working flow with none of the protection.
            return Response.json(
              {
                error: "invalid_request",
                error_description:
                  "code_verifier must be 43-128 unreserved characters (RFC 7636 §4.1)",
              },
              { status: 400 },
            );
          }
          if (!body.redirect_uri || typeof body.redirect_uri !== "string") {
            return Response.json(
              {
                error: "invalid_request",
                error_description: "redirect_uri required",
              },
              { status: 400 },
            );
          }

          const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
          const authority = env.SIGNING_AUTHORITY.get(authorityId);
          const result = await authority.redeemAuthorizationCode({
            code: body.code,
            codeVerifier: body.code_verifier,
            redirectUri: body.redirect_uri,
          });

          if (!result.ok) {
            // One answer for unknown / spent / expired / wrong-redirect_uri /
            // bad-verifier. Distinguishing them would tell an attacker
            // probing with harvested codes which ones were real.
            return Response.json({ error: result.reason }, { status: 400 });
          }

          return Response.json({
            access_token: result.accessToken,
            token_type: "Bearer",
            expires_in: 300,
          });
        } catch (e: any) {
          return jsonErr("authorize redeem error: " + e.message, 500);
        }
      }

      // POST /authorize/token — Unbound redirect token for /authorize flow.
      // Session cookie required. No DPoP — token has no cnf.jkt.
      // Used by the /authorize page JS after passkey login.
      //
      // LEGACY (ADR-013). Superseded by /authorize/code + /authorize/redeem,
      // which keep the credential out of the URL entirely. Retained only
      // until rig ships its side; deletion tracked on notme-2bba44.
      if (pathname === "/authorize/token" && request.method === "POST") {
        try {
          const cookie = parseCookie(
            request.headers.get("cookie") || "",
            "notme_session",
          );
          if (!cookie) {
            return Response.json(
              { error: "session_required" },
              { status: 401 },
            );
          }

          let audience = "";
          try {
            const body = (await request.json()) as { audience?: string };
            audience = body.audience || "";
          } catch {
            /* empty body */
          }

          if (!audience) {
            return Response.json(
              { error: "audience_required" },
              { status: 400 },
            );
          }
          const allowedAudiences = getAllowedAudiences(env);
          if (!allowedAudiences.has(audience)) {
            return Response.json(
              { error: "invalid_audience", allowed: [...allowedAudiences] },
              { status: 400 },
            );
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
          return Response.json(
            { error: "authorize token error: " + e.message },
            { status: 500 },
          );
        }
      }

      // POST /token — DPoP sender-constrained access token (RFC 9449)
      if (pathname === "/token" && request.method === "POST") {
        // withCors: the preflight advertises this origin; the response must
        // honour it (notme-0a27a6). Wraps every exit, including the 500.
        return withCors(
          await (async (): Promise<Response> => {
            try {
              const dpopProof = request.headers.get("DPoP");

              // Fast-fail: no DPoP proof = 400
              if (!dpopProof) {
                return Response.json(
                  { error: "dpop_proof_required" },
                  { status: 400 },
                );
              }

              // Parse body for audience — validated against module-scope ALLOWED_AUDIENCES
              // JSON (the first-party session flow) or form-encoded (RFC 8693
              // token exchange, form-encoded per RFC 6749 §4.1.3).
              let fields: Record<string, string> = {};
              try {
                const ct = request.headers.get("content-type") || "";
                fields = ct.includes("application/x-www-form-urlencoded")
                  ? Object.fromEntries(new URLSearchParams(await request.text()))
                  : ((await request.json()) as Record<string, string>);
              } catch {
                /* empty body */
              }
              const audience = typeof fields.audience === "string" ? fields.audience : "";
              const grantType = typeof fields.grant_type === "string" ? fields.grant_type : "";
              // Discovery advertises exactly this grant (as-metadata.ts). An
              // absent grant_type is the first-party session flow, which is
              // deliberately not advertised; anything else is refused by its
              // RFC 6749 §5.2 name rather than silently treated as a session.
              if (grantType && grantType !== TOKEN_EXCHANGE_GRANT) {
                return Response.json({ error: "unsupported_grant_type" }, { status: 400 });
              }

              if (!audience) {
                return Response.json(
                  { error: "audience_required" },
                  { status: 400 },
                );
              }
              const allowedAudiences = getAllowedAudiences(env);
              if (!allowedAudiences.has(audience)) {
                return Response.json(
                  { error: "invalid_audience", allowed: [...allowedAudiences] },
                  { status: 400 },
                );
              }

              const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
              const authority = env.SIGNING_AUTHORITY.get(authorityId);

              // ── Resolve identity: session cookie OR client cert ──
              let principalId: string | null = null;
              let scopes: string[] = [];
              // Hoisted: the DPoP nonce MAC key is derived from this same secret
              // (src/auth/dpop-nonce.ts), and re-fetching it below would be a
              // second DO round-trip for a value already in hand.
              let sessionSecret: string | null = null;
              // Set for token exchange: the subject token's jti and exp, spent
              // only after the DPoP proof verifies.
              let exchanged: { jti: string; exp: number } | null = null;

              if (grantType === TOKEN_EXCHANGE_GRANT) {
                // RFC 8693, a GitHub Actions OIDC token as the subject
                // (notme-486e8a). Discovery used to advertise
                // "github_actions_oidc" here while this endpoint accepted only
                // a session cookie. The checks are /cert/gha's, because it is
                // the same evidence buying a different artifact: GitHub's
                // signature, our audience, the owner allowlist, a jti.
                const tokenType = fields.subject_token_type || "";
                if (
                  tokenType !== "urn:ietf:params:oauth:token-type:id_token" &&
                  tokenType !== "urn:ietf:params:oauth:token-type:jwt"
                ) {
                  return Response.json(
                    { error: "invalid_request", error_description: "subject_token_type must be id_token or jwt" },
                    { status: 400 },
                  );
                }
                const cfg = getConfig(env);
                const { validateGHAToken } = await import("./src/gha-oidc");
                let claims: any;
                try {
                  claims = await validateGHAToken(fields.subject_token || "", cfg.ghaCertAudience);
                } catch {
                  // Coarse on purpose, as mintBridgeCert's refusals are.
                  return Response.json({ error: "invalid_grant" }, { status: 400 });
                }
                if (
                  !claims.jti ||
                  !getAllowedOwners(env).has(String(claims.repository_owner).toLowerCase())
                ) {
                  return Response.json({ error: "invalid_grant" }, { status: 400 });
                }
                // A workload identity, exactly as /cert/gha mints: the GitHub
                // subject, carrying bridgeCert — enough to be mint evidence
                // (rig's notme-access-token proof), nothing more.
                principalId = claims.sub;
                scopes = ["bridgeCert"];
                exchanged = { jti: claims.jti, exp: Number(claims.exp) || 0 };
                sessionSecret = await authority.getSessionSecret();
              } else {
                // Session cookie (browser/passkey users)
                const cookie = parseCookie(
                  request.headers.get("cookie") || "",
                  "notme_session",
                );
                if (cookie) {
                  const { verifySessionCookie, liveScopes } =
                    await import("./src/auth/session");
                  const secret: string = await authority.getSessionSecret();
                  sessionSecret = secret;
                  const session = await verifySessionCookie(cookie, secret);
                  if (session) {
                    principalId = session.principalId;
                    // LIVE grants, not the cookie's copy (notme-486e8a): a
                    // revoked scope must not keep appearing in fresh tokens.
                    scopes = await liveScopes(session, authority);
                  }
                }

                // X-Client-Cert path REMOVED — mTLS not configured in wrangler.toml,
                // so the header is attacker-controlled. Re-enable only when CF mTLS
                // bindings are active and CF injects the cert (not the client).

                if (!principalId) {
                  return Response.json(
                    { error: "session_required" },
                    { status: 401 },
                  );
                }
              }

              // Rate limit — atomic, edge-fast (replaces KV-based TOCTOU-vulnerable limiter)
              if (env.TOKEN_LIMITER) {
                const { success } = await env.TOKEN_LIMITER.limit({
                  key: `token:${principalId}`,
                });
                if (!success) {
                  return Response.json(
                    { error: "rate_limited" },
                    { status: 429 },
                  );
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
                return Response.json(
                  { error: "invalid_dpop_proof" },
                  { status: 401 },
                );
              }

              // ── Nonce challenge (RFC 9449 §8/§9) ──
              //
              // Placed AFTER session resolution, rate limiting and proof
              // validation, so a challenge is only ever minted for a caller that
              // has already authenticated and proved possession of the proof key.
              // Issuing nonces earlier would hand an unauthenticated caller a
              // free HMAC oracle on the rejection path.
              //
              // Off by default: turning it on rejects the first request of every
              // client that has never seen a challenge, which is correct per spec
              // but is a breaking change for deployed clients. Deployments opt in
              // once their clients handle the retry.
              if (dpopNonceRequired(env)) {
                if (!sessionSecret) {
                  // Unreachable — principalId is only set on the cookie path,
                  // which assigns the secret. Explicit rather than a `!`: if a
                  // future auth path sets principalId without the secret, this
                  // must fail closed, not skip the nonce check.
                  return jsonErr("nonce unavailable: no session secret", 500);
                }
                const { issueDpopNonce, verifyDpopNonce, nonceHeaders } =
                  await import("./src/auth/dpop-nonce");
                const nonceOk = await verifyDpopNonce(
                  proofResult.nonce,
                  sessionSecret,
                );
                if (!nonceOk) {
                  // §8.1: 400 + `use_dpop_nonce`, carrying the nonce to retry
                  // with. The JTI is deliberately NOT consumed — the client will
                  // re-sign with a fresh proof, and burning the jti here would
                  // make every challenge cost the client an extra round-trip.
                  return Response.json(
                    {
                      error: "use_dpop_nonce",
                      error_description:
                        "Authorization server requires a nonce in the DPoP proof",
                    },
                    {
                      status: 400,
                      headers: nonceHeaders(
                        await issueDpopNonce(sessionSecret),
                      ),
                    },
                  );
                }
              }

              // Atomically consume the proof JTI and mint inside the singleton DO.
              // SQLite uniqueness closes the cross-edge read/write race that an
              // eventually-consistent KV cache cannot.
              if (exchanged) {
                // Spent after the DPoP proof verified, in the keyspace /cert/gha
                // and /cert's oidc proof use: one GitHub token, one spend.
                const key = `jti:${exchanged.jti}`;
                if (await platform.cache.get(key)) {
                  return Response.json({ error: "invalid_grant" }, { status: 400 });
                }
                await platform.cache.put(key, "1", {
                  expirationTtl: Math.max(60, exchanged.exp - Math.floor(Date.now() / 1000)),
                });
              }
              const mintResult = await authority.mintDPoPTokenOnce({
                sub: principalId,
                scope: scopes.join(" "),
                audience,
                jkt: proofResult.thumbprint,
                proofJti: proofResult.jti,
              });
              if (!mintResult.ok) {
                return Response.json(
                  { error: "proof_reused" },
                  { status: 401 },
                );
              }

              // §8.2 permits a fresh nonce on a SUCCESSFUL response too. Without
              // it a client only ever learns a nonce by being rejected, so every
              // token would cost two round-trips once the nonce it holds ages
              // out. sessionSecret is non-null here whenever the flag is on —
              // the challenge block above returns otherwise.
              let successHeaders: Record<string, string> = {};
              if (dpopNonceRequired(env) && sessionSecret) {
                const { issueDpopNonce, nonceHeaders } =
                  await import("./src/auth/dpop-nonce");
                successHeaders = nonceHeaders(
                  await issueDpopNonce(sessionSecret),
                );
              }

              return Response.json(
                {
                  access_token: mintResult.accessToken,
                  token_type: "DPoP",
                  expires_in: 300,
                  // RFC 8693 §2.2.1: REQUIRED in a token-exchange response.
                  ...(exchanged
                    ? { issued_token_type: "urn:ietf:params:oauth:token-type:access_token" }
                    : {}),
                },
                { headers: successHeaders },
              );
            } catch (e: any) {
              return jsonErr("token endpoint error: " + e.message, 500);
            }
          })(),
        );
      }

      // GET /.well-known/jwks.json — Ed25519 public key for token verification
      // GET /.well-known/epochs.json — every epoch's signing key, current
      // and retired, so a THIRD PARTY can verify history rather than only the
      // present (notme-a0cff4).
      //
      // jwks.json answers "which key is live now", which is all a verifier of
      // a FRESH token needs. An auditor holding a receipt or certificate that
      // names epoch N needs the key that signed THAT epoch — and notme has
      // retained retired keys since PR #64 (rotate() archives before
      // deleting) while offering no way to read them. Cloister could only
      // archive epochs it happened to observe by polling, so a rotation
      // between polls left that epoch unresolvable even though notme held the
      // key: the repudiation risk notme-acd503 describes.
      //
      // Unauthenticated by design, like jwks.json and the discovery document:
      // this is public key material, and an auditor is not a principal.
      // Requiring a credential to verify history would defeat the point.
      if (pathname === "/.well-known/epochs.json") {
        const cached = await cacheMatch(request);
        if (cached) return cached;
        const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
        const authority = env.SIGNING_AUTHORITY.get(authorityId);
        const epochs = await authority.listEpochKeys();
        const resp = Response.json(
          { epochs },
          {
            headers: {
              // Short max-age: a rotation adds an entry, and an auditor
              // fetching just after one should not be told the epoch is
              // unknown. The set only ever grows, so a stale copy is
              // incomplete rather than wrong.
              "Cache-Control": "public, max-age=60",
              "Access-Control-Allow-Origin": "*",
            },
          },
        );
        return cachePut(request, resp);
      }

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
            cert_endpoint: `${authorityUrl}/cert`,
            cert_gha_endpoint: `${authorityUrl}/cert/gha`,
            ca_bundle_endpoint: `${authorityUrl}/.well-known/ca-bundle.pem`,
            algorithms_supported: ["Ed25519"],
            grant_types_supported: AUTHORITY_GRANT_TYPES,
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

      // ── OAuth 2.0 Authorization Server Metadata (RFC 8414) ──────────────
      //
      // notme IS an OAuth 2.0 authorization server: it has /authorize,
      // /token, and /.well-known/jwks.json, and mints DPoP-bound `at+jwt`
      // access tokens (RFC 9449). What it is NOT is an OpenID Provider —
      // it issues no `id_token` and honours no `scope=openid`.
      //
      // WHY THIS IS SERVED AT TWO PATHS:
      //   /.well-known/oauth-authorization-server  — the correct, accurate
      //     path for what this server is (RFC 8414).
      //   /.well-known/openid-configuration        — served ONLY because
      //     many client libraries probe exclusively there and would
      //     otherwise fail to discover us at all.
      //
      // WHAT IS DELIBERATELY OMITTED (do not "helpfully" add these):
      //   - id_token_signing_alg_values_supported  (REQUIRED by OIDC Discovery)
      //   - subject_types_supported                (REQUIRED by OIDC Discovery)
      //   - "openid" in scopes_supported
      //   - "id_token" in response_types_supported
      // Their absence is load-bearing: a strict OIDC client fails fast and
      // legibly instead of discovering an "OP", requesting scope=openid, and
      // silently getting no id_token back. Publishing a capability we do not
      // have would be worse here than publishing nothing — this is a trust
      // substrate. If id_token support ever lands, add these fields THEN.
      //
      // SECURITY NOTE: this document is unauthenticated by design (RFC 8414
      // §3) and intentionally public — it is a map, not a key. Reading it
      // grants nothing. What actually constrains issuance is the closed
      // audience allowlist (src/allowed-audiences.ts — every mint checks the
      // requested audience), validateRedirectUri() on /authorize, the
      // required session cookie, DPoP sender-binding via cnf.jkt, and the
      // absence of dynamic client registration.
      if (
        pathname === "/.well-known/oauth-authorization-server" ||
        pathname === "/.well-known/openid-configuration"
      ) {
        const cached = await cacheMatch(request);
        if (cached) return cached;
        // Body is built by src/as-metadata.ts — a pure function so the
        // document's CONTENT is unit-testable without a Cache API, an env, or
        // workerd. Every field's rationale (including which fields are
        // deliberately ABSENT, and why) lives there next to the values, and
        // src/__tests__/as-metadata.test.ts pins them. This handler owns only
        // caching + headers.
        const resp = Response.json(
          buildAsMetadata(authorityUrl, siteUrl, getSigningAlgs(env)),
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
                cert: "/cert",
                cert_gha: "/cert/gha",
                token: "/token",
                login: "/login",
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
        const result = new Response(resp.body, {
          status: resp.status,
          statusText: resp.statusText,
          headers,
        });
        return cachePut(request, result, "Accept");
      }

      // Proxy everything else to signet via VPC tunnel (requires VPC_AUTH binding)
      //
      // The tunnel fetch is awaited inside a try so a REJECTION lands here
      // instead of escaping the handler. Unawaited, it propagated and every
      // unmatched path under the authority host answered with Cloudflare's
      // error 1101 — a Worker exception, not a routing answer (notme-cb0354,
      // live in production 2026-08-05 while known routes were healthy).
      // Staging cannot catch this: with no VPC_AUTH binding it takes the 503
      // fallthrough below, so the environments diverge exactly at this branch
      // and a green staging run says nothing about this path.
      //
      // The 404 body is CONSTANT deliberately. From here a dead tunnel and a
      // path that was never routable are the same event — the fetch fails
      // identically for both — so the honest distinction is unavailable, and
      // manufacturing one would leak the authority's private route table to
      // unauthenticated callers. The cause goes to the log, where an operator
      // can tell an outage from a typo; the caller learns only that nothing
      // answers here.
      if (env.VPC_AUTH) {
        const originUrl = `http://localhost${pathname}${url.search}`;
        try {
          return await env.VPC_AUTH.fetch(
            new Request(originUrl, {
              method: request.method,
              headers: request.headers,
              body: request.body,
            }),
          );
        } catch (vpcErr: any) {
          console.error("[vpc-auth] proxy failed:", pathname, vpcErr?.message);
          return Response.json({ error: "not_found" }, { status: 404 });
        }
      }
      // Same constant 404 as the VPC-failure branch above, deliberately.
      //
      // This used to answer 503 "auth.notme.bot not yet configured", which
      // made an unmatched path mean two different things depending on whether
      // a VPC binding happened to exist — so the verify check that is correct
      // for production failed on staging the moment it was added, and the two
      // environments disagreed about a response an auditor might rely on.
      //
      // It also disclosed deployment state to unauthenticated callers. From
      // the caller's side the path simply does not resolve; whether an
      // operator has configured a tunnel is not their business, and is not a
      // fact worth handing to a stranger.
      return Response.json({ error: "not_found" }, { status: 404 });
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
      const result = new Response(resp.body, {
        status: resp.status,
        statusText: resp.statusText,
        headers,
      });
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
      const result = new Response(resp.body, {
        status: resp.status,
        statusText: resp.statusText,
        headers,
      });
      return cachePut(request, result, "Accept");
    }

    // /why moved to the blog at q-q.dev.
    //
    // The page itself lives in the PRIVATE agentic-research/notme.bot repo,
    // which declares a worker of the same name on these same two routes —
    // so the two repos are two sources for ONE deployment and the last
    // deploy wins. This repo is what is live (production's nav.js matches
    // this repo's, and has no "why" entry), and this repo has no why.html,
    // which is why /why has been 404ing. Nothing pointed at it: the
    // deployed nav and sitemap predate the page, so only a typed URL
    // reached the 404.
    //
    // 302 AND SHORT-CACHED, UNLIKE EVERY OTHER REDIRECT BELOW. Those are
    // settled renames and use 301 with `max-age=31536000, immutable`. This
    // destination is NOT settled: the post is not published on q-q.dev yet,
    // so the target is the blog root and will become the post's own URL. An
    // immutable 301 would make browsers ignore that change for a year.
    // Flip both when the post lands (notme-4e02fb).
    if (url.pathname === "/why") {
      const resp = new Response(null, {
        status: 302,
        headers: {
          Location: "https://q-q.dev/",
          "Cache-Control": "public, max-age=600",
        },
      });
      return cachePut(request, resp);
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
        newHeaders.set(
          "Cache-Control",
          "public, s-maxage=60, stale-while-revalidate=300",
        );
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
