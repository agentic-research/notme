// Generic proof verification — OIDC JWTs and X.509 certs.
// No provider-specific code. If it has a JWKS, we can verify it.

import { TRUSTED_ISSUERS as CONTRACT_TRUSTED_ISSUERS } from "@notme/contract";
/** The contract's trusted issuers (ADR-023 narrows their pin to a challenge audience at /join). */
export { CONTRACT_TRUSTED_ISSUERS };
import { base64urlDecode } from "@agentic-research/dpop";
import { OID_EPOCH } from "../cert-authority";
import { assertGhaEventAllowed, GHA_ISSUER as GHA_OIDC_ISSUER } from "../gha-oidc";
import { JWKS_FETCH_TIMEOUT_MS, JWKS_POLICY, JwksCache } from "./jwks-cache";

export interface VerifiedIdentity {
  type: "oidc" | "x509";
  issuer: string; // OIDC issuer URL or cert issuer CN
  subject: string; // OIDC sub claim or cert subject CN
  claims?: Record<string, unknown>; // raw claims for the connection record
}

export interface OIDCProof {
  type: "oidc";
  token: string; // raw JWT
}

export interface X509Proof {
  type: "x509";
  cert: string; // PEM
  /**
   * Intermediate tier certificates, leaf-side first — present when the cert
   * was signed by an Issuing CA tier rather than the root (ADR-019 D4).
   * Absent or empty means root-signed, verified single-hop by verifyX509.
   */
  chain?: string[];
}

export type Proof = OIDCProof | X509Proof;

// ── OIDC verification (any issuer with a JWKS endpoint) ──

interface JWK {
  kty: string;
  kid: string;
  n?: string;
  e?: string;
  alg?: string;
  crv?: string;
  x?: string;
  y?: string;
}

/**
 * Select the verifying JWK for a token by its `kid`.
 *
 * A silent first-key fallback when the header omits `kid` is key-confusion on a
 * multi-key JWKS: the token gets verified against whichever key happens to be
 * first, regardless of which key signed it. That is not hypothetical here — a
 * rotation grace window publishes BOTH the current and previous key, so
 * "pick keys[0]" can verify a token against the wrong one. The fallback is only
 * unambiguous for a single-key JWKS; with more than one key an explicit `kid`
 * is required. Returns undefined when a present `kid` matches no key (caller
 * surfaces "unknown key id"). notme ADR-012 R1: kid selects the key, never
 * silently guessed. (notme-692274)
 */
export function selectVerifyingKey<K extends { kid: string }>(
  keys: readonly K[],
  kid: string | undefined,
): K | undefined {
  if (kid) return keys.find((k) => k.kid === kid);
  if (keys.length === 1) return keys[0];
  throw new Error(
    "kid required: JWKS publishes multiple keys, cannot select without a kid",
  );
}

// ── Per-issuer audience map (notme-0a1ee8) ──
//
// Which OIDC issuers are trusted, and the audience each one's tokens must
// carry. PRESENCE IN THE MAP IS TRUST: an issuer with no entry is refused
// before any JWKS fetch, which is what stops an attacker-controlled `iss`
// from steering a fetch (SSRF).
//
// One audience for every issuer was the old shape, and it is why Google
// could not be supported: its ID tokens carry
// aud=<client-id>.apps.googleusercontent.com, which can never match
// "notme.bot". A pin per issuer lets each carry the audience it actually
// issues (notme-ae65a0, M1).
//
//   - https://auth.notme.bot: self-issued, always aud=notme.bot.
//   - https://token.actions.githubusercontent.com: a workflow requests
//     aud=notme.bot via core.getIDToken(audience).
//   - https://accounts.google.com: ONLY when GOOGLE_CLIENT_ID is set, and
//     pinned to exactly that client id.
export type IssuerAudienceMap = Readonly<Record<string, string | readonly string[]>>;

/** The audience the baseline issuers (@notme/contract TRUSTED_ISSUERS) must carry. */
export const NOTME_AUDIENCE = "notme.bot";

export const GOOGLE_ISSUER = "https://accounts.google.com";

/**
 * The deployment's audience map, from its env. The contract's baseline
 * issuers always pin "notme.bot", exactly as the single pin did. Google is
 * added only when the operator sets GOOGLE_CLIENT_ID. Unset or blank means
 * Google stays untrusted rather than trusted with no audience.
 */
export function issuerAudiences(env: { GOOGLE_CLIENT_ID?: unknown }): IssuerAudienceMap {
  const map: Record<string, string> = {};
  for (const iss of CONTRACT_TRUSTED_ISSUERS) map[iss] = NOTME_AUDIENCE;
  const google = typeof env.GOOGLE_CLIENT_ID === "string" ? env.GOOGLE_CLIENT_ID.trim() : "";
  if (google) map[GOOGLE_ISSUER] = google;
  return Object.freeze(map);
}

/**
 * The audiences `iss` must carry, or null if it is not trusted. Own
 * properties only: `iss` is attacker-chosen, so "constructor" or
 * "__proto__" must not resolve through Object.prototype. An entry with no
 * usable audience counts as untrusted, never as "any audience".
 */
function expectedAudiencesFor(map: IssuerAudienceMap, iss: string): string[] | null {
  if (!Object.prototype.hasOwnProperty.call(map, iss)) return null;
  const v = map[iss];
  const arr = (Array.isArray(v) ? v : [v]).filter((a): a is string => typeof a === "string" && a.length > 0);
  return arr.length > 0 ? arr : null;
}

// Per-issuer JWKS cache (notme-a36d10, review M2): 1 h TTL, one rate-limited
// refetch on an unknown kid, stale keys served up to 24 h when the issuer is
// down. The rules are in jwks-cache.ts. The fetcher runs only for an issuer
// fetchJWKS has already checked against the trust map.
const jwksCache = new JwksCache<JWK>(async (issuer, { bypassCache }) => {
  // Each request bounded, so the up-to-three-step discovery cannot hold a
  // route on a hung issuer; an unknown-kid refetch skips any HTTP cache.
  const get = (url: string) =>
    fetch(url, {
      ...(bypassCache ? { cache: "no-store" as const } : {}),
      signal: AbortSignal.timeout(JWKS_FETCH_TIMEOUT_MS),
    });
  // Try .well-known/jwks first, then .well-known/openid-configuration
  let res = await get(`${issuer}/.well-known/jwks`);
  if (!res.ok) {
    const configRes = await get(`${issuer}/.well-known/openid-configuration`);
    if (configRes.ok) {
      const config = (await configRes.json()) as { jwks_uri?: string };
      if (config.jwks_uri) {
        res = await get(config.jwks_uri);
      }
    }
  }
  if (!res.ok) throw new Error(`JWKS fetch failed for ${issuer}: ${res.status}`);
  const body = (await res.json()) as { keys?: unknown };
  if (!Array.isArray(body.keys)) throw new Error(`JWKS fetch failed for ${issuer}: no keys array`);
  return body.keys as JWK[];
}, JWKS_POLICY);

async function fetchJWKS(
  issuer: string,
  audiences: IssuerAudienceMap,
  kid: string | undefined,
): Promise<JWK[]> {
  // Re-checked here, where the fetch is, so that no path can reach the
  // network with an issuer the map does not name.
  if (!expectedAudiencesFor(audiences, issuer)) {
    throw new Error(`untrusted issuer: ${issuer}`);
  }
  return jwksCache.get(issuer, (keys) => {
    try {
      return selectVerifyingKey(keys, kid) !== undefined;
    } catch {
      return true; // kid omitted with several keys: refetching cannot help; the caller refuses
    }
  });
}

/**
 * Verify an OIDC token with mandatory, per-issuer audience validation.
 *
 * `audiences` is REQUIRED. It prevents confused deputy attacks: a token
 * issued for evil-app.com (same Google issuer, same user sub) must be
 * rejected because its aud doesn't match notme's client ID. Earlier the
 * audience was optional and `/connections` forgot to pass it (see
 * notme-567f07); making it required at the type level kills the bug
 * class — TS rejects callers that try to skip the check. It is a MAP since
 * notme-0a1ee8: the token's own `iss` selects its audience, and an `iss`
 * absent from the map is untrusted.
 */
export async function verifyOIDC(
  token: string,
  audiences: IssuerAudienceMap,
): Promise<VerifiedIdentity> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("malformed JWT");

  const header = JSON.parse(
    new TextDecoder().decode(base64urlDecode(parts[0])),
  ) as { alg: string; kid?: string };
  const payload = JSON.parse(
    new TextDecoder().decode(base64urlDecode(parts[1])),
  ) as Record<string, unknown>;

  // Basic claim checks
  const iss = payload.iss as string;
  const sub = payload.sub as string;
  const exp = payload.exp as number;
  if (!iss) throw new Error("missing issuer");
  if (!sub) throw new Error("missing subject");
  if (typeof exp !== "number") throw new Error("missing exp claim");
  if (exp < Math.floor(Date.now() / 1000)) throw new Error("token expired");

  // Trust, then audience. The token's own `iss` picks its audience pin, so
  // an issuer with no pin has nothing to check against and is refused here.
  const expectedArr = expectedAudiencesFor(audiences, iss);
  if (!expectedArr) throw new Error(`untrusted issuer: ${iss}`);

  // Audience validation — always runs. Confused-deputy defense.
  const tokenAud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  const audienceOk = tokenAud.some((a: unknown) =>
    typeof a === "string" && expectedArr.includes(a),
  );
  if (!audienceOk) {
    throw new Error(
      `wrong audience: expected ${expectedArr.join(",")}, got ${tokenAud.join(",")}`,
    );
  }

  // Fetch JWKS and select the verifying key by kid (see selectVerifyingKey).
  const keys = await fetchJWKS(iss, audiences, header.kid);
  const jwk = selectVerifyingKey(keys, header.kid);
  if (!jwk) throw new Error(`unknown key id: ${header.kid ?? "<omitted>"}`);

  let cryptoKey: CryptoKey;
  if (header.alg === "RS256" && jwk.n && jwk.e) {
    cryptoKey = await crypto.subtle.importKey(
      "jwk",
      { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256" },
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
  } else if (header.alg === "ES256" && jwk.x && jwk.y) {
    cryptoKey = await crypto.subtle.importKey(
      "jwk",
      { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  } else {
    throw new Error(`unsupported alg: ${header.alg}`);
  }

  const signingInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const algParams =
    header.alg === "RS256"
      ? "RSASSA-PKCS1-v1_5"
      : { name: "ECDSA", hash: "SHA-256" };

  const valid = await crypto.subtle.verify(
    algParams,
    cryptoKey,
    base64urlDecode(parts[2]),
    signingInput,
  );
  if (!valid) throw new Error("invalid signature");

  // GitHub Actions tokens from fork-PR events buy nothing (notme-fbb00e):
  // the same rule validateGHAToken enforces, here for the routes that take a
  // GitHub token through this verifier (/cert oidc, /join, /auth/oidc/login).
  // After the signature, so the claim is GitHub-signed.
  if (iss === GHA_OIDC_ISSUER) assertGhaEventAllowed(payload.event_name);

  return {
    type: "oidc",
    issuer: iss,
    subject: sub,
    claims: payload,
  };
}

// ── X.509 verification (cert signed by known CA) ──

/**
 * Read the CA epoch a certificate was issued under, or null if it carries none.
 *
 * The extension is a DER INTEGER written by `cert-authority.ts` at OID_EPOCH.
 * Parsed here rather than trusted from elsewhere, because the epoch is the
 * value the revocation decision turns on.
 */
export function certEpoch(cert: {
  getExtension(oid: string): { value: ArrayBuffer } | null;
}): number | null {
  const ext = cert.getExtension(OID_EPOCH);
  if (!ext) return null;
  const der = new Uint8Array(ext.value);
  // DER INTEGER: 0x02 <len> <big-endian bytes>. Lengths here are single-byte;
  // an epoch needing a long-form length would be astronomically large and is
  // refused rather than mis-parsed.
  if (der.length < 3 || der[0] !== 0x02) return null;
  const len = der[1]!;
  if (len === 0 || len > 6 || der.length < 2 + len) return null;
  let n = 0;
  for (let i = 0; i < len; i++) n = n * 256 + der[2 + i]!;
  return n;
}

export async function verifyX509(
  certPem: string,
  caPublicKeyPem: string,
  /**
   * The authority's CURRENT epoch. REQUIRED, deliberately.
   *
   * A verifier that does not know the current epoch cannot make a revocation
   * decision, so it must refuse rather than skip. An optional parameter would
   * reproduce this repo's most common defect — a control that silently does
   * nothing when unwired — which is exactly how `checkRevocation` came to have
   * zero call sites while two documents claimed revocation worked.
   */
  currentEpoch: number,
): Promise<VerifiedIdentity> {
  const { X509Certificate } = await import("@peculiar/x509");
  const cert = new X509Certificate(certPem);

  // Check not expired
  if (cert.notAfter < new Date()) throw new Error("cert expired");
  if (cert.notBefore > new Date()) throw new Error("cert not yet valid");

  // Verify cert was signed by the CA — THE critical check.
  // Without this, any self-signed cert with valid dates would pass.
  const caCert = new X509Certificate(caPublicKeyPem);
  const signatureValid = await cert.verify({ publicKey: caCert.publicKey });
  if (!signatureValid) throw new Error("cert signature invalid — not signed by trusted CA");

  // ── Epoch check: the emergency revocation lever, finally wired ──
  //
  // AFTER the signature check, deliberately. Everything here interprets the
  // certificate's CONTENTS, and contents are only meaningful once the cert
  // is known to be ours. Checking the epoch first also handed an
  // unauthenticated caller an oracle: submit a forged cert with a guessed
  // epoch and the error message distinguishes a right guess from a wrong one.
  //
  // ADR-008 §418: "increment the CA epoch. All certs signed with the previous
  // epoch are immediately invalid." §420: "if cert.epoch < bundle.epoch, the
  // cert is REJECTED. The grace window (if any) is a deployment-time
  // configuration, not a protocol-level default."
  //
  // Until now OID_EPOCH was WRITTEN into every cert and READ NOWHERE, so
  // rotate() bumped a number nothing compared and the documented lever did
  // nothing (notme-77a024).
  //
  // Strict `!==`, not `<`. A cert from a FUTURE epoch is not a rotation case:
  // it is forged, or from another authority. Accepting it would let anyone who
  // could influence that field outrun every future rotation at once.
  const epoch = certEpoch(cert);
  if (epoch === null) {
    throw new Error("cert carries no epoch — cannot be checked against rotation");
  }
  if (epoch !== currentEpoch) {
    throw new Error(
      `cert epoch ${epoch} does not match authority epoch ${currentEpoch} — revoked by rotation`,
    );
  }

  // Extract subject CN
  const subject = cert.subjectName.getField("CN")?.[0] ?? cert.subject;
  const issuer = cert.issuerName.getField("CN")?.[0] ?? cert.issuer;

  return {
    type: "x509",
    issuer,
    subject,
  };
}

// ── Dispatch: verify any proof type ──

export async function verifyProof(
  proof: Proof,
  caPublicKeyPem: string | undefined,
  audiences: IssuerAudienceMap,
  /** Authority's current epoch — required for the x509 path. See verifyX509. */
  currentEpoch?: number,
): Promise<VerifiedIdentity> {
  if (proof.type === "oidc") {
    return verifyOIDC(proof.token, audiences);
  }
  if (proof.type === "x509") {
    if (!caPublicKeyPem) throw new Error("CA public key required for x509 verification");
    // `audiences` is unused here — certs don't carry an aud claim. We
    // still take it as a required argument so callers can't accidentally
    // route a token-issuing flow through this function without one.
    void audiences; // intent in IR, not just prose
    // Fail closed: a caller that did not supply the epoch cannot have its
    // certificate checked against rotation, and must not be given a pass.
    if (currentEpoch === undefined) {
      throw new Error("current epoch required for x509 verification");
    }
    if (proof.chain && proof.chain.length > 0) {
      // A tier-signed cert. The chain walker carries the three bounds a
      // single-hop check cannot: pathlen, scopes ⊆ parent, and the D5
      // namespace confinement. verifyX509 stays single-hop on purpose —
      // delegation-depth.do.test.ts pins that split.
      const { verifyCertChain } = await import("./verify-chain");
      return verifyCertChain(proof.cert, proof.chain, caPublicKeyPem, currentEpoch);
    }
    return verifyX509(proof.cert, caPublicKeyPem, currentEpoch);
  }
  // Exhaustiveness: if Proof gains a new variant, the line below fails to
  // typecheck (proof would no longer be `never` here). Runtime read covers
  // a malformed object cast through.
  const _exhaustive: never = proof;
  const seen = (_exhaustive as { type?: unknown }).type;
  throw new Error(`unknown proof type: ${String(seen)}`);
}
