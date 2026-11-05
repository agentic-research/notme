/**
 * Session-cookie verification that does not cost the SigningAuthority a call
 * for a cookie that is going to be refused (notme-a34dad, overnight review C2).
 *
 * Every cookie route used to read `authority.getSessionSecret()` BEFORE it
 * looked at the cookie, so any value in `notme_session` ("x" will do) bought a
 * billed RPC on the one Durable Object that serialises issuance. Past its
 * soft limit that object returns overloaded errors and the whole authority is
 * down. This module makes the refusal local:
 *
 *  1. SHAPE first. A cookie that cannot be a session — not `payload.sig`, not
 *     base64url, a signature that is not 32 bytes, a payload that is not a
 *     JSON object with a finite, unexpired `exp` — is refused with no secret
 *     at all, so not even a cold isolate pays for it. Each of these is a
 *     refusal verifySessionCookie would also make, so no valid cookie is lost.
 *  2. HMAC against an ISOLATE-CACHED secret. The secret is held for
 *     SESSION_SECRET_TTL_MS; when it is missing or older, ONE fetch refreshes
 *     it and every concurrent caller waits on that same promise. A cookie
 *     whose HMAC fails is refused here, before any DO call.
 *  3. A cookie that PASSES against a cached secret is confirmed against the
 *     live one before it is believed. resetPasskeyData rotates the secret to
 *     revoke every outstanding cookie (bootstrap-code.do.test.ts), and a TTL
 *     cache alone would turn that revocation into a grace period as long as
 *     the TTL in every warm isolate. Only a correctly signed cookie gets this
 *     far, so the confirmation is the one secret read the route always made —
 *     a valid session costs exactly what it did before; junk costs nothing.
 *
 * Grant liveness is unchanged and is not this module's job: routes still read
 * the grant store through `liveScopes` for every authority decision.
 *
 * What the cache CAN delay: a cookie minted under a NEW secret, presented to
 * an isolate that cached the old one in the TTL before a reset, is refused
 * (as a junk cookie would be) until that isolate's entry expires. That is a
 * false negative of at most SESSION_SECRET_TTL_MS after a rare, deliberate
 * admin action, and the isolate that mints refreshes its own entry
 * (`liveSessionSecret`). Refetching on a failed HMAC would close the window
 * and reopen the flood, so it is not done.
 *
 * `limit` is the caller's limiter, keyed by WHO the cookie proved to be. It
 * runs once, only after the HMAC has passed, and before the liveness
 * confirmation, so junk never reaches it and a limited session costs no RPC.
 * (On a cold isolate the secret fetch comes first, because there is nothing
 * to check the HMAC against without it; that fetch is single-flight and
 * cached for the TTL, so it is bounded per isolate whatever the request
 * rate, and needs no limiter of its own.)
 */
import { decodeBase64url } from "@oslojs/encoding";
import { type SessionPayload, verifySessionCookie } from "./session";

/** How long an isolate trusts its copy of the secret for a NEGATIVE answer. */
export const SESSION_SECRET_TTL_MS = 30_000;

/**
 * SESSION_LIMITER's rate: requests per PRINCIPAL per 60 s (wrangler.toml.example,
 * and the test pool, which binds it at this number).
 *
 * Sized from the routes, not guessed. Every same-origin page and flow that
 * presents the cookie, counted from worker.ts and public/*.html:
 *   - /me: 1. The invites page (public/_invite.html): GET /invites, then 1
 *     per invite created or revoked.
 *   - An OAuth /authorize round trip: GET /authorize, then the page's one
 *     POST to /authorize/code or /authorize/token, so 2.
 *   - A bridge-pair mint: POST /cert/nonce, then POST /cert/passkey, so 2.
 *     POST /cert with a session proof: 1.
 *   - A device enrolment approval: GET /enroll, POST .../device/approve,
 *     then GET .../enrollments to see it, so 3.
 *   - Admin reads: /admin/alarm-health, /auth/passkey/status, /connections: 1 each.
 * No page polls a cookie route (the 5 s enrolment poll is
 * /cert/issuing-ca/device/token, which carries no cookie). So one flow is at
 * most 3, and an admin clicking through EVERYTHING in one minute is about
 * 15 (the dashboard-burst test replays that minute). 60 is four times that,
 * room for a CLI minting about 30 pairs a minute. It holds one hammering
 * session to 1 request/s of DO work, which is about a thousandth of the
 * singleton's soft limit.
 *
 * NO per-IP backstop. Its job was junk, and junk no longer reaches the DO.
 * Every request this limiter sees carries a cookie the authority signed, so
 * the attacker's unit of cost is a SESSION, and sessions are not free: they
 * come from a passkey login (PASSKEY_LIMITER, 5/min per IP), an invite (an
 * admin's act), an OIDC or bootstrap proof. Keying by IP would only re-create
 * the NAT problem this replaced (two admins behind one address sharing 20/min).
 */
export const SESSION_LIMIT_PER_MINUTE = 60;

/** HMAC-SHA256, the only signature session.ts produces. */
const SIG_BYTES = 32;

type SecretSource = { getSessionSecret(): Promise<string> };

type Entry = { secret: string; fetchedAt: number };

let cached: Entry | null = null;
let inflight: Promise<Entry> | null = null;

function store(e: Entry): void {
  // A slow fetch that started before a newer one finished must not overwrite
  // it with what may be a pre-rotation secret.
  if (!cached || e.fetchedAt >= cached.fetchedAt) cached = e;
}

/** One fetch at a time per isolate; concurrent callers share its result. */
function refresh(authority: SecretSource): Promise<Entry> {
  if (inflight) return inflight;
  const p = (async () => {
    const startedAt = Date.now();
    const secret = await authority.getSessionSecret();
    const e = { secret, fetchedAt: startedAt };
    store(e);
    return e;
  })();
  inflight = p;
  // Cleared on failure too, so one failed fetch is not cached as a rejection.
  p.then(
    () => { if (inflight === p) inflight = null; },
    () => { if (inflight === p) inflight = null; },
  );
  return p;
}

/**
 * The live secret, read from the DO, and recorded as this isolate's copy. For
 * the paths that MINT a cookie or derive a MAC key: those must use the
 * current secret, and reading it is a chance to refresh the cache for free.
 */
export async function liveSessionSecret(authority: SecretSource): Promise<string> {
  const startedAt = Date.now();
  const secret = await authority.getSessionSecret();
  store({ secret, fetchedAt: startedAt });
  return secret;
}

/** Forget this isolate's copy — after a reset this isolate performed. */
export function invalidateSessionSecret(): void {
  cached = null;
}

/** For tests only: a cold isolate. */
export function __resetSessionSecretCacheForTests(): void {
  cached = null;
  inflight = null;
}

/**
 * Could this string be a session cookie at all? Every `false` here is a
 * refusal verifySessionCookie would also make; it is checked first only
 * because it needs no secret.
 */
export function couldBeSessionCookie(cookie: string, nowSeconds = Math.floor(Date.now() / 1000)): boolean {
  const parts = cookie.split(".");
  if (parts.length !== 2) return false;
  let payloadBytes: Uint8Array;
  let sig: Uint8Array;
  try {
    payloadBytes = decodeBase64url(parts[0]!);
    sig = decodeBase64url(parts[1]!);
  } catch {
    return false;
  }
  if (sig.length !== SIG_BYTES) return false;
  let payload: unknown;
  try {
    payload = JSON.parse(new TextDecoder().decode(payloadBytes));
  } catch {
    return false;
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) return false;
  const exp = (payload as { exp?: unknown }).exp;
  return typeof exp === "number" && Number.isFinite(exp) && exp >= nowSeconds;
}

type RateLimitBinding = { limit(opts: { key: string }): Promise<{ success: boolean }> };

/**
 * The cookie-route limiter: SESSION_LIMITER, its own binding (TOKEN_LIMITER's
 * 20/min is /token's budget, keyed by the same principals), keyed
 * `session:<principalId>` — the principal the HMAC proved, which a forger
 * cannot choose. No binding (local workerd) means no limit, as at every
 * other limiter site.
 */
export function sessionLimiter(env: { SESSION_LIMITER?: RateLimitBinding }): (s: SessionPayload) => Promise<boolean> {
  return async (session) => {
    if (!env.SESSION_LIMITER) return true;
    const { success } = await env.SESSION_LIMITER.limit({ key: `session:${session.principalId}` });
    return success;
  };
}

export type SessionCheck =
  | { ok: true; session: SessionPayload; secret: string }
  | { ok: false; limited: boolean };

const REFUSED: SessionCheck = { ok: false, limited: false };
const LIMITED: SessionCheck = { ok: false, limited: true };

/**
 * Verify a `notme_session` value. On success, `secret` is the LIVE session
 * secret (a route that derives a MAC key from it, like /token's DPoP nonce,
 * may use it without a second read).
 */
export async function verifySessionCached(
  cookie: string,
  authority: SecretSource,
  limit?: (session: SessionPayload) => Promise<boolean>,
): Promise<SessionCheck> {
  if (!couldBeSessionCookie(cookie)) return REFUSED;

  const startedAt = Date.now();
  let entry = cached && startedAt - cached.fetchedAt < SESSION_SECRET_TTL_MS && startedAt >= cached.fetchedAt
    ? cached
    : null;
  let fresh = false;
  if (!entry) {
    entry = await refresh(authority);
    fresh = true;
  }

  const session = await verifySessionCookie(cookie, entry.secret);
  if (!session) return REFUSED;
  // Signed by us, so the principal is real: only now is there an identity to
  // charge, and only now can a DO call follow.
  if (limit && !(await limit(session))) return LIMITED;
  if (fresh) return { ok: true, session, secret: entry.secret };

  // Correctly signed under a cached secret: confirm it is still THE secret.
  const live = await liveSessionSecret(authority);
  if (live === entry.secret) return { ok: true, session, secret: live };
  const reverified = await verifySessionCookie(cookie, live);
  return reverified ? { ok: true, session: reverified, secret: live } : REFUSED;
}
