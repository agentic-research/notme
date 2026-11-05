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
 * `limit` is the caller's limiter, keyed by the SESSION the cookie proved and
 * then its principal (sessionLimiter). It runs once, only after the HMAC has
 * passed, and before the liveness confirmation, so junk never reaches it and
 * a limited session costs no RPC.
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
 * SESSION_LIMITER's rate: requests per SESSION (one issued cookie) per 60 s,
 * PER CLOUDFLARE LOCATION (wrangler.toml.example, and the test pool, which
 * binds it at this number).
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
 * room for a CLI minting about 30 pairs a minute.
 *
 * THE BOUND IS PER LOCATION, NOT GLOBAL. Cloudflare's Workers rate limiting
 * binding (https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/):
 * "Rate limits are approximate and apply separately in each Cloudflare
 * location", "Requests served in another Cloudflare location count toward a
 * separate limit, even with the same namespace and key", "These counts do not
 * combine into one worldwide limit", and "If you need one strict limit
 * across all locations, implement a rate limiter with Durable Objects." So
 * one session spread over proxies in N locations gets about 60·N per minute,
 * that is about N/60 requests/s of DO work: one location is 1 rps, and all of
 * Cloudflare's (some 300) is about 300 rps per session — a few sessions'
 * worth reaches the singleton's soft limit. The documented strict
 * alternative is a DO-backed counter, which costs a DO call on every request:
 * the very call this limiter exists to keep off the singleton, so it is not
 * used. The bound is documented instead (THREAT_MODEL §8), and what keeps it
 * from being free is that every unit of it needs a session.
 *
 * NO per-IP backstop. Its job was junk, and junk no longer reaches the DO.
 * Every request this limiter sees carries a cookie the authority signed, so
 * the attacker's unit of cost is a SESSION, and sessions are not free: they
 * come from a passkey login (PASSKEY_LIMITER, 5/min per IP), an invite (an
 * admin's act), an OIDC or bootstrap proof. Keying by IP would only re-create
 * the NAT problem this replaced (two admins behind one address sharing 20/min).
 */
export const SESSION_LIMIT_PER_MINUTE = 60;

/**
 * PRINCIPAL_LIMITER's rate: requests per PRINCIPAL per 60 s, per location —
 * the aggregate over all its sessions, so minting many sessions does not
 * multiply a principal's budget. Five sessions' worth: an admin with a
 * laptop, a phone, a CLI and a linked CI workflow all busy at once fits.
 * Because the session key is checked first, one session (a stolen cookie
 * included) can spend at most SESSION_LIMIT_PER_MINUTE of it, so no single
 * session can lock its principal's other sessions out (review L4).
 */
export const PRINCIPAL_LIMIT_PER_MINUTE = 300;

/** HMAC-SHA256, the only signature session.ts produces. */
const SIG_BYTES = 32;

type SecretSource = { getSessionSecret(): Promise<string> };

/**
 * `seq` orders fetches by when they STARTED (Date.now() does not: in workerd
 * it only advances across I/O, so two events in one tick share a time). A
 * verification is "fresh" only if its secret came from a fetch that started
 * after the verification did; one that joined an earlier fetch may hold a
 * pre-reset secret, so it is confirmed live (review L3).
 */
type Entry = { secret: string; fetchedAt: number; seq: number };

let cached: Entry | null = null;
let inflight: Promise<Entry> | null = null;
let fetchSeq = 0;
/**
 * Bumped by invalidateSessionSecret. A fetch records the generation it began
 * in and is not cached if that has moved on, so a fetch in flight across this
 * isolate's own reset can never re-cache the pre-reset secret.
 */
let generation = 0;

function store(e: Entry, gen: number): void {
  if (gen !== generation) return;
  // A slow fetch that started before a newer one finished must not overwrite
  // it with what may be a pre-rotation secret.
  if (!cached || e.seq >= cached.seq) cached = e;
}

/** One fetch at a time per isolate; concurrent callers share its result. */
function refresh(authority: SecretSource): Promise<Entry> {
  if (inflight) return inflight;
  const gen = generation;
  const seq = ++fetchSeq;
  const p = (async () => {
    const startedAt = Date.now();
    const secret = await authority.getSessionSecret();
    const e = { secret, fetchedAt: startedAt, seq };
    store(e, gen);
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
  const gen = generation;
  const seq = ++fetchSeq;
  const startedAt = Date.now();
  const secret = await authority.getSessionSecret();
  store({ secret, fetchedAt: startedAt, seq }, gen);
  return secret;
}

/**
 * Forget this isolate's copy, and abandon any fetch in flight — after a reset
 * this isolate performed. Later requests start a new fetch rather than join
 * one that may have read the pre-reset secret, and that fetch's result is
 * not cached when it lands.
 */
export function invalidateSessionSecret(): void {
  generation++;
  cached = null;
  inflight = null;
}

/** For tests only: a cold isolate. */
export function __resetSessionSecretCacheForTests(): void {
  generation++;
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
 * The cookie-route limiter, after a valid HMAC, in two keys (review L4):
 *  1. SESSION_LIMITER, `session:<the cookie's MAC>` — the one issued cookie.
 *     The MAC is unforgeable and unique per issued cookie, and naming the
 *     session rather than the principal means one session hammering (a
 *     stolen cookie, a runaway CLI, a CI workflow linked to an admin) spends
 *     its own budget, never the principal's other sessions'.
 *  2. PRINCIPAL_LIMITER, `principal:<principalId>` — the aggregate, so many
 *     sessions do not multiply one principal's budget. Charged only once the
 *     session key admitted the request, so one session can spend at most
 *     SESSION_LIMIT_PER_MINUTE of it.
 *
 * WHY BEFORE THE LIVE CONFIRMATION, not after it. After would mean the
 * confirmation's getSessionSecret, the DO call this limiter exists to
 * protect, ran unthrottled for every correctly signed cookie. The cost of
 * before is that a cookie a reset revoked can still be charged — and that
 * cost is one request per isolate: the confirmation stores the live secret,
 * so every later use of the revoked cookie fails the local HMAC and is never
 * charged (session-cookie-amplification.do.test.ts). Keying by session makes
 * even that one charge land on the revoked session, not on its principal's
 * live ones.
 *
 * Their own bindings: TOKEN_LIMITER's 20/min is /token's budget. No binding
 * (local workerd) means no limit, as at every other limiter site.
 */
export function sessionLimiter(env: {
  SESSION_LIMITER?: RateLimitBinding;
  PRINCIPAL_LIMITER?: RateLimitBinding;
}): (s: SessionPayload, sessionId: string) => Promise<boolean> {
  return async (session, sessionId) => {
    if (env.SESSION_LIMITER) {
      const { success } = await env.SESSION_LIMITER.limit({ key: `session:${sessionId}` });
      if (!success) return false;
    }
    if (env.PRINCIPAL_LIMITER) {
      const { success } = await env.PRINCIPAL_LIMITER.limit({ key: `principal:${session.principalId}` });
      if (!success) return false;
    }
    return true;
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
  limit?: (session: SessionPayload, sessionId: string) => Promise<boolean>,
): Promise<SessionCheck> {
  if (!couldBeSessionCookie(cookie)) return REFUSED;

  const startedAt = Date.now();
  const seqAtStart = fetchSeq;
  let entry = cached && startedAt - cached.fetchedAt < SESSION_SECRET_TTL_MS && startedAt >= cached.fetchedAt
    ? cached
    : await refresh(authority);
  // Fresh only if the fetch began after this verification did (review L3).
  // Joining a fetch already in flight is not fresh: it may predate a reset.
  const fresh = entry.seq > seqAtStart;

  const session = await verifySessionCookie(cookie, entry.secret);
  if (!session) return REFUSED;
  // Signed by us, so the session and its principal are real: only now is
  // there an identity to charge, and only now can a DO call follow.
  if (limit && !(await limit(session, cookie.split(".")[1]!))) return LIMITED;
  if (fresh) return { ok: true, session, secret: entry.secret };

  // Correctly signed under a cached secret: confirm it is still THE secret.
  const live = await liveSessionSecret(authority);
  if (live === entry.secret) return { ok: true, session, secret: live };
  const reverified = await verifySessionCookie(cookie, live);
  return reverified ? { ok: true, session: reverified, secret: live } : REFUSED;
}
