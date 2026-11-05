# Pre-deploy cost estimate (2026-11-03)

Tracked: rig-ed460e (WAF spend guard never applied; gates deploy), notme-ed6114 (unthrottled DO paths; gates deploy), CT-log cost decisions on notme-1b46a8. Prices are from the Cloudflare pages cited below as fetched on 2026-11-03; line numbers as of goalzero 90297b7.

**Status (2026-11-03, after notme-ed6114 merged in d3a0814 and the CT cost decisions in 89d459d):** the notme-side items below are done. `/token` checks a limit before the Durable Object (0cdde59; this line used to say EVERY unauthenticated path did, which was wrong, see the correction below), `/.well-known/*` cache keys ignore the query string (bfbcb24), `jwks.json` and `ca-bundle.pem` are `max-age=300` (728aca2, `worker/worker.ts:1951`), and the CT shard config is `sequence_interval_millis` 750 with `max_sequence_skips` 1 (`ct/config.notme.json:25-26`). rig-ed460e (the WAF ruleset) and the billing alerts are outside this repo and remain owner actions. The estimate below is as written before those fixes.

**Correction (2026-11-04, notme-a34dad):** the sentence "Every unauthenticated path checks a limit before the Durable Object" was false when written. The 2026-11-04 overnight review found it on goalzero dff01a8, and it was re-verified against the tree before fixing:
- **Junk session cookie (review C2).** Only `/token` limited before the DO. Every other cookie route read `getSessionSecret()` on the singleton for any `notme_session` value, with no limiter. That covered `/me`, `/connections`, `/invites`, `/principals/:id/revoke`, `/admin/*`, `/auth/passkey/status`, `/cert`, `/cert/nonce`, `/cert/passkey`, `/enroll`, `/cert/issuing-ca*` and `/authorize*`.
  - Fixed: junk is refused in the Worker with no DO call. The cookie shape is checked first, then the HMAC against an isolate-cached secret (30 s TTL, single-flight refresh).
  - The one DO call that remains is for a correctly signed cookie (the live-secret confirmation) or a cold isolate. A per-IP `session-ip:` limiter on `TOKEN_LIMITER` runs before it. Test: `worker/src/session-cookie-amplification.do.test.ts`.
- **`/internal/ca-bundle` (M1).** It was public and unlimited, with one KV read per request, and a herd of `generateBundle()` calls when the bundle was stale.
  - Fixed: it is served from the edge and from an isolate copy for at most 30 s, and never past the bundle's 300 s. A refresh is single-flight per isolate, and `no-cache` reads are per-IP limited.
- **Cache error latch and uncached 503s (M3).** Fixed with backoff and recovery, plus a 5 s negative cache for DO-backed public documents.
- **Unmatched auth-host paths proxied to signet (M4).** Fixed: closed by default behind an exact-path allowlist (`SIGNET_PASSTHROUGH_PATHS`), with per-IP limits.

**Still NOT limited before the DO, as of this correction** (out of notme-a34dad's scope, recorded so the claim is not repeated):
- `POST /auth/passkey/reset` (`consumeBootstrapCode` on any body)
- `POST /authorize/redeem` (`redeemAuthorizationCode` once the body is well-formed)
- `POST /cert/issuing-ca/device` and `/cert/issuing-ca/device/token` (enrolment start and collect; review H1, notme-a36d10)

The stress scenario below ("/cert/nonce with a junk cookie") describes the pre-fix tree.


Month = 30 d = 2,592,000 s. Prices fetched today.

## Pricing (cited)
- Workers Paid, https://developers.cloudflare.com/workers/platform/pricing/ : $5/mo minimum; 10M requests incl, then $0.30/M; 30M CPU-ms incl, then $0.02/M CPU-ms; duration not billed; subrequests not billed; service-binding calls add no request fee (one request for the initial invocation + CPU of both Workers); static assets free UNLESS the Worker runs first (wrangler.toml has run_worker_first = true, so page loads bill as Worker requests). Workers Logs: 20M events incl, $0.60/M after.
- Durable Objects, https://developers.cloudflare.com/durable-objects/platform/pricing/ : 1M requests incl, $0.15/M; 400,000 GB-s incl, $12.50/M GB-s; SQLite rows read 25B incl, $0.001/M; rows written 50M incl, $1.00/M; stored 5 GB-mo incl, $0.20/GB-mo. Each alarm fire = 1 request; each setAlarm() = 1 row written; EACH RPC method call on a stub = 1 request (own session).
- R2, https://developers.cloudflare.com/r2/pricing/ : $0.015/GB-mo (10 GB free); Class A $4.50/M (1M free); Class B $0.36/M (10M free); egress free.
- KV, https://developers.cloudflare.com/kv/platform/pricing/ : 10M reads incl, $0.50/M; 1M writes incl, $5.00/M; 1M deletes/lists incl; 1 GB incl.
- WAF rate limiting, https://developers.cloudflare.com/waf/rate-limiting-rules/ : Free = 1 rule, 10 s period, 10 s mitigation timeout, IP only, expression fields Path + Verified Bot only (no Host). Pro = 2 rules, <=1 min, <=1 h timeout, Host/URI/Path/Query. Page does not state a charge for Free rate limiting.
- Notifications: https://developers.cloudflare.com/notifications/notification-available/ : "Usage Based Billing" alert (Alerts > Platform Notifications > Create), pay-as-you-go accounts, "Professional plans or higher"; page does not list Workers/DO products explicitly. WfP pricing page URL 404'd; the account WfP sub is a separate base fee, not modeled (rig spec says cancel is safe).
- Workers Rate Limiting bindings (TOKEN/CERT/PASSKEY_LIMITER in wrangler.toml.example) are not metered on the Workers pricing page.

## Usage derived from code
Alarm (worker/src/signing-authority.ts): BUNDLE_REFRESH_MS = 4 min (:288). alarm() :4421 -> #publishBundle (generateBundle + 1 KV put "bundle:current") + alarm_health writes + re-arm via setAlarm (:4540). Per fire: ~3 rows written (state seqno UPDATE, alarm_health UPDATE, setAlarm), ~6 read, 1 KV write. Re-arm happens only after a completed fire; after 5 consecutive failures the breaker stops re-arming (:317, :4521-4531) -> a failing alarm does NOT run away. Fires/mo = 15*24*30 = 10,800.
CT drain (only if CT_LOG bound): <=20 rows/fire, 4 concurrent (:2032-2035), 2 s timeout each, errors swallowed (:4489-4495). Worst case 20 service-binding calls + 20 UPDATEs per fire = 216,000 calls + 216,000 rows written/mo (~$0 on notme side). Rows past 24 attempts retried 1/24h forever; ct_backlog rows are never deleted (no DELETE FROM ct_backlog anywhere).

Per operation (CT unbound; W = Worker requests, D = DO RPC requests billed, R/Wr = SQL rows read/written approx):
- Bridge pair mint (passkey session): /cert/nonce (W1, D2: getSessionSecret, issuePopNonce) + /cert/passkey (W1, D4: getSessionSecret, consumePopNonce, getPrincipalScopes, mintBridgeCertPair; getAuthorityState is internal, not billed). Total W2, D6, ~10 R, ~3 Wr. CT bound adds 2 add-pre-chain service-binding calls (one per cert; final chain is NOT submitted on the happy path, only via backlog add-chain on failure), up to 2 s wall in the DO.
- Tier enrolment: start (W1,D1), /enroll GET (W1,D2), approve (W1,D~3), collect polls every 5 s (interval:5, worker.ts ~3075) ~10 polls (W1,D1 each), ~W14, D16, ~25 R, ~5 Wr.
- Tier renewal (hourly/machine): /cert/issuing-ca/renew W1, D1 (renewTier does state/scope/mint internally), ~10 R, ~3 Wr (generation UPDATE, digest INSERT).
- Task cert: no worker route mints it; the Issuing CA tier key (CA=true) signs on the machine (worker.ts:3017). Server cost = 0 (no request, no DO, no KV). Verified by absence of any route and by the comment.
- /token: W1; D3 (getSessionSecret, getPrincipalScopes, mintDPoPTokenOnce; GHA exchange: D2); KV 1 read + 1 write (jti replay cache); ~5 R, ~3 Wr; TOKEN_LIMITER binding is checked AFTER the getSessionSecret DO call (worker.ts:3935 vs :3960).
- Passkey login: options (W1,D1,1 Wr) + verify (W1,D3: verify, getSessionSecret, ensurePasskeyPrincipal) = W2, D4.
- Hot read path: every cookie-authed request calls getSessionSecret (27 call sites in worker.ts) = 1 billed DO request + CREATE TABLE IF NOT EXISTS + 1 SELECT each (signing-authority.ts:3463). Secret is never cached in the Worker isolate.
- /.well-known/*: Cache API (caches.default; free, per-colo, no billing). Miss -> 1 DO call. epochs.json max-age 60, jwks 3600, ca-bundle.pem 3600. cacheKey keeps the caller's query string (src/cache-key.ts:38), so ?x=<random> is always a miss.
- KV: only CA_BUNDLE_CACHE: 10,800 bundle writes/mo (alarm) + per-/token jti get/put + public bundle reads. Far under allowances.

CT log (azul ct_worker, ../azul/crates/ct_worker/wrangler.jsonc + generic_log_worker): Sequencer DO re-arms its alarm every sequence_interval (default 1000 ms; dev config 750 ms) unconditionally (sequencer_do.rs:181). With max_sequence_skips = 0 (default) take() returns Some(empty) every tick (log_ops.rs:212) so EVERY tick signs and uploads a new checkpoint to R2 even with no entries. Idle = 2,592,000 alarm requests + 2,592,000 R2 Class A PUTs + ~3 DO rows written/tick (7.8M) + DO resident all month (128 MB x 2.592M s = 331,776 GB-s). Dev config (750 ms, skips 1) = 3.456M alarms, 1.728M checkpoint PUTs. Cleaner DO alarm every 60 s (+43,200 req). Daily cron for roots. Per submission: frontend W1 (service binding, no extra fee), KV dedup read ~2 + write 1, Batcher+Sequencer DO ~2 requests, ~2-3 R2 Class A (data tile + L0 hash tile). Prod config (sequence_interval / skips) is not in the repo; defaults assumed.

## Scenarios per month (CT unbound unless noted)
### Idle (alarms only)
- DO requests 10,800 (1M incl). Rows written 32,400; read ~65k. KV writes 10,800. Worker requests 0. CPU ~10,800 x 5 ms = 54k ms. Duration: 0.1 s..10 s resident x 0.128 GB x 10,800 = 138..13,824 GB-s (400k incl).
- Overage $0. TOTAL = $5.00. Driver: the $5 base.
- With CT_LOG bound and a self-hosted log in the same account: R2 Class A (2.592M + 43k - 1M free) x $4.50 = $7.36; DO requests (2.592M + 43k + 10.8k - 1M) x $0.15 = $0.25; GB-s 331,776 + <=13.8k < 400k = $0; => ~$12.6 (dev-config log: ~$8.9). Driver: sequencer empty-checkpoint PUTs.

### Light (1 operator, 5 machines hourly, 200 mints/d, 50 enrolments/d (assumed per day), 200 /token/d, ~1 login/d, 10k well-known hits, 1k UI hits)
- Worker requests: mints 6,000x2 = 12,000; renewals 3,600; enrolments 1,500x14 = 21,000; /token 6,000; login 60; well-known 10,000; UI 1,000 = 53,660 (10M incl) -> $0.
- DO requests: alarms 10,800; mints 36,000; renewals 3,600; enrolments 24,000; /token 18,000; login 120; well-known misses ~5,000; UI 1,000 = 98,520 (1M incl) -> $0.
- Rows written ~87k, read ~250k; KV writes ~16.8k, reads ~6k+; CPU ~0.3M ms (30M incl); GB-s <=126k worst case (400k incl).
- TOTAL = $5.00. Driver: base fee (usage is ~0.5% of Worker and ~10% of DO request allowances).
- With CT_LOG bound + own log: notme side still $0 overage (17,100 add-pre-chain calls are free subrequests); log side idle $7.36 + $0.25 + submissions (~17,100 x 3 Class A = 51k x $4.50/M = $0.23) => ~$12.9-13.5. Driver: idle checkpoint PUTs, not users.

### Stress (one abusive IP held just under the WAF block threshold: spec default 100 req/10 s = 10 rps; tofu var value not read)
- Best DO-touching, un-limited machine path, e.g. /cert/nonce with a junk cookie: W 25.92M, D 25.92M (1 getSessionSecret each).
- Worker: (25.92M + 0.05M - 10M) x $0.30/M = $4.79. DO requests: (25.92M + 0.1M - 1M) x $0.15/M = $3.75. CPU ~2 ms x 25.9M = 51.8M ms - 30M = 21.8M x $0.02/M = $0.44. Rows read ~26M (<25B). GB-s ~331,776 + light 126k worst = ~458k -> <= $0.73, probably $0.
- TOTAL ~ $14 (up to ~$15) for ONE IP. Each extra IP at threshold adds ~$9/mo (~$0.49 per million requests); 100 IPs ~ $900/mo. Driver: Worker requests + per-request DO RPC on getSessionSecret.
- Browser paths (/auth/passkey/*, /me, ...) hit the 20/10 s challenge tier first, and PASSKEY_LIMITER caps login options at 5/min/IP before the DO, so machine paths are the worst case.
- NOT covered by the WAF at all: /token, /authorize*, /bootstrap/claim, /enroll, /.well-known/* (cache-busted). ~$0.49/M requests with no ceiling except the single DO's throughput (idFromName("default"), single-threaded): 1,000 rps ~ 2.6B req/mo ~ $1.3k.

## Risks / scale-badly
1. WAF ruleset as written is not valid on a Free zone: 2 rules (Free = 1), mitigation_timeout 60 (Free = 10 s fixed), expressions use http.host (Free = Path/Verified Bot only) - rig/tofu/modules/cloudflare/notme_waf.tf:35,49-69. It will likely be rejected at apply, leaving NO edge spend guard (or needs Pro, 2 rules). Also the WAF covers only /auth/passkey, /join, /connections, /invites, /me, /cert*, /auth/oidc/login.
2. Unauthenticated per-request DO calls before any limit: /token calls getSessionSecret before TOKEN_LIMITER (worker.ts:3935 -> :3960); getSessionSecret does CREATE TABLE IF NOT EXISTS + SELECT per call (signing-authority.ts:3463) and is uncached in the Worker; /.well-known/jwks.json etc. cache key keeps query string so ?x=rand bypasses the Cache API to the DO (src/cache-key.ts:38, worker.ts:4133). Both uncapped and un-WAFed; also serialise through the single DO.
3. CT: azul sequencer alarm every 1 s forever + empty checkpoint PUT per tick (generic_log_worker sequencer_do.rs:181, log_ops.rs:212) = ~2.6M R2 Class A/mo (~$7.4) and a DO resident 24x7 (~332k of the 400k GB-s) even with zero users; notme side ct_backlog never pruned and rows retried every 24 h indefinitely (signing-authority.ts:2032-2160).
Minor: alarm itself is safe (breaker, getAlarm check, no re-arm after 5 failures), but breaker-open means bundle goes stale (>5 min) - outage, not cost. passkey_challenges 'authentication' rows are never deleted (storage growth, tiny $). observability invocation_logs on: 20M events incl.

## Pre-deploy actions
- Set Usage Based Billing notifications (Alerts > Platform Notifications; check Workers requests + DO requests/duration are selectable; may need a plan that offers it) at ~$10 and ~$25; set a Cloudflare billing/budget alert too. No hard spend cap exists on Workers Paid.
- Fix the WAF for Free (1 path-only rule, 10 s timeout) or move zone to Pro; confirm the applied thresholds.
- Add /token, /authorize*, /bootstrap/claim, /.well-known/* to edge protection; in code add a pre-DO limiter and strip/ignore query strings in cacheKey for /.well-known.
- Keep CT_LOG unbound until a sequence_interval/max_sequence_skips and account for the log are decided (or raise interval to >=5-10 s, skips >=1 to cut checkpoint PUTs).
- Verify alarm cadence post-deploy via /admin/alarm-health (driftRatio ~1).

