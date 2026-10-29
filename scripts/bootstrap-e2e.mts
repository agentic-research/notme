/**
 * bootstrap-e2e.ts — prove first boot end to end with a REAL GitHub OIDC
 * token and a real WebAuthn ceremony (notme-486e8a; criterion E).
 *
 * Runs inside a GitHub Actions job against a locally-running Worker, because
 * that is the only place both halves exist at once: a genuine GitHub-signed
 * token, and an authority fresh enough to claim.
 *
 * What the unit tests cannot cover, and this does:
 *   · the approving token is signed by GitHub, not a keypair this repo made
 *   · validateGHAToken fetches the REAL JWKS over the network
 *   · `sub` is the real string, so BOOTSTRAP_GHA_SUBJECT armed with the
 *     documented format is checked against reality — the ref segment is
 *     trigger-dependent and a mismatch fails the claim
 *
 * REVISED from bootstrap-e2e.mjs, which asserted that /cert/gha made the
 * workflow the administrator. That was the dead end: a workflow never holds
 * a session and /invites requires one, so no human could ever get in. Now:
 *
 *   register a passkey (claim, holds nothing) → the real workflow token
 *   approves the code → sign in → that session can issue an invite.
 *
 * Exits non-zero with a named reason on any failure.
 */
import { SoftwareAuthenticator } from "../worker/src/__tests__/helpers/software-authenticator";

const BASE = process.env.AUTH_BASE ?? "http://localhost:8787";
const token = process.env.OIDC_TOKEN;
const token2 = process.env.OIDC_TOKEN_2;

function fail(msg: string): never {
  console.error(`FAIL: ${msg}`);
  process.exit(1);
}
const ok = (msg: string) => console.log(`  ok  ${msg}`);
if (!token || !token2) fail("OIDC_TOKEN and OIDC_TOKEN_2 must both be set — each jti is single-use");

const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
const cookieOf = (res: Response) => (res.headers.get("set-cookie") ?? "").split(";")[0]!;

const sub = JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString("utf8")).sub;
console.log(`\nattested subject: ${sub}\n`);

const auth = await SoftwareAuthenticator.create(new URL(BASE).hostname, BASE);

// 1. A fresh authority accepts an unauthenticated registration — as a CLAIM.
const opts = await post("/auth/passkey/register/options", {});
const o = (await opts.json()) as { userId: string; options: { challenge: string }; claim?: boolean; error?: string };
if (opts.status !== 200 || !o.claim) fail(`fresh authority did not offer a claim: ${opts.status} ${JSON.stringify(o)}`);
ok("fresh authority offers a claim registration");

const verify = await post("/auth/passkey/register/verify", {
  userId: o.userId,
  response: await auth.register(o.options.challenge),
});
const v = (await verify.json()) as { scopes: string[]; claim?: { code: string } };
if (verify.status !== 200 || !v.claim?.code) fail(`registration produced no claim code: ${verify.status} ${JSON.stringify(v)}`);
if (v.scopes.length !== 0) fail(`a claim must hold nothing before approval, got ${JSON.stringify(v.scopes)}`);
ok(`passkey registered as claim ${v.claim.code}, holding nothing`);

// 2. The REAL workflow token approves it.
const approve = await post("/bootstrap/claim", { code: v.claim.code }, { authorization: `Bearer ${token}` });
const a = (await approve.json()) as { principal_id?: string; error?: string };
if (approve.status !== 200) fail(`the real GitHub token did not approve the claim: ${approve.status} ${JSON.stringify(a)}`);
if (a.principal_id !== o.userId) fail(`approved the wrong principal: ${a.principal_id} vs ${o.userId}`);
ok("a real GitHub-signed token approved the claim");

// 3. Signing in with that passkey yields a session that can administer.
const lo = await post("/auth/passkey/login/options", {});
const { challenge } = (await lo.json()) as { challenge: string };
const lv = await post("/auth/passkey/login/verify", { response: await auth.authenticate(challenge) });
if (lv.status !== 200) fail(`sign-in after approval failed: ${lv.status}`);
const invite = await post("/invites", { scopes: ["bridgeCert"] }, { cookie: cookieOf(lv) });
if (invite.status !== 200) fail(`the approved administrator cannot issue an invite: ${invite.status}`);
ok("the approved passkey signs in as an administrator and issues an invite");

// 4. The door is shut: registration is invite-only and approval is refused.
const again = await post("/auth/passkey/register/options", {});
if (again.status !== 403) fail(`registration should be invite-only once claimed, got ${again.status}`);
const twice = await post("/bootstrap/claim", { code: v.claim.code }, { authorization: `Bearer ${token2}` });
if (twice.status !== 409) fail(`a second approval should be refused as governed, got ${twice.status}`);
ok("claimed once: registration is invite-only and a second approval is refused");

console.log("\nPASS: fresh → claimed by a passkey, approved by the attested workflow, administrable.\n");
