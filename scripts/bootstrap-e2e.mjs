#!/usr/bin/env node
/**
 * bootstrap-e2e.mjs — prove attested first boot with a REAL GitHub OIDC token.
 *
 * Runs inside a GitHub Actions job against a locally-running Worker, because
 * that is the only place both halves exist at once: a genuine GitHub-signed
 * token, and an authority fresh enough to bootstrap.
 *
 * What the unit tests could not cover, and this does:
 *   · the token is signed by GitHub, not by a keypair this repo generated
 *   · validateGHAToken fetches the REAL JWKS over the network
 *   · the claim set is whatever GitHub actually sends today, not a fixture
 *   · `sub` is the real string, so an operator arming BOOTSTRAP_GHA_SUBJECT
 *     with the documented format is verified against reality — the ref
 *     segment is trigger-dependent and mismatching it fails SILENTLY
 *
 * Exits non-zero with a named reason on any failure. A green run means an
 * authority went from ungovernable to governed by attestation alone.
 */
import { webcrypto as crypto } from "node:crypto";

const BASE = process.env.AUTH_BASE ?? "http://localhost:8787";
const token = process.env.OIDC_TOKEN;

function fail(msg) {
  console.error(`FAIL: ${msg}`);
  process.exit(1);
}
function ok(msg) {
  console.log(`  ok  ${msg}`);
}
if (!token) fail("OIDC_TOKEN not set — the job must request an id-token");

const b64 = (buf) => Buffer.from(new Uint8Array(buf)).toString("base64");
const pem = (spki) =>
  `-----BEGIN PUBLIC KEY-----\n${b64(spki).match(/.{1,64}/g).join("\n")}\n-----END PUBLIC KEY-----`;

/** Binding = mtls_spki ‖ signing_spki ‖ SHA-256(token), signed as PRE-IMAGE. */
async function popBody() {
  const mtls = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const signing = await crypto.subtle.generateKey(
    { name: "Ed25519" }, true, ["sign", "verify"]);
  const mtlsSpki = await crypto.subtle.exportKey("spki", mtls.publicKey);
  const signingSpki = await crypto.subtle.exportKey("spki", signing.publicKey);
  const tokenHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  const binding = new Uint8Array(mtlsSpki.byteLength + signingSpki.byteLength + 32);
  binding.set(new Uint8Array(mtlsSpki), 0);
  binding.set(new Uint8Array(signingSpki), mtlsSpki.byteLength);
  binding.set(new Uint8Array(tokenHash), mtlsSpki.byteLength + signingSpki.byteLength);
  return {
    public_keys: { mtls: pem(mtlsSpki), signing: pem(signingSpki) },
    proofs: {
      mtls: b64(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, mtls.privateKey, binding)),
      signing: b64(await crypto.subtle.sign({ name: "Ed25519" }, signing.privateKey, binding)),
    },
  };
}

const sub = JSON.parse(
  Buffer.from(token.split(".")[1], "base64url").toString("utf8"),
).sub;
console.log(`\nattested subject: ${sub}\n`);

// 1. The authority must START ungovernable, or "it bootstrapped" proves nothing.
const before = await fetch(`${BASE}/auth/passkey/register/options`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: "{}",
});
const beforeBody = await before.json();
if (before.status !== 401) fail(`expected a fresh authority to refuse registration, got ${before.status}`);
if (!/no administrator/.test(beforeBody.error ?? "")) fail(`authority is not fresh: ${beforeBody.error}`);
if (!/BOOTSTRAP_GHA_SUBJECT/.test(beforeBody.error ?? "")) {
  fail(`gha-oidc is not armed — the 401 does not offer it: ${beforeBody.error}`);
}
ok("authority starts ungovernable, with attested bootstrap armed");

// 2. The real token bootstraps it.
const res = await fetch(`${BASE}/cert/gha`, {
  method: "POST",
  headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
  body: JSON.stringify(await popBody()),
});
const body = await res.json();
if (res.status !== 200) fail(`/cert/gha refused a real GitHub token: ${res.status} ${JSON.stringify(body)}`);
ok("a real GitHub-signed OIDC token was verified against the live JWKS");

if (!body.principal_id) fail("no principal_id — the token verified but bootstrap did not fire");
ok(`bootstrap created an administrator: ${body.principal_id}`);

if (JSON.stringify(body.scopes) !== JSON.stringify(["bridgeCert"])) {
  fail(`cert carries ${JSON.stringify(body.scopes)} — capabilities belong on the principal, not the cert`);
}
ok("the certificate carries bridgeCert only");

// 3. The authority must now be GOVERNED — an admin that can authenticate.
const after = await fetch(`${BASE}/auth/passkey/register/options`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: "{}",
});
const afterBody = await after.json();
if (/no administrator/.test(afterBody.error ?? "")) {
  fail("still reports no administrator — the principal was created but nothing can authenticate as it");
}
ok("the authority now reports an administrator");

// 4. Bootstrap is a one-time door.
const again = await fetch(`${BASE}/cert/gha`, {
  method: "POST",
  headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
  body: JSON.stringify(await popBody()),
});
const againBody = await again.json();
if (again.status === 200 && againBody.principal_id) {
  fail("a second run bootstrapped again — the door is not one-time");
}
ok("a second run mints no second administrator");

console.log("\nPASS: attested first boot, end to end, with a real GitHub token\n");
