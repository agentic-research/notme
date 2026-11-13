// Local end-to-end smoke test of a built action bundle.
// Stubs the GHA OIDC token endpoint and the authority's POST /cert/gha,
// VERIFIES both PoP proofs over the binding pre-image, then runs the bundle
// as a child process the way the runner does (INPUT_* env + GITHUB_OUTPUT)
// and checks the outputs it wrote.
// Usage: node action/scripts/smoke.mjs [path/to/dist/index.js]  (default: action/dist/index.js)
import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { webcrypto as wc, createHash } from "node:crypto";

const bundle = process.argv[2] ?? new URL("../dist/index.js", import.meta.url).pathname;
const JWT = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJyZXBvOngvejpyZWY6cmVmcy9oZWFkcy9tYWluIn0.";
const seen = { oidc: 0, cert: 0, audience: null, authz: null, proofsOk: false };

function pemToDer(pem) {
  return Buffer.from(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  if (req.method === "GET" && url.pathname === "/oidc") {
    seen.oidc++;
    seen.audience = url.searchParams.get("audience");
    if (req.headers.authorization !== "Bearer runner-token") { res.writeHead(401).end(); return; }
    res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ value: JWT }));
    return;
  }
  if (req.method === "POST" && url.pathname === "/cert/gha") {
    seen.cert++;
    seen.authz = req.headers.authorization;
    let body = "";
    for await (const c of req) body += c;
    const j = JSON.parse(body);
    const mtlsSpki = pemToDer(j.public_keys.mtls);
    const signSpki = pemToDer(j.public_keys.signing);
    const binding = Buffer.concat([mtlsSpki, signSpki, createHash("sha256").update(JWT).digest()]);
    const mk = await wc.subtle.importKey("spki", mtlsSpki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const sk = await wc.subtle.importKey("spki", signSpki, { name: "Ed25519" }, false, ["verify"]);
    const ok1 = await wc.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, mk, Buffer.from(j.proofs.mtls, "base64url"), binding);
    const ok2 = await wc.subtle.verify({ name: "Ed25519" }, sk, Buffer.from(j.proofs.signing, "base64url"), binding);
    seen.proofsOk = ok1 && ok2;
    if (!seen.proofsOk) { res.writeHead(400).end(JSON.stringify({ error: "bad proof" })); return; }
    res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({
      certificates: { mtls: "MTLS-PEM\nline2", signing: "SIGN-PEM" },
      identity: "wimse://notme.bot/gha/x/z",
      scopes: [], expires_at: 1234567890, binding: "abcdef0123456789",
      authority: { epoch: 1, key_id: "kid" },
      claims: { repository: "x/z", ref: "r", sha: "s", actor: "a", workflow: "w", run_id: "1", event_name: "push" },
    }));
    return;
  }
  res.writeHead(404).end();
});

await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;
const dir = mkdtempSync(join(tmpdir(), "notme-smoke-"));
const out = join(dir, "out");
writeFileSync(out, "");

const env = {
  PATH: process.env.PATH,
  INPUT_AUDIENCE: "notme.bot",
  INPUT_AUTHORITY_URL: base,
  INPUT_SKIP_BRIDGE_CERT: "false",
  INPUT_OCTO_STS_SCOPE: "",
  INPUT_OCTO_STS_IDENTITY: "default",
  GITHUB_OUTPUT: out,
  ACTIONS_ID_TOKEN_REQUEST_URL: `${base}/oidc?api-version=2.0`,
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: "runner-token",
};
const child = spawn(process.execPath, [bundle], { env, stdio: ["ignore", "pipe", "pipe"] });
let log = "";
child.stdout.on("data", (d) => (log += d));
child.stderr.on("data", (d) => (log += d));
const code = await new Promise((r) => child.on("close", r));
server.close();

const outputs = readFileSync(out, "utf8");
const failures = [];
if (code !== 0) failures.push(`exit code ${code}`);
if (process.exitCode) failures.push("nonzero exitCode");
if (seen.oidc !== 1 || seen.audience !== "notme.bot") failures.push(`oidc calls=${seen.oidc} audience=${seen.audience}`);
if (seen.cert !== 1 || seen.authz !== `Bearer ${JWT}`) failures.push(`cert calls=${seen.cert} authz=${seen.authz}`);
if (!seen.proofsOk) failures.push("PoP proofs did not verify");
for (const [k, v] of [["notme_cert", "MTLS-PEM\nline2"], ["notme_signing_cert", "SIGN-PEM"], ["notme_identity", "wimse://notme.bot/gha/x/z"], ["expires_at", "1234567890"], ["notme_url", base]]) {
  const re = new RegExp(`^${k}<<(ghadelimiter_[0-9a-f-]+)\\n([\\s\\S]*?)\\n\\1$`, "m");
  const m = outputs.match(re);
  if (!m || m[2] !== v) failures.push(`output ${k} missing/wrong`);
}
if (/::error::/.test(log)) failures.push("action logged ::error::");
console.log(`node ${process.version} ${bundle}: ${failures.length ? "FAIL " + failures.join("; ") : "PASS (oidc + PoP verified + 5 outputs)"}`);
if (failures.length) { console.log(log); process.exit(1); }
