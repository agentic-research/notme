#!/usr/bin/env -S pnpm exec tsx
/**
 * notme task certificates from a machine (notme-486e8a).
 *
 *   task-cert enrol  [--authority URL] [--dir DIR]
 *   task-cert mint   --task ID --goal TEXT [--scopes a,b] [--ttl-min N] [--out DIR] [--dir DIR]
 *   task-cert verify --cert FILE [--dir DIR]
 *   task-cert status [--dir DIR]
 *
 * State lives in --dir (default ~/.notme/tier): the tier cert, its private
 * key (0600, PKCS#8), the authority root pinned at enrol time, and metadata.
 *
 * TRUST, stated plainly: the root is fetched over TLS from the authority at
 * enrol time and pinned. After that, mint and verify never touch the network.
 * The private key on disk is the tier — anyone who reads it can mint task
 * certs as you until it expires (≤24h). It is protected by file permissions
 * only.
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { X509Certificate } from "@peculiar/x509";
import {
  enrolProof, exportPrivateKeyPem, generateTierKey, groupFingerprint, importPrivateKeyPem,
  mintTask, pollEnrolment, startEnrolment, verifyChain,
} from "./lib";

function args(argv: string[]) {
  const out: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i]!.startsWith("--")) out[argv[i]!.slice(2)] = argv[i + 1] ?? "";
  }
  return out;
}

const [cmd, ...rest] = process.argv.slice(2);
const a = args(rest);
const dir = a.dir || join(homedir(), ".notme", "tier");
const authority = (a.authority || "https://auth.notme.bot").replace(/\/$/, "");

function need(f: string) {
  const p = join(dir, f);
  if (!existsSync(p)) throw new Error(`no ${f} in ${dir} — run \`task-cert enrol\` first`);
  return readFileSync(p, "utf8");
}

async function enrol() {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const key = await generateTierKey();
  const start = await startEnrolment(authority, key.pem, a.scopes ? a.scopes.split(",") : undefined);
  console.log(`\nApprove this machine with your passkey:\n\n  ${start.verification_uri}\n`);
  console.log(`  code:        ${start.user_code}`);
  console.log(`  fingerprint: ${groupFingerprint(start.key_fingerprint)}`);
  console.log(`\nApprove only if the page shows the same fingerprint. Waiting (${start.expires_in}s)...`);
  const proof = await enrolProof(key.privateKey, key.spki, start.device_code);
  const tier = await pollEnrolment(authority, start.device_code, proof, {
    interval: start.interval,
    expiresIn: start.expires_in,
  });
  const root = await (await fetch(`${authority}/.well-known/ca-bundle.pem`)).text();
  writeFileSync(join(dir, "tier.key.pem"), await exportPrivateKeyPem(key.privateKey), { mode: 0o600 });
  chmodSync(join(dir, "tier.key.pem"), 0o600);
  writeFileSync(join(dir, "tier.pem"), tier.certificate);
  writeFileSync(join(dir, "root.pem"), root);
  writeFileSync(
    join(dir, "tier.json"),
    JSON.stringify(
      { authority, identity: tier.identity, scopes: tier.scopes, expires_at: tier.expires_at, epoch: tier.authority.epoch },
      null,
      2,
    ),
  );
  const check = await verifyRoot(root, tier.certificate);
  console.log(`\nEnrolled ${tier.identity}`);
  console.log(`  scopes ${tier.scopes.join(", ")}, expires ${new Date(tier.expires_at * 1000).toISOString()}`);
  console.log(`  tier chains to the pinned root: ${check}`);
}

async function verifyRoot(rootPem: string, tierPem: string) {
  const root = new X509Certificate(rootPem);
  const tier = new X509Certificate(tierPem);
  return (await tier.verify({ publicKey: await root.publicKey.export(), signatureOnly: true })) ? "yes" : "NO";
}

async function mint() {
  if (!a.task || !a.goal) throw new Error("--task and --goal are required");
  const meta = JSON.parse(need("tier.json"));
  const t = await mintTask(need("tier.pem"), await importPrivateKeyPem(need("tier.key.pem")), {
    task: a.task,
    goal: a.goal,
    epoch: meta.epoch,
    scopes: a.scopes ? a.scopes.split(",") : undefined,
    ttlMs: a["ttl-min"] ? Number(a["ttl-min"]) * 60_000 : undefined,
  });
  const out = a.out || `task-${a.task}`;
  mkdirSync(out, { recursive: true, mode: 0o700 });
  writeFileSync(join(out, "signing.pem"), t.certificates.signing);
  writeFileSync(join(out, "mtls.pem"), t.certificates.mtls);
  writeFileSync(join(out, "signing.key.pem"), t.keys.signing, { mode: 0o600 });
  writeFileSync(join(out, "mtls.key.pem"), t.keys.mtls, { mode: 0o600 });
  writeFileSync(join(out, "chain.pem"), t.certificates.signing + need("tier.pem"));
  console.log(`Minted offline: ${t.identity}`);
  console.log(`  goal sha256 ${t.goalHash}`);
  console.log(`  expires ${new Date(t.expires_at * 1000).toISOString()}  →  ${out}/`);
}

async function verify() {
  if (!a.cert) throw new Error("--cert is required");
  const r = await verifyChain(need("root.pem"), need("tier.pem"), readFileSync(a.cert, "utf8"));
  console.log(r.ok ? "OK: root → tier → task" : `FAIL: ${r.reason}`);
  if (!r.ok) process.exitCode = 1;
}

async function status() {
  const meta = JSON.parse(need("tier.json"));
  const left = meta.expires_at * 1000 - Date.now();
  console.log(`${meta.identity}\n  ${left > 0 ? `expires in ${Math.round(left / 60000)} min` : "EXPIRED — run enrol again"}`);
}

const run = { enrol, mint, verify, status }[cmd ?? ""];
if (!run) {
  console.error("usage: task-cert <enrol|mint|verify|status> [...]  (see header of scripts/task-cert/cli.ts)");
  process.exit(2);
}
Promise.resolve(run()).catch((e) => {
  console.error(`task-cert ${cmd}: ${e.message}`);
  process.exit(1);
});
