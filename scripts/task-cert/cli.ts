#!/usr/bin/env -S pnpm exec tsx
/**
 * notme task certificates from a machine (notme-486e8a).
 *
 *   task-cert enroll [--authority URL] [--dir DIR]   (alias: enrol)
 *   task-cert mint   --task ID --goal TEXT [--scopes a,b] [--ttl-min N] [--out DIR] [--dir DIR]
 *                    (--out defaults to ~/.notme/tasks/<task>)
 *   task-cert mint   --parent TASK --task SUB --goal TEXT   (a subtask)
 *   task-cert renew  [--dir DIR]
 *   task-cert revoke --task TASK                           (and everything under it)
 *   task-cert verify --cert FILE [--dir DIR]
 *   task-cert status [--dir DIR]
 *   (every command takes --tasks-dir DIR, default ~/.notme/tasks)
 *
 * RESUMING. A machine that paused past its tier's lifetime renews it with no
 * human, by proof of possession, for as long as the approval holds — the
 * horizon chosen when it was approved (default 7 days). `mint` does this
 * itself when the tier has expired; `renew` does it on demand. If the approval
 * has ended (revoked, past the horizon, epoch changed, approver lost certMint)
 * it says which, and a human approves again with `enroll`.
 *
 * SUBTASKS AND RE-MINTS are one operation: a new credential derived from an
 * existing task's, minted HERE by the tier holder — an agent never mints.
 * They can only narrow (scopes ⊆ and lifetime ≤ the parent's), names extend
 * the parent's, and every mint is recorded in ~/.notme/tasks/ledger.jsonl.
 * `revoke` stops this machine minting or re-minting a task and everything
 * under it; certificates already issued live out their ≤5 minutes.
 *
 * State lives in --dir (default ~/.notme/tier): the tier cert, its private
 * key (0600, PKCS#8), the authority root pinned at enroll time, and metadata.
 *
 * TRUST, stated plainly: the root is fetched over TLS from the authority at
 * enroll time and pinned. After that, mint and verify never touch the network.
 * The private key on disk is the tier — anyone who reads it can mint task
 * certs as you until it expires (≤24h). It is protected by file permissions
 * only.
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { X509Certificate } from "@peculiar/x509";
import { appendFileSync } from "node:fs";
import {
  enrolProof, exportPrivateKeyPem, generateTierKey, groupFingerprint, importPrivateKeyPem,
  isRevokedTask, mintTask, pollEnrolment, renewTier, startEnrolment, taskOutDir, verifyChain,
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
// Where task certs, the ledger and the local revocation list live.
const TASKS = a["tasks-dir"] || join(homedir(), ".notme", "tasks");
const LEDGER = join(TASKS, "ledger.jsonl");
const REVOKED = join(TASKS, "revoked.json");
const revokedList = (): string[] => (existsSync(REVOKED) ? JSON.parse(readFileSync(REVOKED, "utf8")) : []);

function need(f: string) {
  const p = join(dir, f);
  if (!existsSync(p)) throw new Error(`no ${f} in ${dir} — run \`task-cert enroll\` first`);
  return readFileSync(p, "utf8");
}

async function enroll() {
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
      {
        authority,
        identity: tier.identity,
        scopes: tier.scopes,
        expires_at: tier.expires_at,
        epoch: tier.authority.epoch,
        renew_until: tier.renew_until,
      },
      null,
      2,
    ),
  );
  const check = await verifyRoot(root, tier.certificate);
  console.log(`\nEnrolled ${tier.identity}`);
  console.log(`  scopes ${tier.scopes.join(", ")}, expires ${new Date(tier.expires_at * 1000).toISOString()}`);
  console.log(`  tier chains to the pinned root: ${check}`);
  if (tier.renew_until) {
    console.log(`  renews without you until ${new Date(tier.renew_until * 1000).toISOString()}`);
  }
}

/**
 * Renew the tier with no human. The tier's public key comes from the tier
 * certificate itself, so nothing beyond what enroll saved is needed.
 */
async function renewNow(quiet = false) {
  const meta = JSON.parse(need("tier.json"));
  const tierCert = new X509Certificate(need("tier.pem"));
  const spki = new Uint8Array(tierCert.publicKey.rawData);
  const pem = `-----BEGIN PUBLIC KEY-----\n${btoa(String.fromCharCode(...spki)).match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----\n`;
  let r;
  try {
    r = await renewTier(meta.authority ?? authority, {
      privateKey: await importPrivateKeyPem(need("tier.key.pem")),
      spki,
      pem,
    });
  } catch (e: any) {
    throw new Error(`the approval for this machine has ended (${e.message}) — run \`task-cert enroll\` and approve again`);
  }
  writeFileSync(join(dir, "tier.pem"), r.certificate);
  writeFileSync(
    join(dir, "tier.json"),
    JSON.stringify({ ...meta, expires_at: r.expires_at, epoch: r.authority.epoch, renew_until: r.renew_until }, null, 2),
  );
  if (!quiet) {
    console.log(`Renewed — no human needed. Tier valid until ${new Date(r.expires_at * 1000).toISOString()},`);
    console.log(`  renewable without you until ${new Date(r.renew_until * 1000).toISOString()}.`);
  }
}

async function renew() {
  await renewNow();
}

/** The resume path: an expired (or nearly expired) tier is renewed first. */
async function ensureFreshTier() {
  const tierCert = new X509Certificate(need("tier.pem"));
  if (tierCert.notAfter.getTime() - Date.now() < 60_000) {
    console.log("Tier expired or expiring — renewing (no human needed)...");
    await renewNow(true);
  }
}

async function revoke() {
  if (!a.task) throw new Error("--task is required");
  mkdirSync(TASKS, { recursive: true, mode: 0o700 });
  const list = revokedList();
  if (!list.includes(a.task)) list.push(a.task);
  writeFileSync(REVOKED, JSON.stringify(list, null, 2));
  console.log(`Revoked ${a.task} and everything under it on this machine.`);
  console.log("  No further mints or re-mints here; certificates already issued live out their ≤5 minutes.");
}

async function verifyRoot(rootPem: string, tierPem: string) {
  const root = new X509Certificate(rootPem);
  const tier = new X509Certificate(tierPem);
  return (await tier.verify({ publicKey: await root.publicKey.export(), signatureOnly: true })) ? "yes" : "NO";
}

async function mint() {
  if (!a.task || !a.goal) throw new Error("--task and --goal are required");
  const taskPath = a.parent ? `${a.parent}/${a.task}` : a.task;
  if (isRevokedTask(taskPath, revokedList())) {
    throw new Error(`${taskPath} is revoked on this machine (it, or a task it derives from)`);
  }
  await ensureFreshTier();
  const meta = JSON.parse(need("tier.json"));
  let parent: string | undefined;
  if (a.parent) {
    const p = join(taskOutDir(TASKS, a.parent), "signing.pem");
    if (!existsSync(p)) throw new Error(`no parent task ${a.parent} — mint it first (${p})`);
    parent = readFileSync(p, "utf8");
  }
  const t = await mintTask(need("tier.pem"), await importPrivateKeyPem(need("tier.key.pem")), {
    task: a.task,
    goal: a.goal,
    epoch: meta.epoch,
    scopes: a.scopes ? a.scopes.split(",") : undefined,
    ttlMs: a["ttl-min"] ? Number(a["ttl-min"]) * 60_000 : undefined,
    parent,
  });
  // Default OUTSIDE the working directory. These are private keys, and the
  // working directory is usually a repo: notme's deny-by-default .gitignore
  // happens to cover it, most repos' do not. Subtasks nest under the parent.
  const out = a.out || taskOutDir(TASKS, taskPath);
  mkdirSync(out, { recursive: true, mode: 0o700 });
  writeFileSync(join(out, "signing.pem"), t.certificates.signing);
  writeFileSync(join(out, "mtls.pem"), t.certificates.mtls);
  writeFileSync(join(out, "signing.key.pem"), t.keys.signing, { mode: 0o600 });
  writeFileSync(join(out, "mtls.key.pem"), t.keys.mtls, { mode: 0o600 });
  writeFileSync(join(out, "chain.pem"), t.certificates.signing + need("tier.pem"));
  mkdirSync(TASKS, { recursive: true, mode: 0o700 });
  appendFileSync(
    LEDGER,
    JSON.stringify({
      at: new Date().toISOString(),
      task: taskPath,
      parent: a.parent ?? null,
      identity: t.identity,
      goal_sha256: t.goalHash,
      serial: new X509Certificate(t.certificates.signing).serialNumber,
      scopes: t.scopes,
      expires_at: t.expires_at,
    }) + "\n",
    { mode: 0o600 },
  );
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
  const now = Date.now();
  const left = meta.expires_at * 1000 - now;
  const renewLeft = (meta.renew_until ?? 0) * 1000 - now;
  console.log(meta.identity);
  console.log(`  tier: ${left > 0 ? `valid for ${Math.round(left / 60000)} min` : "expired"}`);
  console.log(
    `  renewal: ${renewLeft > 0 ? `without a human for ${Math.round(renewLeft / 3_600_000)} h more` : "ended — run enroll and approve again"}`,
  );
  const minted = existsSync(LEDGER) ? readFileSync(LEDGER, "utf8").trim().split("\n").filter(Boolean).length : 0;
  console.log(`  tasks minted here: ${minted}; revoked: ${revokedList().join(", ") || "none"}`);
}

// `enrol` is the first spelling, kept so existing instructions still work.
const run = { enroll, enrol: enroll, mint, renew, revoke, verify, status }[cmd ?? ""];
if (!run) {
  console.error("usage: task-cert <enroll|mint|renew|revoke|verify|status> [...]  (see header of scripts/task-cert/cli.ts)");
  process.exit(2);
}
Promise.resolve(run()).catch((e) => {
  console.error(`task-cert ${cmd}: ${e.message}`);
  process.exit(1);
});
