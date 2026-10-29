/**
 * Check the deployed CT log's key against the committed pin (notme-1b46a8).
 *
 *   task ct:verify                          # compare the log to trust/notme-ct-log.json
 *   task ct:verify -- --write --metadata U  # record the pin the FIRST time
 *   task ct:verify -- --metadata <url|file> # override where metadata.json comes from
 *   task ct:verify -- --pin <file>          # override the pin file (tests)
 *
 * Exit codes
 *   0  pin matches the log, OR the pin is "not-provisioned" (nothing to check
 *      yet; CI must not break before the log exists), OR --write recorded it
 *   1  the log disagrees with the pin, could not be read, or the pin is malformed
 *   1  also: the pin is provisioned (or being written) while the log config
 *      still contains the REPLACE-ME placeholder URLs (--config overrides the path)
 *   2  --write refused: a DIFFERENT pin is already recorded
 *
 * What is compared is the `key` (base64 SPKI DER) and `log_id` from the log's
 * `metadata.json` (azul ct_worker: GET /logs/<log>/metadata.json). The log_id
 * must also equal SHA-256(key), the RFC 6962 definition; a metadata document
 * whose id and key disagree is rejected whatever the pin says.
 *
 * Same stance as refresh-trust-anchor.ts: a changed key is a different log,
 * not a refresh. --write therefore NEVER overwrites a recorded pin; replacing
 * one is a reviewed edit of trust/notme-ct-log.json by a human.
 *
 * Fetching metadata.json authenticates nothing by itself: a party that
 * controls the log's hostname serves its own key. The pin is the second
 * channel, which is why it is committed and release-signed.
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const DEFAULT_CONFIG = join(__dirname, "..", "ct", "config.notme.json");
export const DEFAULT_PIN = join(__dirname, "..", "trust", "notme-ct-log.json");

export interface ProvisionedPin {
  status: "provisioned";
  log_name: string;
  metadata_url: string;
  /** base64 of the 32-byte log id */
  log_id: string;
  /** base64 of the log's public key, SPKI DER */
  key: string;
  /** hex SHA-256 of the key's SPKI DER, in the style of notme-root.json */
  key_spki_sha256: string;
  observed_at: string;
}

export type Verdict =
  | { kind: "not-provisioned" }
  | { kind: "match"; logId: string }
  | { kind: "mismatch" | "malformed"; reason: string };

const b64 = (s: unknown): Buffer | null =>
  typeof s === "string" && s.length > 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(s)
    ? Buffer.from(s, "base64")
    : null;
const sha256 = (b: Buffer) => createHash("sha256").update(b).digest();

/**
 * Validate a metadata document on its own: key and id present, well formed,
 * and log_id === SHA-256(key). Returns the canonical values or a reason.
 */
export function readMetadata(
  md: unknown,
): { key: string; logId: string } | { error: string } {
  const o = (md ?? {}) as Record<string, unknown>;
  const key = b64(o.key);
  const id = b64(o.log_id);
  if (!key) return { error: "metadata has no usable base64 `key`" };
  if (!id) return { error: "metadata has no usable base64 `log_id`" };
  if (!sha256(key).equals(id))
    return { error: "metadata log_id is not SHA-256(key); the document is inconsistent" };
  return { key: key.toString("base64"), logId: id.toString("base64") };
}

export function judge(pin: unknown, md: unknown): Verdict {
  const p = (pin ?? {}) as Record<string, unknown>;
  if (p.status === "not-provisioned") return { kind: "not-provisioned" };
  if (p.status !== "provisioned")
    return { kind: "malformed", reason: `pin status is ${JSON.stringify(p.status)}` };
  const pk = b64(p.key);
  const pid = b64(p.log_id);
  if (!pk || !pid) return { kind: "malformed", reason: "pin lacks a usable key or log_id" };
  if (!sha256(pk).equals(pid))
    return { kind: "malformed", reason: "pin's log_id is not SHA-256(its key)" };
  if (p.key_spki_sha256 !== sha256(pk).toString("hex"))
    return { kind: "malformed", reason: "pin's key_spki_sha256 does not match its key" };
  const live = readMetadata(md);
  if ("error" in live) return { kind: "mismatch", reason: live.error };
  if (live.key !== pk.toString("base64"))
    return {
      kind: "mismatch",
      reason: `log serves key ${sha256(Buffer.from(live.key, "base64")).toString("hex")}, pin has ${p.key_spki_sha256}`,
    };
  return { kind: "match", logId: live.logId };
}

export function buildPin(url: string, md: unknown, now = new Date()): ProvisionedPin | { error: string } {
  const live = readMetadata(md);
  if ("error" in live) return live;
  const name = /\/logs\/([^/]+)\/metadata\.json$/.exec(url)?.[1] ?? "notme";
  return {
    status: "provisioned",
    log_name: name,
    metadata_url: url,
    log_id: live.logId,
    key: live.key,
    key_spki_sha256: sha256(Buffer.from(live.key, "base64")).toString("hex"),
    observed_at: now.toISOString().replace(/\.\d{3}Z$/, "Z"),
  };
}

async function load(src: string): Promise<unknown> {
  if (/^https?:\/\//.test(src)) {
    const res = await fetch(`${src}${src.includes("?") ? "&" : "?"}r=${Date.now()}`, {
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) throw new Error(`${src} answered ${res.status}`);
    return res.json();
  }
  return JSON.parse(readFileSync(src, "utf8"));
}

const arg = (argv: string[], name: string) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};

export async function run(argv: string[]): Promise<number> {
  const pinPath = arg(argv, "--pin") ?? DEFAULT_PIN;
  const write = argv.includes("--write");
  const pin = JSON.parse(readFileSync(pinPath, "utf8"));
  if (write || pin.status === "provisioned") {
    const cfgPath = arg(argv, "--config") ?? DEFAULT_CONFIG;
    if (readFileSync(cfgPath, "utf8").includes("REPLACE-ME")) {
      console.error(
        `${cfgPath} still contains the REPLACE-ME placeholder URLs; a log was deployed from a config that does not name where it is served.`,
      );
      return 1;
    }
  }
  const src = arg(argv, "--metadata") ?? process.env.CT_LOG_METADATA_URL ?? pin.metadata_url;

  if (write) {
    if (!src) {
      console.error("--write needs --metadata <url|file> (or CT_LOG_METADATA_URL).");
      return 1;
    }
    const md = await load(src);
    const next = buildPin(src, md);
    if ("error" in next) {
      console.error(next.error);
      return 1;
    }
    if (pin.status === "provisioned") {
      if (pin.key === next.key) {
        console.log(`pin already records this key (log_id ${pin.log_id}); nothing written.`);
        return 0;
      }
      console.error(
        `REFUSING: ${pinPath} already pins a different key (${pin.key_spki_sha256}); the log serves ${next.key_spki_sha256}.\n` +
          "A different key is a different log, not a refresh. Replacing a pin is a reviewed manual edit.",
      );
      return 2;
    }
    writeFileSync(pinPath, JSON.stringify(next, null, 4) + "\n");
    console.log(`recorded ${pinPath}: log_id ${next.log_id}, key sha256 ${next.key_spki_sha256}`);
    console.log("Commit it and cut a release: the release workflow signs it.");
    return 0;
  }

  if (pin.status === "not-provisioned") {
    console.log("ct-log: not provisioned (trust/notme-ct-log.json). Nothing to verify; exiting 0.");
    return 0;
  }
  if (!src) {
    console.error("pin has no metadata_url; pass --metadata <url|file>.");
    return 1;
  }
  let v: Verdict;
  try {
    v = judge(pin, await load(src));
  } catch (e) {
    console.error(`could not read ${src}: ${e instanceof Error ? e.message : e}`);
    return 1;
  }
  if (v.kind === "match") {
    console.log(`ct-log: key and log_id match the pin (log_id ${v.logId}).`);
    return 0;
  }
  if (v.kind === "not-provisioned") return 0;
  console.error(`ct-log: ${v.kind.toUpperCase()}: ${v.reason}`);
  return 1;
}

if (require.main === module) {
  run(process.argv.slice(2)).then(
    (c) => process.exit(c),
    (e) => {
      console.error(e instanceof Error ? e.message : e);
      process.exit(1);
    },
  );
}
