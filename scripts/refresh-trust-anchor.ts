/**
 * Refresh trust/ from the live root (notme-8e8836).
 *
 *   task trust:refresh            # write trust/notme-root.{pem,json}
 *   task trust:refresh -- --check # exit 1 if trust/ disagrees with production
 *
 * The anchor went stale TWICE while its tests passed: once after the pathlen
 * heal (2026-08-28), once after the notBefore re-issue (2026-10-28). Both
 * times the key was unchanged and the certificate was not — so anyone pinning
 * the certificate pinned one production no longer served. The tests re-derive
 * the pin from the PEM beside it, which makes the two agree with each other
 * and with nothing else. This script is the half that compares to production,
 * and `worker:verify` runs its --check after every deploy.
 *
 * REFUSES if the key changed. A different SPKI is not a refresh, it is a
 * different authority, and adopting it silently is exactly the root
 * substitution this directory exists to detect. That case needs a human and
 * its own review (trust/README.md, "refresh rule").
 *
 * Digests are computed the way trust-anchor.test.ts computes them — DER of the
 * parsed certificate and of its SPKI — never over file bytes, whose framing
 * (a trailing newline) differs between the endpoint and the committed file.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import * as x509 from "@peculiar/x509";
import { rootKeyIsCurrent } from "./trust-anchor-freshness";

const AUTHORITY = "https://auth.notme.bot";
const BUNDLE = `${AUTHORITY}/.well-known/ca-bundle.pem`;
/** The signed KV CABundle: no-store, names the live key (src/internal-ca-bundle.ts). */
const LIVE_BUNDLE = `${AUTHORITY}/internal/ca-bundle`;
const DIR = join(__dirname, "..", "trust");
const check = process.argv.includes("--check");

const sha256Hex = async (b: ArrayBuffer) =>
  [...new Uint8Array(await crypto.subtle.digest("SHA-256", b))]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");

async function main() {
  // Edge-cached: a query no longer gets past the Cache API (/.well-known/*
  // keys ignore it, notme-ed6114), and nothing purges it on rotate(). So the
  // PEM is only trusted once the no-store CABundle confirms its key is the
  // live one — otherwise this could write, or --check could bless, the root
  // of a key the authority stopped using (review F2).
  const res = await fetch(BUNDLE);
  if (!res.ok) throw new Error(`${BUNDLE} answered ${res.status}`);
  const live = new x509.X509Certificate(await res.text());
  const cab = await fetch(LIVE_BUNDLE, { headers: { accept: "application/json" } });
  if (!cab.ok) throw new Error(`${LIVE_BUNDLE} answered ${cab.status}`);
  const bundle = (await cab.json()) as { keyId: string; keys: Record<string, string> };
  if (!rootKeyIsCurrent(new Uint8Array(live.publicKey.rawData), bundle)) {
    console.error(
      `STALE EDGE COPY: ${BUNDLE} serves a root whose key is not the authority's current key ` +
        `(${LIVE_BUNDLE} keyId ${bundle.keyId}). A rotate() is still inside the PEM's max-age ` +
        "at this colo. Not writing or judging anything — re-run once it has expired.",
    );
    process.exit(3);
  }
  const pin = JSON.parse(readFileSync(join(DIR, "notme-root.json"), "utf8"));

  const spki = await sha256Hex(live.publicKey.rawData);
  const certHash = await sha256Hex(live.rawData);

  if (spki !== pin.spki_sha256) {
    console.error(
      `KEY CHANGED: production serves SPKI ${spki}, trust/ pins ${pin.spki_sha256}.\n` +
        "This is a different authority, not a refresh. Not writing anything — " +
        "see the refresh rule in trust/README.md.",
    );
    process.exit(2);
  }

  if (certHash === pin.cert_sha256) {
    console.log(`trust/ is current (serial ${live.serialNumber}, same key).`);
    process.exit(0);
  }

  if (check) {
    console.error(
      `trust/ is STALE: production re-issued the root under the same key ` +
        `(serial ${pin.serial_number} → ${live.serialNumber.toLowerCase()}). ` +
        "Run `task trust:refresh` and commit trust/.",
    );
    process.exit(1);
  }

  // Canonical PEM framing with a trailing newline, matching `openssl x509`.
  writeFileSync(join(DIR, "notme-root.pem"), live.toString("pem").trimEnd() + "\n");
  const iso = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, "Z");
  writeFileSync(
    join(DIR, "notme-root.json"),
    JSON.stringify(
      {
        ...pin,
        serial_number: live.serialNumber.toLowerCase(),
        cert_sha256: certHash,
        not_before: iso(live.notBefore),
        not_after: iso(live.notAfter),
        observed_at: iso(new Date()),
      },
      null,
      4,
    ) + "\n",
  );
  console.log(
    `trust/ refreshed: serial ${pin.serial_number} → ${live.serialNumber.toLowerCase()}, ` +
      `same key ${spki.slice(0, 16)}…`,
  );
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
