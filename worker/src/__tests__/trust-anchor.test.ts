/**
 * trust-anchor.test.ts — notme's root trust material must be pinnable from
 * source control, not only from the live endpoint (notme-8e8836).
 *
 * Today a third party bootstraps trust by fetching /.well-known/ca-bundle.pem
 * over TLS from the same host that issued their credential. The CA is
 * self-signed (verified live: subject == issuer), so whoever controls the
 * hostname controls the trust root, and every fetch RE-ESTABLISHES trust
 * rather than confirming it.
 *
 * Committing the root's fingerprint gives a consumer an out-of-band channel —
 * git history, reviewed and distributed independently of the TLS endpoint —
 * to pin against. That is the first half of an anchor; signing the material
 * with the release pipeline's Sigstore identity is the second, and the
 * pipeline already has that capability (cosign keyless, verified live).
 *
 * SELF-CONSISTENCY IS THE POINT of the fingerprint assertion below: a
 * committed pin that does not match the committed certificate is worse than
 * no pin, because it looks authoritative. This makes the two unable to
 * disagree silently.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import * as x509 from "@peculiar/x509";

const TRUST_DIR = new URL("../../../trust/", import.meta.url);
const read = (f: string) =>
  readFileSync(fileURLToPath(new URL(f, TRUST_DIR)), "utf8");

const sha256Hex = async (bytes: ArrayBuffer | Uint8Array) =>
  [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as any))]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

describe("committed root trust anchor (notme-8e8836)", () => {
  it("ships the root certificate and a machine-readable pin", () => {
    expect(read("notme-root.pem")).toContain("BEGIN CERTIFICATE");
    const pin = JSON.parse(read("notme-root.json"));
    for (const key of [
      "authority",
      "subject",
      "spki_sha256",
      "cert_sha256",
      "not_before",
      "not_after",
    ]) {
      expect(pin, `pin is missing ${key}`).toHaveProperty(key);
    }
    expect(pin.spki_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(pin.cert_sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("the committed fingerprints actually match the committed certificate", async () => {
    // A pin that disagrees with the cert beside it is worse than no pin.
    const pin = JSON.parse(read("notme-root.json"));
    const cert = new x509.X509Certificate(read("notme-root.pem"));
    expect(await sha256Hex(cert.rawData)).toBe(pin.cert_sha256);
    expect(await sha256Hex(cert.publicKey.rawData)).toBe(pin.spki_sha256);
    expect(cert.subject).toContain("signet-authority");
  });

  it("documents how to verify against it", () => {
    const doc = read("README.md");
    expect(doc).toMatch(/pin/i);
    expect(doc).toMatch(/ca-bundle\.pem/);
  });
});
