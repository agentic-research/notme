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
 *
 * SELF-CONSISTENCY IS ALSO NOT ENOUGH, and this file learned that the hard
 * way (notme-1b46a8). Both assertions passed for weeks while the committed
 * certificate was the PRE-HEAL root: serial d01f2a0a, pathlen:0, issued
 * 2026-03-31. Production had re-issued under the same key in August with
 * pathlen:1 (notme-1b1db4), and nothing here compared the anchor to anything
 * outside itself — so the pin and the cert agreed with each other and both
 * disagreed with reality.
 *
 * That is not cosmetic for an anchor whose whole purpose is that strangers
 * pin it: pathlen:0 FORBIDS the intermediate tier ADR-019 D4 issues, so a
 * verifier pinning the committed file would reject every tier-signed
 * certificate notme mints.
 *
 * The fix is the last case below — tie the anchor to a fact that moves when
 * production moves. CA_PATH_LEN is that fact, it lives in the code that
 * issues the root, and it needs no network.
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

  it("the anchor's path length matches the CA_PATH_LEN the code issues", () => {
    // The assertion that would have caught the staleness above. Read from
    // source rather than duplicated here, so bumping the constant fails this
    // until the committed anchor is refreshed to a root that actually
    // carries the new budget.
    const source = readFileSync(
      fileURLToPath(new URL("../signing-authority.ts", import.meta.url)),
      "utf8",
    );
    const declared = source.match(/CA_PATH_LEN\s*=\s*(\d+)/);
    expect(declared, "CA_PATH_LEN not found in signing-authority.ts").toBeTruthy();
    const expected = Number(declared![1]);

    const cert = new x509.X509Certificate(read("notme-root.pem"));
    const bc = cert.getExtension(x509.BasicConstraintsExtension);
    expect(bc, "committed anchor has no BasicConstraints").toBeTruthy();
    expect(bc!.ca, "committed anchor is not a CA").toBe(true);
    expect(
      bc!.pathLength,
      `committed anchor is pathlen:${bc!.pathLength} but the code issues ` +
        `pathlen:${expected}. The anchor is stale — refresh trust/ from ` +
        `/.well-known/ca-bundle.pem and update notme-root.json.`,
    ).toBe(expected);
  });

  it("documents how to verify against it", () => {
    const doc = read("README.md");
    expect(doc).toMatch(/pin/i);
    expect(doc).toMatch(/ca-bundle\.pem/);
  });
});
