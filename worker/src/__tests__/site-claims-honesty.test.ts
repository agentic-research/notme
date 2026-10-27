/**
 * site-claims-honesty.test.ts — the public site may not claim capabilities
 * the code does not have (notme-bed754 criterion A).
 *
 * WHY THIS EXISTS. An audit of the marketing pages found a described
 * mechanism that was entirely fictional: `architecture.html` carried a
 * sequence diagram naming a `CertAgent (Durable Object)` doing
 * "Check Serial Status" against an "Analytics (SQLite)" D1 database, under
 * the heading "Revocation is not a batch job — it is a real-time state
 * machine… track and kill credentials in seconds at the edge". None of it
 * existed: no such class, no D1 binding, no serial lookup anywhere, no cert
 * registry, and the one alarm in the codebase refreshes a bundle. A reader
 * would conclude notme can revoke an individual certificate in seconds. It
 * cannot revoke an individual certificate at all.
 *
 * `api-docs-honesty.test.ts` already does this for the API surface. This is
 * the same discipline for the pages a stranger reads first, and the
 * distinction worth keeping is that these checks are COUPLED TO REALITY
 * rather than being a blocklist of embarrassing phrases: the DO check reads
 * wrangler.toml, so inventing a different fictional class fails too.
 */
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const publicDir = fileURLToPath(new URL("../../public/", import.meta.url));
const workerDir = fileURLToPath(new URL("../../", import.meta.url));

const pages = readdirSync(publicDir)
  .filter((f) => f.endsWith(".html"))
  .map((f) => ({ name: f, text: readFileSync(`${publicDir}/${f}`, "utf8") }));

const wrangler = readFileSync(`${workerDir}/wrangler.toml`, "utf8");

describe("site claims stay coupled to what the code does", () => {
  it("names no Durable Object class that is not actually bound", () => {
    // Reads wrangler.toml rather than hardcoding the real names, so a
    // newly-invented class fails here even if it is spelled plausibly.
    const bound = [...wrangler.matchAll(/class_name\s*=\s*"([^"]+)"/g)].map(
      (m) => m[1]!,
    );
    expect(bound.length).toBeGreaterThan(0); // guard: the regex still matches

    for (const { name, text } of pages) {
      // Anything described as a Durable Object in prose or a diagram.
      const claimed = [
        ...text.matchAll(/([A-Z][A-Za-z0-9]+)\s*\(Durable Object\)/g),
      ].map((m) => m[1]!);
      for (const cls of claimed) {
        expect(
          bound,
          `${name} describes a Durable Object "${cls}" that wrangler.toml does ` +
            `not bind. Either bind it or stop describing it.`,
        ).toContain(cls);
      }
    }
  });

  it("claims no D1 database while none is bound", () => {
    const hasD1 = /\[\[d1_databases\]\]/.test(wrangler);
    for (const { name, text } of pages) {
      if (hasD1) continue;
      expect(
        /\bD1\b/.test(text),
        `${name} mentions D1 but wrangler.toml binds no d1_databases.`,
      ).toBe(false);
    }
  });

  it("claims no per-certificate or serial-based revocation", () => {
    // The repo has no CRL, no OCSP and no serial lookup; the levers are a
    // whole signing generation and a principal's grants. These phrasings all
    // tell a reader otherwise.
    const forbidden = [
      /Check Serial Status/i,
      /revocation is surgical/i,
      /kill the specific/i,
      /near-real-time (edge )?revo/i,
      /track and kill credentials/i,
    ];
    for (const { name, text } of pages) {
      for (const re of forbidden) {
        expect(
          re.test(text),
          `${name} claims per-certificate revocation (${re}). There is no CRL, ` +
            `no OCSP and no serial lookup — see ADR-019 D7.`,
        ).toBe(false);
      }
    }
  });

  it("does not claim post-quantum readiness while only Ed25519 is accepted", () => {
    // cert-authority.ts rejects any non-Ed25519 key, and no ML-DSA code
    // exists. "ready" reads as implemented.
    const certAuthority = readFileSync(
      `${workerDir}/src/cert-authority.ts`,
      "utf8",
    );
    const hasMlDsa = /ml[-_]?dsa|dilithium/i.test(certAuthority);
    for (const { name, text } of pages) {
      if (hasMlDsa) continue;
      expect(
        /(ML-DSA[^.<]*ready|ready[^.<]*ML-DSA)/i.test(text),
        `${name} calls ML-DSA "ready" but no ML-DSA code exists and the ` +
          `minter refuses non-Ed25519 keys.`,
      ).toBe(false);
    }
  });

  it("does not present DSSE/in-toto envelopes as a shipped notme capability", () => {
    // The only DSSE reference in worker/src is a comment and a format string.
    // The pages must mark it planned. apas.html is excluded: its wording is
    // pinned by apas-content.test.ts and describes the APAS spec rather than
    // notme's implementation.
    for (const { name, text } of pages) {
      if (name === "apas.html") continue;
      const m = /in-toto\/DSSE[^<]*/i.exec(text);
      if (!m) continue;
      expect(
        /planned|coming|in progress|not yet/i.test(m[0]),
        `${name} presents "${m[0].trim()}" as shipped. Mark it planned.`,
      ).toBe(true);
    }
  });

  it("does not claim mTLS handshake enforcement that no code performs", () => {
    // Nothing reads Cloudflare's client-certificate fields.
    const src = readdirSync(`${workerDir}/src`)
      .filter((f) => f.endsWith(".ts"))
      .map((f) => readFileSync(`${workerDir}/src/${f}`, "utf8"))
      .join("\n");
    const enforcesMtls = /tlsClientAuth|cf-client-cert|certPresented/i.test(src);
    for (const { name, text } of pages) {
      if (enforcesMtls) continue;
      expect(
        /require[sd]? valid mTLS handshake/i.test(text),
        `${name} says protected routes require an mTLS handshake, but no code ` +
          `reads any client-certificate field.`,
      ).toBe(false);
    }
  });
});
