/**
 * api-docs-honesty.test.ts — /api/docs is a LIVE PUBLIC PAGE, and this pins
 * it to the code it describes (notme-8e0f3a, Goal Zero criterion A).
 *
 * The page had drifted badly: it documented three endpoints that do not
 * exist, two grant types that were never implemented, a discovery document
 * with the wrong fields, a curl that 400s, and — worst — it advertised a
 * `private_key` in cert responses, describing a WEAKER security property
 * than the one the whole design exists to provide.
 *
 * Correcting the text alone would leave nothing stopping the next drift, so
 * these assertions read the page AND the code and require them to agree,
 * rather than pinning prose to prose. The grant list comes from
 * AUTHORITY_GRANT_TYPES; every documented path must be a route worker.ts
 * actually serves.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { AUTHORITY_GRANT_TYPES } from "../as-metadata";

const root = fileURLToPath(new URL("../../", import.meta.url));
const docs = readFileSync(`${root}public/_api-docs.html`, "utf8");
// _auth.html is the authority's OWN landing page and carried the same stale
// claims — the same /exchange-token and /api/cert/register rows, and a
// `private_key` in the documented response.
const authPage = readFileSync(`${root}public/_auth.html`, "utf8");
const workerSrc = readFileSync(`${root}worker.ts`, "utf8");

/** Every path a page presents as an endpoint. */
const pathsIn = (html: string) =>
  [...html.matchAll(/class="ep-path"[^>]*>([^<]+)</g)].map((m) => m[1]!.trim());
const documentedPaths = pathsIn(docs);
const authPaths = pathsIn(authPage);

describe("api-docs.endpoints-exist", () => {
  it("documents at least the core surface", () => {
    // Guards the extractor itself: a changed class name would silently make
    // every assertion below vacuous over an empty list.
    expect(documentedPaths.length).toBeGreaterThan(8);
    expect(documentedPaths).toContain("/cert/gha");
    expect(documentedPaths).toContain("/token");
  });

  it("documents no endpoint the worker does not serve", () => {
    const missing = [...documentedPaths, ...authPaths].filter((p) => {
      if (p === "/") return false; // content-negotiated landing
      return !(
        workerSrc.includes(`pathname === "${p}"`) ||
        workerSrc.includes(`url.pathname === "${p}"`) ||
        workerSrc.includes(`pathname.startsWith("${p}`)
      );
    });
    expect(missing, `documented but not routed: ${missing.join(", ")}`).toEqual([]);
  });

  it("does not resurrect the three routes that never existed", () => {
    // /exchange-token and /api/cert/register were documented as "proxied to
    // signet authority on Fly"; both 404. /healthz is real but is answered
    // at the edge, not proxied anywhere.
    for (const page of [docs, authPage]) {
      expect(page).not.toContain("/exchange-token");
      expect(page).not.toContain("/api/cert/register");
      expect(page).not.toMatch(/Proxied to signet authority on Fly/i);
    }
  });

  it("the authority's own landing page lists a real surface too", () => {
    expect(authPaths.length).toBeGreaterThan(4);
    expect(authPaths).toContain("/cert/gha");
  });
});

describe("api-docs.grant-types", () => {
  it("advertises exactly the grant types the authority implements", () => {
    for (const grant of AUTHORITY_GRANT_TYPES) {
      expect(docs, `${grant} is implemented but undocumented`).toContain(grant);
    }
  });

  it("the sample discovery document matches the one actually served", () => {
    // The page's own example is what an integrator copies. It listed
    // oidc_token_exchange / github_actions_oidc / github_pat while the served
    // document listed github_actions_oidc / dpop, so the page contradicted
    // the authority on a capability claim.
    const sample = docs.match(/"grant_types_supported":\s*\[([^\]]*)\]/);
    expect(sample, "no grant_types_supported sample on the page").toBeTruthy();
    const listed = [...sample![1]!.matchAll(/"([^"]+)"/g)].map((m) => m[1]!);
    expect(listed).toEqual([...AUTHORITY_GRANT_TYPES]);
  });

  it("does not advertise a grant type that was never implemented", () => {
    // Both were published for a long time. The only permitted mentions are
    // the sentence saying they were removed.
    for (const ghost of ["oidc_token_exchange", "github_pat"]) {
      const mentions = docs.split(ghost).length - 1;
      expect(mentions, `${ghost} appears ${mentions}x`).toBeLessThanOrEqual(1);
    }
    expect(docs).toMatch(/Neither was ever implemented/);
  });
});

describe("api-docs.no-private-key", () => {
  it("never shows a private key in a response example", () => {
    // The property the secretless design exists to provide. `private_key`
    // survives only inside the note saying no endpoint returns one.
    expect(docs).not.toContain("BEGIN PRIVATE KEY");
    expect(docs).not.toMatch(/private key returned once/i);
    expect(docs).toMatch(/notme never sends a private key/);
    expect(docs).toMatch(/No endpoint returns a private key/i);
  });

  it("the authority landing page does not promise one either", () => {
    expect(authPage).not.toContain("private_key");
    expect(authPage).not.toContain("BEGIN PRIVATE KEY");
    expect(authPage).toMatch(/No private key is sent, ever/);
  });

  it("agrees with the code: no route emits a private_key field", () => {
    // If this ever fails, the DOC is the honest one and the code regressed.
    expect(workerSrc).not.toMatch(/private_key\s*:/);
  });
});

describe("api-docs.cert-gha-request", () => {
  it("the landing page's copyable curl carries the required body", () => {
    // It was a bare `-H Authorization` with no body: production answers 400
    // "public_keys.mtls and public_keys.signing required". Assert the COMMAND
    // has a -d, not merely that the page mentions the fields somewhere —
    // prose about a body does not make the copy button work.
    const cmd = authPage.match(
      /curl -sS https:\/\/auth\.notme\.bot\/cert\/gha[\s\S]{0,400}?<\/div>/,
    );
    expect(cmd, "no /cert/gha curl block on the landing page").toBeTruthy();
    expect(cmd![0]).toMatch(/-d /);
    expect(authPage).toContain("public_keys");
    expect(authPage).toContain("proofs");
  });

  it("shows the token in the Authorization header, where the route reads it", () => {
    // The old example put it in an `oidc_token` body field and omitted the
    // keys entirely, so the documented command answered 400.
    expect(docs).toMatch(/Authorization: Bearer \$\{ACTIONS_ID_TOKEN\}/);
    expect(docs).not.toContain('"oidc_token"');
    expect(docs).toContain('"public_keys"');
    expect(docs).toContain('"proofs"');
  });

  it("describes the binding as a pre-image, which is what is signed", () => {
    expect(docs).toMatch(/PRE-IMAGE/);
    expect(docs).toMatch(/never their digest/);
  });
});

describe("api-docs.ca-bundle", () => {
  it("says plainly that cRLSign is set and no CRL is published", () => {
    // Advertising the bit while publishing no list invites a verifier that
    // waits forever for one.
    expect(docs).toContain("cRLSign");
    expect(docs).toMatch(/no CRL and no CRL distribution point/);
  });
});
