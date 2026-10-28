/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * do-rpc-trust-boundary.do.test.ts — the DO derives the subject, the caller
 * does not assert it (notme-51ccd7).
 *
 * THE DEFECT. `AuthService.mintBridgeCert(subject, publicKeyPem, ttlMs)` took
 * the subject as a plain STRING and passed it through `SigningAuthority`
 * straight to `mintGHABridgeCert`, which signed it. Nothing between the RPC
 * boundary and the signature checked that the caller was entitled to that
 * subject. The docstring said "for a verified subject" — an assumption about
 * the caller standing in for a check.
 *
 * `AuthService` is an exported `WorkerEntrypoint`, and `mintBridgeCert` is in
 * the REVIEWED allow-list at rpc-surface.do.test.ts. So the exposure was
 * deliberate: the review asked "may a service-binding holder call this",
 * which is the right question, and never asked "does this method trust its
 * argument", which is the one that bites. Per ADR-009 the binding holder is
 * every agent Worker.
 *
 * The irony was local. The comment immediately above it explains at length
 * why `#getAuthority` must be ECMAScript-private — handing out the DO stub
 * would allow "mintBridgeCertPair() with caller-chosen identity and scopes…
 * a complete CA compromise". The narrow door beside the locked one did
 * caller-chosen SUBJECT.
 *
 * FORWARD-PORTED, NOT REDESIGNED. The private agentic-research/notme.bot repo
 * diagnosed and fixed this on 2026-05-18 (`1d1ec7e`, bead notme.bot-69a3a9)
 * and the fix never reached the deployed repo — it sat five months in a repo
 * whose code has never run (notme-4e02fb). The shape here is that one's:
 * a `MintBridgeCertProof` discriminated union the DO re-verifies internally.
 *
 * NOTE THE ABSENT FIELD. The envelope carries no `audience`. An early draft
 * had one and a review removed it: an audience supplied by the caller is an
 * audience the caller can widen, which would hand back the whole defect in a
 * new wrapper. It comes from the DO's own env.
 */
import { env } from "cloudflare:test";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type GhaSigner, installGhaSigner, spkiPem } from "./__tests__/helpers/gha-token";

const OWNER = "agentic-research";
const REPO = "notme";
const AUDIENCE = "notme.bot";

let signer: GhaSigner;
let subjectPem: string;

// ONE keypair per file: validateGHAToken caches JWKS at module scope for an
// hour, so a second would be verified against the first's cached key.
beforeAll(async () => {
  signer = await installGhaSigner({ owner: OWNER, repo: REPO, audience: AUDIENCE });
  const kp = (await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  subjectPem = await spkiPem(kp.publicKey);
});
afterAll(() => signer.restore());


const authority = (name: string) =>
  env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(name));

describe("mintBridgeCert derives the subject from evidence (notme-51ccd7)", () => {
  it("REFUSES a bare subject string — the regression this file exists for", async () => {
    const stub = authority("tb-bare-subject");
    // Exactly the old call shape, which MINTED. Measured with a direct probe
    // before the fix, because an earlier version of this test asserted only
    // `rejects.toThrow()` and PASSED against the unfixed code — for the wrong
    // reason, almost certainly a PEM the minter rejected rather than a
    // subject it refused. The probe's result, verbatim:
    //
    //   MINTED subject="wimse://notme.bot/i-am-whoever"
    //
    // A string has no `kind`, so it lands in the exhaustive branch.
    const r = await (stub as unknown as {
      mintBridgeCert(s: string, p: string): Promise<{ ok: boolean; reason?: string }>;
    }).mintBridgeCert("wimse://notme.bot/i-am-whoever-i-say", subjectPem);
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("unknown_proof_kind");
  });

  it("mints for the subject the VERIFIED token names", async () => {
    const stub = authority("tb-valid-proof");
    const token = await signer.token();
    const r = await stub.mintBridgeCert({ kind: "gha-oidc", token }, subjectPem);
    expect(r.ok).toBe(true);
    if (!r.ok) throw new Error("unreachable");
    // The subject is the OIDC `sub`, derived inside the DO.
    expect(r.subject).toBe(`repo:${OWNER}/${REPO}:ref:refs/heads/main`);
    expect(r.certificate).toContain("BEGIN CERTIFICATE");
  });

  it("refuses a token whose signature was tampered with", async () => {
    const stub = authority("tb-forged");
    const token = await signer.token();
    const [h, pl, sig] = token.split(".");
    // Flip a character in the MIDDLE of the signature. The last base64url
    // character of an RSA signature encodes padding bits, so flipping it can
    // leave the signature valid — a trap this repo has fallen into before.
    const mid = Math.floor(sig!.length / 2);
    const flipped = sig![mid] === "A" ? "B" : "A";
    const forged = `${h}.${pl}.${sig!.slice(0, mid)}${flipped}${sig!.slice(mid + 1)}`;
    const r = await stub.mintBridgeCert({ kind: "gha-oidc", token: forged }, subjectPem);
    expect(r).toEqual({ ok: false, reason: "invalid_gha_token" });
  });

  it("refuses a wrong-audience token, and the caller cannot widen the audience", async () => {
    const stub = authority("tb-audience");
    const wrongAud = await signer.token({ aud: "https://example.invalid" });
    expect(
      await stub.mintBridgeCert({ kind: "gha-oidc", token: wrongAud }, subjectPem),
    ).toEqual({ ok: false, reason: "invalid_gha_token" });
    // There is no envelope field through which to assert the audience. If one
    // is ever added this stops compiling, and the reviewer gets to ask why
    // the caller is choosing it.
    expect(
      await stub.mintBridgeCert(
        // @ts-expect-error — `audience` is deliberately not part of the proof.
        { kind: "gha-oidc", token: wrongAud, audience: "https://example.invalid" },
        subjectPem,
      ),
    ).toEqual({ ok: false, reason: "invalid_gha_token" });
  });

  it("refuses an unknown proof kind rather than falling through", async () => {
    const stub = authority("tb-unknown-kind");
    expect(
      // @ts-expect-error — exhaustiveness is enforced at runtime as well.
      await stub.mintBridgeCert({ kind: "trust-me-bro", token: "x" }, subjectPem),
    ).toEqual({ ok: false, reason: "unknown_proof_kind" });
  });

  it("refuses an invalid session cookie", async () => {
    const stub = authority("tb-bad-cookie");
    expect(
      await stub.mintBridgeCert(
        { kind: "session-cookie", cookie: "not.a.valid.cookie" },
        subjectPem,
      ),
    ).toEqual({ ok: false, reason: "invalid_session" });
  });

  it("never leaks WHY a proof failed — the reason is coarse on purpose", async () => {
    // validateGHAToken throws messages like "wrong audience: <value>".
    // Echoing those to whoever supplied the token is free reconnaissance, so
    // a forged signature and a wrong audience are INDISTINGUISHABLE to the
    // caller. The detail goes to the log.
    const stub = authority("tb-no-leak");
    const wrongAud = await signer.token({ aud: "https://example.invalid" });
    const token = await signer.token();
    const [h, pl, sig] = token.split(".");
    const mid = Math.floor(sig!.length / 2);
    const forged = `${h}.${pl}.${sig!.slice(0, mid)}${sig![mid] === "A" ? "B" : "A"}${sig!.slice(mid + 1)}`;

    const a = await stub.mintBridgeCert({ kind: "gha-oidc", token: wrongAud }, subjectPem);
    const b = await stub.mintBridgeCert({ kind: "gha-oidc", token: forged }, subjectPem);
    expect(a).toEqual(b);
    expect(JSON.stringify(a)).not.toMatch(/audience|signature|example\.invalid/i);
  });
});

// ── notme's own access token as evidence (rig-098326) ───────────────────────
//
// WHY THIS KIND EXISTS. rig/web holds an AUTH service binding and called
// `mintBridgeCert(userId, publicKeyPem)` — the old shape, asserting the
// subject. After notme-51ccd7 it gets `unknown_proof_kind`, which is correct,
// and leaves rig with nothing to present: it has no GHA OIDC token, and
// notme's session cookie is scoped to notme.bot so a browser never sends it to
// rosary.bot.
//
// What rig CAN hold is a notme-issued `at+jwt`. notme already mints them to
// authenticated principals (/token, /authorize/token — both session-gated,
// both audience-checked) and rig already verifies them (its /admin/setup-github
// path). Presenting one back to the authority that signed it is evidence in
// the same sense a GHA token is: the DO checks its OWN signature and reads the
// subject out of the verified claims. The caller supplies a token, never a
// name.
//
// THIS KIND WAS NOT SAFE TO ADD UNTIL notme-d68da8 LANDED. `AuthService`
// exposed `mintDPoPToken({ sub, scope, audience, jkt })`, which signed a
// caller-chosen subject with the master key — so any binding holder could mint
// a token naming anyone and feed it straight back in here. Accepting tokens as
// proof while that method existed would have reopened notme-51ccd7 through a
// second door, with the forgery laundered through a real signature. The
// deletion is the precondition, which is why the two changes ship together.
describe("mintBridgeCert accepts a notme-issued access token (rig-098326)", () => {
  const AUD = "https://rosary.bot"; // on DEFAULT_ALLOWED_AUDIENCES

  it("mints for the sub the VERIFIED token names", async () => {
    const stub = authority("tb-at-valid");
    const token = await stub.mintRedirectToken({
      sub: "github-99",
      scope: "bridgeCert",
      audience: AUD,
    });
    const r = await stub.mintBridgeCert({ kind: "notme-access-token", token }, subjectPem);
    expect(r.ok).toBe(true);
    if (!r.ok) throw new Error("unreachable");
    expect(r.subject).toBe("github-99");
    expect(r.certificate).toContain("BEGIN CERTIFICATE");
  });

  it("refuses a token signed by a DIFFERENT authority", async () => {
    // Each named DO id owns its own master key, so this is a real
    // cross-authority token, not a mutated one. A verifier that trusted the
    // claims without checking the signature against ITS OWN key would mint
    // here — which is the whole point of doing the check inside the DO.
    const foreign = await authority("tb-at-other-authority").mintRedirectToken({
      sub: "github-99",
      scope: "bridgeCert",
      audience: AUD,
    });
    expect(
      await authority("tb-at-foreign").mintBridgeCert(
        { kind: "notme-access-token", token: foreign },
        subjectPem,
      ),
    ).toEqual({ ok: false, reason: "invalid_access_token" });
  });

  it("refuses a token whose audience is not on this authority's allowlist", async () => {
    // The authority will sign any audience it is asked for — getAllowedAudiences
    // is enforced by the ROUTES, and this proof path does not go through one.
    // So the check has to be here, or a token minted for one resource server
    // is spendable at every other.
    const stub = authority("tb-at-audience");
    const token = await stub.mintRedirectToken({
      sub: "github-99",
      scope: "bridgeCert",
      audience: "https://attacker.invalid",
    });
    expect(
      await stub.mintBridgeCert({ kind: "notme-access-token", token }, subjectPem),
    ).toEqual({ ok: false, reason: "invalid_access_token" });
  });

  it("refuses a token that does not carry bridgeCert scope", async () => {
    // A read token is not a minting token. /cert defaults requestedScopes to
    // ["bridgeCert"] and /cert/gha hardcodes it; a token whose principal was
    // never granted it must not become a certificate.
    const stub = authority("tb-at-scope");
    const token = await stub.mintRedirectToken({
      sub: "github-99",
      scope: "beads:read beads:write",
      audience: AUD,
    });
    expect(
      await stub.mintBridgeCert({ kind: "notme-access-token", token }, subjectPem),
    ).toEqual({ ok: false, reason: "invalid_access_token" });
  });

  it("refuses scope that merely CONTAINS bridgeCert as a substring", async () => {
    // `scope` is a space-delimited list (RFC 6749 §3.3), so the check must
    // split it. `includes("bridgeCert")` would pass for "notbridgeCertish",
    // which is the mutation this case kills.
    const stub = authority("tb-at-scope-substring");
    const token = await stub.mintRedirectToken({
      sub: "github-99",
      scope: "notbridgeCertish",
      audience: AUD,
    });
    expect(
      await stub.mintBridgeCert({ kind: "notme-access-token", token }, subjectPem),
    ).toEqual({ ok: false, reason: "invalid_access_token" });
  });

  it("refuses a token with an empty sub rather than minting a nameless cert", async () => {
    const stub = authority("tb-at-empty-sub");
    const token = await stub.mintRedirectToken({
      sub: "",
      scope: "bridgeCert",
      audience: AUD,
    });
    expect(
      await stub.mintBridgeCert({ kind: "notme-access-token", token }, subjectPem),
    ).toEqual({ ok: false, reason: "invalid_access_token" });
  });

  it("refuses a token whose signature was tampered with", async () => {
    const stub = authority("tb-at-tampered");
    const token = await stub.mintRedirectToken({
      sub: "github-99",
      scope: "bridgeCert",
      audience: AUD,
    });
    const [h, pl, sig] = token.split(".");
    // Middle of the signature, for the same reason as the GHA case above: the
    // final base64url character can encode padding bits and flipping it can
    // leave the signature valid.
    const mid = Math.floor(sig!.length / 2);
    const forged = `${h}.${pl}.${sig!.slice(0, mid)}${sig![mid] === "A" ? "B" : "A"}${sig!.slice(mid + 1)}`;
    expect(
      await stub.mintBridgeCert({ kind: "notme-access-token", token: forged }, subjectPem),
    ).toEqual({ ok: false, reason: "invalid_access_token" });
  });

  it("never leaks WHICH check the token failed", async () => {
    // Same discipline as the GHA path: a caller learns its token was rejected,
    // not whether the audience, the scope or the signature was the problem.
    // Telling it apart would let a holder of a wrong-audience token confirm
    // which audiences this authority accepts.
    const stub = authority("tb-at-no-leak");
    const wrongAud = await stub.mintRedirectToken({
      sub: "github-99",
      scope: "bridgeCert",
      audience: "https://attacker.invalid",
    });
    const wrongScope = await stub.mintRedirectToken({
      sub: "github-99",
      scope: "beads:read",
      audience: AUD,
    });
    const a = await stub.mintBridgeCert({ kind: "notme-access-token", token: wrongAud }, subjectPem);
    const b = await stub.mintBridgeCert({ kind: "notme-access-token", token: wrongScope }, subjectPem);
    expect(a).toEqual(b);
    expect(JSON.stringify(a)).not.toMatch(/audience|scope|signature|attacker\.invalid/i);
  });
});
