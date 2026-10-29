/**
 * threat-model-authorize.test.ts — the last THREAT_MODEL rows whose test
 * identifier named nothing (notme-8eed12).
 *
 * `authorize.state.csrf` is deliberately NOT here: that row's own defence
 * column says the state parameter is "validated by consuming app (rig checks
 * KV)", so there is no notme behaviour to test. Its test column now says so
 * rather than naming a test, which is the honest form of that claim.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { createSessionCookie, verifySessionCookie } from "../auth/session";

const root = fileURLToPath(new URL("../../", import.meta.url));

describe("authorize.return-to.validation", () => {
  /**
   * The guard lives in `_login.html`'s inline script, so this executes THAT
   * SOURCE rather than a copy of the rule. A reimplementation here would
   * test my transcription and pass while the page shipped something else —
   * the defect class this whole bead is about.
   */
  const page = readFileSync(`${root}public/_login.html`, "utf8");
  const guard = page.match(/if \(returnTo\.indexOf.*?returnTo = '\/me';/)?.[0];

  it("the page actually carries a guard", () => {
    expect(guard, "no return_to sanitizer found in _login.html").toBeTruthy();
  });

  const sanitize = (raw: string | null): string => {
    const fn = new Function(
      "raw",
      `var returnTo = raw || '/me'; ${guard} return returnTo;`,
    ) as (raw: string | null) => string;
    return fn(raw);
  };

  it("sends a protocol-relative URL to /me, not to the attacker", () => {
    // //evil.example is the payload the row names: a browser reads it as an
    // absolute URL on the current scheme, so it leaves the origin entirely.
    expect(sanitize("//evil.example")).toBe("/me");
    expect(sanitize("//evil.example/steal")).toBe("/me");
  });

  it("refuses anything that is not a same-origin absolute path", () => {
    for (const hostile of [
      "https://evil.example",
      "http://evil.example",
      "javascript:alert(1)",
      "evil.example",
      "\\\\evil.example",
      "",
    ]) {
      expect(sanitize(hostile), `${hostile || "(empty)"} must not survive`).toBe("/me");
    }
  });

  it("still allows the legitimate value the worker itself produces", () => {
    // worker.ts builds `/authorize?<query>` and redirects to
    // /login?return_to=<that>. A guard that refused it would break the flow
    // it exists to protect, and the test would not notice.
    expect(sanitize("/authorize?client_id=x&redirect_uri=y")).toBe(
      "/authorize?client_id=x&redirect_uri=y",
    );
    expect(sanitize("/me")).toBe("/me");
  });
});

describe("authorize.session.fixation", () => {
  const SECRET = "s".repeat(48);

  it("the cookie is SameSite=Strict, HttpOnly and Secure", async () => {
    // SameSite=Strict is the anti-fixation control the row names: a cookie
    // an attacker set through a cross-site navigation is not sent back on
    // the request that would complete the flow.
    const cookie = await createSessionCookie(
      { principalId: "p1", scopes: ["bridgeCert"], authMethod: "passkey" },
      SECRET,
    );
    expect(cookie).toContain("SameSite=Strict");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Secure");
  });

  it("carries user-specific claims, so a planted cookie is not anyone's session", async () => {
    const cookie = await createSessionCookie(
      { principalId: "victim", scopes: ["bridgeCert"], authMethod: "passkey" },
      SECRET,
    );
    const value = cookie.split(";")[0]!.split("=").slice(1).join("=");
    const session = await verifySessionCookie(value, SECRET);
    expect(session?.principalId).toBe("victim");
  });

  it("a cookie whose principal was swapped no longer verifies", async () => {
    // The fixation attack in its useful form: take a session you were given
    // and repoint it at someone else. The HMAC covers the claims, so it
    // cannot be repointed without the secret.
    const cookie = await createSessionCookie(
      { principalId: "attacker", scopes: ["bridgeCert"], authMethod: "passkey" },
      SECRET,
    );
    const value = cookie.split(";")[0]!.split("=").slice(1).join("=");
    const [payloadB64, sig] = value.split(".") as [string, string];
    const payload = JSON.parse(atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/")));
    payload.principalId = "victim";
    payload.userId = "victim";
    const forged = btoa(JSON.stringify(payload))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

    expect(await verifySessionCookie(`${forged}.${sig}`, SECRET)).toBeNull();
    // Control: the untouched cookie still verifies, so the null above is the
    // swap being caught and not the helper being broken.
    expect(await verifySessionCookie(value, SECRET)).not.toBeNull();
  });
});
