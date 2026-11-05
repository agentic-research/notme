/**
 * auth-method-type.test.ts — a raw string is not an authMethod, at compile
 * time (notme-32003c).
 *
 * The assertions are the `@ts-expect-error` lines. `tsc -p
 * tsconfig.scripts.json` (task worker:check) fails if any of them stops being
 * an error, which is what would happen if a mint parameter went back to
 * `string`. The runtime `it` only keeps vitest from reporting an empty file.
 *
 * Every mint path that stamps a session-derived method into a credential
 * takes AuthMethod. A value of that type comes only from parseAuthMethod (or
 * the constants and constructors built on it), so a new route that hands a
 * mint an unchecked string does not compile: it inherits the check by
 * construction.
 */
import { describe, expect, it } from "vitest";
import { AUTH_METHOD, oidcAuthMethod, parseAuthMethod } from "../auth/session";
import type { SigningAuthority } from "../signing-authority";

type MintPairMethod = Parameters<SigningAuthority["mintBridgeCertPair"]>[0]["authMethod"];
type ApproveTierMethod = Parameters<SigningAuthority["approveTierEnrolment"]>[0]["authMethod"];

const raw: string = "passkey";

// @ts-expect-error a raw string cannot reach mintBridgeCertPair
export const mintPair: MintPairMethod = raw;
// @ts-expect-error nor can a string literal
export const mintPairLiteral: MintPairMethod = "passkey";
// @ts-expect-error a raw string cannot reach approveTierEnrolment
export const approveTier: ApproveTierMethod = raw;

// The ways a checked value is obtained, all of which compile:
export const fromConst: MintPairMethod = AUTH_METHOD.passkey;
export const fromOidc: MintPairMethod = oidcAuthMethod("https://accounts.example");
const parsed = parseAuthMethod(raw);
export const fromParse: MintPairMethod | null = parsed;
export const fromApprove: ApproveTierMethod = AUTH_METHOD.invite;

describe("AuthMethod (compile-time; see the @ts-expect-error lines)", () => {
  it("the checked constants and constructors produce the strings they name", () => {
    expect(AUTH_METHOD.ghaOidc).toBe("gha-oidc");
    expect(AUTH_METHOD.bootstrap).toBe("bootstrap");
    expect(oidcAuthMethod("https://i.example")).toBe("oidc:https://i.example");
    expect(parsed).toBe("passkey");
  });
});
