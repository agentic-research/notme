import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const taskfile = readFileSync(
  fileURLToPath(new URL("../../../Taskfile.yml", import.meta.url)),
  "utf8",
);

describe("post-deploy verification contract", () => {
  it("retries while a new Worker deployment converges", () => {
    expect(taskfile).toContain("MAX_ATTEMPTS=5");
    expect(taskfile).toContain("RETRY_DELAY_SECONDS=2");
    expect(taskfile).toContain('while [ "$attempt" -le "$MAX_ATTEMPTS" ]');
  });

  it("checks the DO-backed /.well-known documents", () => {
    expect(taskfile).toMatch(/ca-bundle\.pem"[\s\S]+BEGIN CERTIFICATE/);
    expect(taskfile).toMatch(/jwks\.json"[\s\S]+"crv":"Ed25519"/);
  });

  it("does not claim a query bypasses the /.well-known cache", () => {
    // It used to (notme-382e63). /.well-known/* keys now ignore the query
    // (notme-ed6114), so a nonce there would read as a bypass it is not;
    // what makes a post-deploy read fresh is the build in every key
    // (cache-build-key.test.ts).
    expect(taskfile).not.toMatch(/\.well-known\/[\w.-]+\?/);
  });

  it("checks the unauthenticated passkey status contract", () => {
    expect(taskfile).toMatch(
      /passkey-status[\s\S]+auth\/passkey\/status[\s\S]+401[\s\S]+unauthorized/,
    );
  });
});
