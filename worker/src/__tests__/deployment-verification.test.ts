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

  it("bypasses Cache API entries that can survive deployments", () => {
    expect(taskfile).toMatch(
      /ca-bundle\.pem\?verify=\$VERIFY_NONCE[\s\S]+BEGIN CERTIFICATE/,
    );
    expect(taskfile).toMatch(
      /jwks\.json\?verify=\$VERIFY_NONCE[\s\S]+"crv":"Ed25519"/,
    );
  });

  it("checks the unauthenticated passkey status contract", () => {
    expect(taskfile).toMatch(
      /passkey-status[\s\S]+auth\/passkey\/status[\s\S]+401[\s\S]+unauthorized/,
    );
  });
});
