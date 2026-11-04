/// <reference types="@cloudflare/vitest-pool-workers/types" />
/**
 * version-id-disclosure.do.test.ts — /.well-known/version names the
 * Cloudflare version id ONLY to a request that already pins it
 * (notme-325916, re-review N2).
 *
 * Cloudflare honours `Cloudflare-Workers-Version-Overrides` for any client. A
 * public version id lets an outsider pin themselves to either version of a
 * canary — e.g. stay on the OLD build through the canary of a security fix.
 * The verifier always sends the pin, so it still sees the id.
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../worker";

const ID = "4e700000-0000-4000-8000-000000000000";
const OTHER = "01d00000-0000-4000-8000-000000000000";

async function version(headers: Record<string, string> = {}, bound = true) {
  const res = await worker.fetch(new Request("https://auth.notme.bot/.well-known/version", { headers }), {
    ...env,
    BUILD_SHA: "a".repeat(40),
    ...(bound ? { CF_VERSION_METADATA: { id: ID, tag: "", timestamp: "" } } : {}),
  } as never);
  expect(res.status).toBe(200);
  return (await res.json()) as Record<string, unknown>;
}

describe("version id disclosure (re-review N2)", () => {
  it("an unpinned request learns the commit but not the version id", async () => {
    const body = await version();
    expect(body.commit).toBe("a".repeat(40));
    expect(body).not.toHaveProperty("version_id");
  });

  it("a request pinned to THIS version gets the id back", async () => {
    const body = await version({ "Cloudflare-Workers-Version-Overrides": `notme-bot="${ID}"` });
    expect(body.version_id).toBe(ID);
  });

  it("a request pinned to ANOTHER version learns nothing about this one", async () => {
    const body = await version({ "Cloudflare-Workers-Version-Overrides": `notme-bot="${OTHER}"` });
    expect(body).not.toHaveProperty("version_id");
  });

  it("no binding → no id, even when pinned", async () => {
    const body = await version({ "Cloudflare-Workers-Version-Overrides": `notme-bot="${ID}"` }, false);
    expect(body).not.toHaveProperty("version_id");
  });
});
