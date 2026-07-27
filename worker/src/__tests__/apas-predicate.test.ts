import { describe, expect, it, vi } from "vitest";

vi.mock("cloudflare:workers", () => ({
  DurableObject: class {},
  WorkerEntrypoint: class {},
}));

const cacheMatch = vi.fn(async () => undefined);
const cachePut = vi.fn(async () => undefined);
vi.stubGlobal("caches", {
  default: {
    match: cacheMatch,
    put: cachePut,
  },
});

const { default: worker } = await import("../../worker");

describe("APAS dispatch predicate", () => {
  it("serves implementation-agnostic work-item vocabulary", async () => {
    const response = await worker.fetch(
      new Request("https://notme.bot/provenance/dispatch/v1", {
        headers: { Accept: "application/schema+json" },
      }),
      {},
    );

    expect(response.status).toBe(200);

    const schema = (await response.json()) as any;
    const properties = schema.properties.dispatchDefinition.properties;
    const workItem = properties.workItemRef;

    expect(workItem).toBeDefined();
    expect(workItem.properties.workItemId).toBeDefined();
    expect(workItem.required).toEqual([
      "repo",
      "workItemId",
      "contentHash",
    ]);
    expect(properties.beadRef).toBeUndefined();
  });

  it("preserves cache-busting queries and classifies schema JSON as JSON", async () => {
    cacheMatch.mockClear();

    await worker.fetch(
      new Request(
        "https://notme.bot/provenance/dispatch/v1?verify=deployment-123",
        {
          headers: { Accept: "application/schema+json" },
        },
      ),
      {},
    );

    const cacheRequest = cacheMatch.mock.calls[0]?.[0] as Request;
    const cacheUrl = new URL(cacheRequest.url);

    expect(cacheUrl.searchParams.get("verify")).toBe("deployment-123");
    expect(cacheUrl.searchParams.get("_accept")).toBe("json");
    expect(cacheUrl.searchParams.get("_cache")).toBe("v2");
  });
});
