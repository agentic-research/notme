import { describe, expect, it, vi } from "vitest";

vi.mock("cloudflare:workers", () => ({
  DurableObject: class {},
  WorkerEntrypoint: class {},
}));

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
});
