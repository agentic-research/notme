import { describe, expect, it } from "vitest";
import { submitChain, submitPreChain } from "../ct/log-client";

const id = btoa(String.fromCharCode(...new Uint8Array(32).fill(7)));
const validSct = {
  sct_version: 0,
  id,
  timestamp: 1700000000000,
  extensions: btoa("ext"),
  signature: btoa("sig"),
};

interface Seen {
  url: string;
  method?: string;
  body?: string;
}

function fake(
  respond: (init?: RequestInit) => Promise<Response>,
  seen: Seen[] = [],
): Fetcher {
  return {
    fetch: (input: RequestInfo | URL, init?: RequestInit) => {
      seen.push({ url: String(input), method: init?.method, body: init?.body as string });
      return respond(init);
    },
  } as unknown as Fetcher;
}

const json = (body: unknown, status = 200) =>
  Promise.resolve(new Response(JSON.stringify(body), { status }));

describe("submitPreChain", () => {
  it("returns a valid SCT", async () => {
    expect(await submitPreChain(fake(() => json(validSct)), ["AA=="])).toEqual(validSct);
  });

  it("posts { chain } to the add-pre-chain path under the prefix", async () => {
    const seen: Seen[] = [];
    await submitPreChain(fake(() => json(validSct), seen), ["QQ==", "Qg=="]);
    expect(seen).toHaveLength(1);
    expect(seen[0].url).toBe("https://ct-log/logs/notme/ct/v1/add-pre-chain");
    expect(seen[0].method).toBe("POST");
    expect(JSON.parse(seen[0].body!)).toEqual({ chain: ["QQ==", "Qg=="] });
  });

  it("honours a custom path prefix", async () => {
    const seen: Seen[] = [];
    await submitPreChain(fake(() => json(validSct), seen), ["AA=="], 2000, "/logs/other");
    expect(seen[0].url).toBe("https://ct-log/logs/other/ct/v1/add-pre-chain");
  });

  it("returns null for a malformed SCT", async () => {
    for (const bad of [
      { ...validSct, sct_version: 1 },
      { ...validSct, id: btoa("short") },
      { ...validSct, timestamp: "1" },
      { ...validSct, extensions: 5 },
      { ...validSct, signature: undefined },
      { ...validSct, signature: "not base64!!" },
      null,
    ]) {
      expect(await submitPreChain(fake(() => json(bad)), ["AA=="])).toBeNull();
    }
  });

  it("returns null on a non-JSON body", async () => {
    expect(
      await submitPreChain(fake(() => Promise.resolve(new Response("nope"))), ["AA=="]),
    ).toBeNull();
  });

  it("returns null on 500", async () => {
    expect(await submitPreChain(fake(() => json(validSct, 500)), ["AA=="])).toBeNull();
  });

  it("returns null on a network error, never throwing", async () => {
    expect(
      await submitPreChain(fake(() => Promise.reject(new Error("down"))), ["AA=="]),
    ).toBeNull();
  });

  it("returns null within timeoutMs + 100 when fetch never resolves", async () => {
    const never = fake((init) => new Promise<Response>((_, rej) => {
      init?.signal?.addEventListener("abort", () => rej(init.signal!.reason));
    }));
    const t0 = Date.now();
    expect(await submitPreChain(never, ["AA=="], 200)).toBeNull();
    expect(Date.now() - t0).toBeLessThan(300);
  });

  it("times out even when fetch ignores the abort signal", async () => {
    const t0 = Date.now();
    expect(await submitPreChain(fake(() => new Promise(() => {})), ["AA=="], 200)).toBeNull();
    expect(Date.now() - t0).toBeLessThan(300);
  });
});

describe("submitChain", () => {
  it("is true on 200 at add-chain", async () => {
    const seen: Seen[] = [];
    expect(await submitChain(fake(() => json(validSct), seen), ["AA=="])).toBe(true);
    expect(seen[0].url).toBe("https://ct-log/logs/notme/ct/v1/add-chain");
    expect(JSON.parse(seen[0].body!)).toEqual({ chain: ["AA=="] });
  });
  it("is false on 500, network error and timeout", async () => {
    expect(await submitChain(fake(() => json({}, 500)), ["AA=="])).toBe(false);
    expect(await submitChain(fake(() => Promise.reject(new Error("x"))), ["AA=="])).toBe(false);
    const t0 = Date.now();
    expect(await submitChain(fake(() => new Promise(() => {})), ["AA=="], 200)).toBe(false);
    expect(Date.now() - t0).toBeLessThan(300);
  });
});
