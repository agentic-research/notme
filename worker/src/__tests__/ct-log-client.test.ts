import { describe, expect, it } from "vitest";
import { postChain, postPreChain, submitChain, submitPreChain } from "../ct/log-client";

const id = btoa(String.fromCharCode(...new Uint8Array(32).fill(7)));
const validSct = {
  sct_version: 0,
  id,
  timestamp: 1700000000000,
  extensions: btoa("ext"),
  signature: btoa(String.fromCharCode(4, 3, 0, 3, 1, 2, 3)),
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

  it("returns null within the bound when fetch never resolves", async () => {
    const never = fake((init) => new Promise<Response>((_, rej) => {
      init?.signal?.addEventListener("abort", () => rej(init.signal!.reason));
    }));
    const t0 = Date.now();
    expect(await submitPreChain(never, ["AA=="], 500)).toBeNull();
    expect(Date.now() - t0).toBeLessThan(1500);
  });

  it("times out even when fetch ignores the abort signal", async () => {
    const t0 = Date.now();
    expect(await submitPreChain(fake(() => new Promise(() => {})), ["AA=="], 500)).toBeNull();
    expect(Date.now() - t0).toBeLessThan(1500);
  });

  it("passes an abort signal that fires at the deadline", async () => {
    let sig: AbortSignal | undefined;
    const f = fake((init) => {
      sig = init?.signal ?? undefined;
      return new Promise(() => {});
    });
    await submitPreChain(f, ["AA=="], 200);
    expect(sig).toBeDefined();
    expect(sig!.aborted).toBe(true);
  });

  it("returns null when headers arrive but the body never ends, and cancels it", async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      pull() { return new Promise(() => {}); },
      cancel() { cancelled = true; },
    });
    const t0 = Date.now();
    expect(
      await submitPreChain(fake(() => Promise.resolve(new Response(body, { status: 200 }))), ["AA=="], 300),
    ).toBeNull();
    expect(Date.now() - t0).toBeLessThan(1300);
    await new Promise((r) => setTimeout(r, 20));
    expect(cancelled).toBe(true);
  });

  it("never throws on a negative or NaN timeout", async () => {
    await expect(submitPreChain(fake(() => json(validSct)), ["AA=="], -5)).resolves.not.toThrow();
    expect(await submitPreChain(fake(() => new Promise(() => {})), ["AA=="], -5)).toBeNull();
    expect(await submitPreChain(fake(() => json(validSct)), ["AA=="], NaN)).toEqual(validSct);
  });

  it("rejects strictly-malformed SCTs", async () => {
    const sig = (...b: number[]) => btoa(String.fromCharCode(...b));
    for (const bad of [
      { ...validSct, signature: "" },
      { ...validSct, signature: sig(4, 3, 0, 5, 1, 2, 3) },
      { ...validSct, signature: sig(4, 3, 0, 0) },
      { ...validSct, id: id.slice(0, -1) },
      { ...validSct, id: id.slice(0, 10) + "\n" + id.slice(10) },
      { ...validSct, extensions: " " + btoa("ext") },
      { ...validSct, extensions: "ZXh0\n" },
      { ...validSct, timestamp: -1 },
      { ...validSct, timestamp: 1.5 },
    ]) {
      expect(await submitPreChain(fake(() => json(bad)), ["AA=="])).toBeNull();
    }
  });

  it("normalises to the five fields", async () => {
    const got = await submitPreChain(fake(() => json({ ...validSct, extra: 1 })), ["AA=="]);
    expect(got).toEqual(validSct);
    expect(Object.keys(got!).sort()).toEqual(["extensions", "id", "sct_version", "signature", "timestamp"]);
  });
});

describe("submitChain", () => {
  it("is true on a 200 carrying a valid SCT, at add-chain", async () => {
    const seen: Seen[] = [];
    expect(await submitChain(fake(() => json(validSct), seen), ["AA=="])).toBe(true);
    expect(seen[0].url).toBe("https://ct-log/logs/notme/ct/v1/add-chain");
    expect(JSON.parse(seen[0].body!)).toEqual({ chain: ["AA=="] });
  });
  it("is false on a 200 with a garbage or HTML body", async () => {
    const html = () => Promise.resolve(new Response("<html>ok</html>", { status: 200 }));
    expect(await submitChain(fake(html), ["AA=="])).toBe(false);
    expect(await submitChain(fake(() => json({})), ["AA=="])).toBe(false);
  });
  it("is false on 500, network error and timeout", async () => {
    expect(await submitChain(fake(() => json(validSct, 500)), ["AA=="])).toBe(false);
    expect(await submitChain(fake(() => Promise.reject(new Error("x"))), ["AA=="])).toBe(false);
    const t0 = Date.now();
    expect(await submitChain(fake(() => new Promise(() => {})), ["AA=="], 300)).toBe(false);
    expect(Date.now() - t0).toBeLessThan(1300);
  });
});

describe("postPreChain / postChain — the reason health records", () => {
  it("ok carries the SCT", async () => {
    expect(await postPreChain(fake(() => json(validSct)), ["AA=="])).toEqual({ ok: true, sct: validSct });
  });

  it("names the HTTP status, a timeout, an invalid SCT, and a network error", async () => {
    expect(await postPreChain(fake(() => json(validSct, 503)), ["AA=="])).toEqual({ ok: false, reason: "HTTP 503" });
    expect(await postChain(fake(() => json(validSct, 429)), ["AA=="])).toEqual({ ok: false, reason: "HTTP 429" });
    expect(await postPreChain(fake(() => new Promise(() => {})), ["AA=="], 100)).toEqual({ ok: false, reason: "timeout" });
    expect(await postPreChain(fake(() => json({ ...validSct, sct_version: 1 })), ["AA=="])).toEqual({ ok: false, reason: "invalid SCT" });
    expect(await postPreChain(fake(() => Promise.resolve(new Response("nope"))), ["AA=="])).toEqual({ ok: false, reason: "invalid SCT" });
    expect(await postPreChain(fake(() => Promise.reject(new Error("down"))), ["AA=="])).toEqual({ ok: false, reason: "network error" });
  });

  it("postChain posts to add-chain", async () => {
    const seen: Seen[] = [];
    await postChain(fake(() => json(validSct), seen), ["AA=="]);
    expect(seen[0]!.url).toBe("https://ct-log/logs/notme/ct/v1/add-chain");
  });
});
