/**
 * proxy-gates.test.ts — the gates ADR-009 promises `AuthService.proxy()`
 * has, and the audit record that says which of them refused (notme-baea8c).
 *
 * proxy() used to permit every destination not on the metadata denylist,
 * attach a held cert without asking whether the authority had since moved
 * its epoch (revokeEpoch / rotate), and write `allowed: true` as a constant
 * after every check had already passed — so a refusal left no audit line.
 *
 *   proxy.allowlist.*  — PROXY_ALLOWED_DESTINATIONS, fail closed when unset
 *   proxy.epoch.*      — the held cert's epoch must equal the authority's
 *   proxy.audit.*      — `allowed` is the decision, written for denials too
 *
 * Real CA-signed certs, as the other AuthService suites use; the authority is
 * a stub returning the CA key and the epoch a test chooses.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { authenticateWithPop, makeCA, mintCreds, stubAuthority } from "./helpers/mint-creds";

vi.mock("cloudflare:workers", () => ({
  // AuthSession (src/auth/auth-session.ts) extends it (notme-153f03).
  RpcTarget: class RpcTarget {},
  WorkerEntrypoint: class WorkerEntrypoint {
    ctx: any;
    env: any;
    constructor(ctx: any, env: any) {
      this.ctx = ctx;
      this.env = env;
    }
  },
  DurableObject: class DurableObject {
    constructor(_s: any, _e: any) {}
  },
}));

import { AuthService } from "../../worker";
import type { AuthSession } from "../auth/auth-session";
import { isAllowedDestination, parseDestinationAllowlist } from "../destination-policy";

const CA = await makeCA();
const IDENTITY = "wimse://notme.bot/gha/proxy-gates";

function service(vars: Record<string, unknown>, authorityEpoch: number | "throw" = 1) {
  // The PoP-nonce store authenticate() spends its challenge in, plus the
  // epoch proxy() reads (notme-fbbfbc).
  const authority = stubAuthority(CA, {
    getAuthorityState: async () => {
      if (authorityEpoch === "throw") throw new Error("DO unavailable");
      return { epoch: authorityEpoch, seqno: 1, keyId: "k" };
    },
  });
  const env = {
    ...vars,
    SIGNING_AUTHORITY: {
      idFromName: () => "default",
      get: () => authority,
    },
  };
  return new (AuthService as unknown as new (ctx: unknown, env: unknown) => AuthService)(null, env);
}

async function authed(vars: Record<string, unknown>, opts: { authorityEpoch?: number | "throw"; certEpoch?: number } = {}) {
  // proxy() is a method of the AuthSession authenticate() returns
  // (notme-153f03), so `authed` hands back the session.
  const svc = service(vars, opts.authorityEpoch ?? 1);
  return authenticateWithPop(svc, await mintCreds(CA, IDENTITY, ["bridgeCert"], opts.certEpoch ?? 1));
}

/** A session whose stub was disposed: it holds nothing any more. */
async function disposed(vars: Record<string, unknown>) {
  const session = await authed(vars);
  session[Symbol.dispose]();
  return session;
}

let fetchSpy: ReturnType<typeof vi.fn>;
let logs: string[];
beforeEach(() => {
  fetchSpy = vi.fn(async () => new Response("ok", { status: 200 }));
  vi.stubGlobal("fetch", fetchSpy);
  logs = [];
  vi.spyOn(console, "log").mockImplementation((line: unknown) => {
    logs.push(String(line));
  });
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const audits = () =>
  logs
    .map((l) => {
      try {
        return JSON.parse(l);
      } catch {
        return null;
      }
    })
    .filter((e) => e?.type === "proxy");

const ALLOW = { PROXY_ALLOWED_DESTINATIONS: "api.github.com, *.notme.bot" };

describe("proxy.allowlist — destinations come from PROXY_ALLOWED_DESTINATIONS (notme-baea8c)", () => {
  it("proxy.allowlist.unset-denies — with no allowlist configured, nothing is proxied", async () => {
    const svc = await authed({});
    await expect(svc.proxy({ url: "https://api.github.com/zen" })).rejects.toThrow(/allowlist/);
    expect(fetchSpy).not.toHaveBeenCalled();
    // And an empty value is the same as unset.
    const empty = await authed({ PROXY_ALLOWED_DESTINATIONS: " , " });
    await expect(empty.proxy({ url: "https://api.github.com/zen" })).rejects.toThrow(/allowlist/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("proxy.allowlist.permits-listed — a listed host is proxied, with redirects NOT followed", async () => {
    const svc = await authed(ALLOW);
    const res = await svc.proxy({ url: "https://api.github.com/zen" });
    expect(res.status).toBe(200);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    // A followed redirect would let a listed host send the request anywhere.
    expect(fetchSpy.mock.calls[0]![1]).toMatchObject({ redirect: "manual" });
    await svc.proxy({ url: "https://a.notme.bot/x" });
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it("proxy.allowlist.refuses-unlisted — lookalikes, the bare apex of a wildcard, other ports and http are refused", async () => {
    const svc = await authed(ALLOW);
    for (const url of [
      "https://evil.example/",
      "https://api.github.com.evil.example/",
      "https://evilapi.github.com/",
      "https://notme.bot/", // "*.notme.bot" names subdomains, not the apex
      "https://api.github.com:8443/",
      "http://api.github.com/",
      "https://api.github.com@evil.example/",
    ]) {
      await expect(svc.proxy({ url }), url).rejects.toThrow(/allowlist/);
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("proxy.allowlist.denylist-wins — listing a metadata address does not unblock it", async () => {
    const svc = await authed({ PROXY_ALLOWED_DESTINATIONS: "169.254.169.254" });
    await expect(svc.proxy({ url: "https://169.254.169.254/latest/meta-data" })).rejects.toThrow(/denied/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("proxy.allowlist.parse — a bare '*' or a mid-label wildcard is not an entry", () => {
    expect([...parseDestinationAllowlist("*, *.com.*, a*.b.com, API.GitHub.com, *.Notme.bot")]).toEqual([
      "api.github.com",
      "*.notme.bot",
    ]);
    expect(parseDestinationAllowlist(undefined).size).toBe(0);
    const list = parseDestinationAllowlist("api.github.com");
    expect(isAllowedDestination("https://API.GITHUB.COM/x", list)).toBe(true);
    expect(isAllowedDestination("https://api.github.com./x", list)).toBe(false);
  });
});

describe("proxy.epoch — a held cert from a moved epoch is not attached (notme-baea8c)", () => {
  it("proxy.epoch.mismatch — after revokeEpoch / rotate, the held cert is refused", async () => {
    const svc = await authed(ALLOW, { authorityEpoch: 2, certEpoch: 1 });
    await expect(svc.proxy({ url: "https://api.github.com/zen" })).rejects.toThrow(/epoch/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("proxy.epoch.future — a cert claiming a later epoch than the authority's is refused too", async () => {
    const svc = await authed(ALLOW, { authorityEpoch: 1, certEpoch: 5 });
    await expect(svc.proxy({ url: "https://api.github.com/zen" })).rejects.toThrow(/epoch/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("proxy.epoch.match — the current epoch proxies", async () => {
    const svc = await authed(ALLOW, { authorityEpoch: 3, certEpoch: 3 });
    expect((await svc.proxy({ url: "https://api.github.com/zen" })).status).toBe(200);
  });
});

describe("proxy.audit — the record says what was decided (notme-baea8c)", () => {
  it("proxy.audit.denied — a refused request logs allowed:false with its reason", async () => {
    const svc = await authed({});
    await expect(svc.proxy({ url: "https://api.github.com/zen" })).rejects.toThrow();
    const [entry] = audits();
    expect(entry).toMatchObject({
      type: "proxy",
      identity: IDENTITY,
      destination: "https://api.github.com/zen",
      allowed: false,
      reason: "destination_not_allowed",
    });
    expect(entry.response_status).toBeUndefined();
  });

  it("proxy.audit.denied — each gate names itself", async () => {
    const reasons: string[] = [];
    const cases: Array<[AuthSession, string]> = [
      [await disposed(ALLOW), "https://api.github.com/"], // credentials dropped
      [await authed(ALLOW), "https://169.254.169.254/"],
      [await authed(ALLOW, { authorityEpoch: 9 }), "https://api.github.com/"],
    ];
    for (const [svc, url] of cases) {
      await expect(svc.proxy({ url })).rejects.toThrow();
    }
    for (const e of audits()) {
      expect(e.allowed).toBe(false);
      reasons.push(e.reason);
    }
    expect(reasons).toEqual(["not_authenticated", "destination_denied", "epoch_mismatch"]);
  });

  it("proxy.audit.allowed — a proxied request logs allowed:true with the response status", async () => {
    const svc = await authed(ALLOW);
    await svc.proxy({ url: "https://api.github.com/zen" });
    const [entry] = audits();
    expect(entry).toMatchObject({ allowed: true, response_status: 200, scope_checked: "bridgeCert" });
    expect(entry.reason).toBeUndefined();
  });
});

// ── Review follow-ups (security review of D3: F5, F6, F7, F8) ──────────────

describe("proxy.allowlist.parse — entries an operator cannot have meant (review F5)", () => {
  it("proxy.allowlist.parse.public-suffix — a wildcard over a single label or a public suffix is dropped", () => {
    const list = parseDestinationAllowlist("*.com, *.co.uk, *.github.io, *.example.com");
    expect([...list]).toEqual(["*.example.com"]);
    expect(isAllowedDestination("https://anything.com/", list)).toBe(false);
  });

  it("proxy.allowlist.parse.ip-wildcard — a wildcard over an IP literal is dropped", () => {
    const list = parseDestinationAllowlist("*.0.0.1, *.[::1], *.10.0.0.1");
    expect(list.size).toBe(0);
    expect(isAllowedDestination("https://127.0.0.1/", list)).toBe(false);
    // An exact IP literal is still an entry (and the denylist still runs first).
    expect([...parseDestinationAllowlist("10.0.0.1")]).toEqual(["10.0.0.1"]);
  });

  it("proxy.allowlist.parse.idn — a Unicode entry is stored as the punycode the URL parser yields", () => {
    const list = parseDestinationAllowlist("bücher.de, *.bücher.de");
    expect([...list]).toEqual(["xn--bcher-kva.de", "*.xn--bcher-kva.de"]);
    expect(isAllowedDestination("https://bücher.de/x", list)).toBe(true);
    expect(isAllowedDestination("https://shop.bücher.de/x", list)).toBe(true);
  });

  it("proxy.allowlist.parse.shape — paths, userinfo and queries are not hosts", () => {
    expect(parseDestinationAllowlist("api.github.com/x, u@api.github.com, api.github.com?q, a b").size).toBe(0);
  });
});

describe("proxy forwarding — headers and the authority's own host (review F6)", () => {
  it("proxy.headers.stripped — Host, cf-*, x-forwarded-* and hop-by-hop headers are not forwarded", async () => {
    const svc = await authed(ALLOW);
    await svc.proxy({
      url: "https://api.github.com/zen",
      headers: {
        Host: "internal.example",
        "CF-Connecting-IP": "1.2.3.4",
        "cf-worker": "x",
        "X-Forwarded-For": "1.2.3.4",
        "X-Forwarded-Host": "internal.example",
        Forwarded: "for=1.2.3.4",
        Connection: "keep-alive, X-Secret-Hop",
        "X-Secret-Hop": "1",
        "Keep-Alive": "timeout=5",
        "Transfer-Encoding": "chunked",
        Upgrade: "websocket",
        "Proxy-Authorization": "Basic x",
        TE: "trailers",
        Trailer: "x",
        Accept: "application/json",
        Authorization: "Bearer caller-token",
      },
    });
    const sent = fetchSpy.mock.calls[0]![1] as RequestInit;
    const names = Object.keys(sent.headers as Record<string, string>).map((n) => n.toLowerCase()).sort();
    expect(names).toEqual(["accept", "authorization"]);
  });

  it("proxy.self.refused — the authority's own host is refused under a wildcard, allowed only when listed exactly", async () => {
    const vars = { PROXY_ALLOWED_DESTINATIONS: "*.notme.bot", SIGNET_AUTHORITY_URL: "https://auth.notme.bot" };
    const svc = await authed(vars);
    await expect(svc.proxy({ url: "https://auth.notme.bot/admin" })).rejects.toThrow(/authority/);
    expect(audits().at(-1)).toMatchObject({ allowed: false, reason: "destination_self" });
    expect(fetchSpy).not.toHaveBeenCalled();
    // Another subdomain under the same wildcard is fine…
    expect((await svc.proxy({ url: "https://docs.notme.bot/" })).status).toBe(200);
    // …and listing the host itself is the explicit opt-in.
    const optIn = await authed({ ...vars, PROXY_ALLOWED_DESTINATIONS: "*.notme.bot, auth.notme.bot" });
    expect((await optIn.proxy({ url: "https://auth.notme.bot/x" })).status).toBe(200);
  });
});

describe("proxy.audit — every exit writes its line (review F7, F8)", () => {
  it("proxy.audit.authority-unavailable — an epoch RPC that throws is a logged refusal, and nothing is fetched", async () => {
    const svc = await authed(ALLOW, { authorityEpoch: "throw" });
    await expect(svc.proxy({ url: "https://api.github.com/zen" })).rejects.toThrow(/authority unavailable/);
    expect(audits().at(-1)).toMatchObject({ allowed: false, reason: "authority_unavailable" });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("proxy.audit.body-error — a response body that fails to read still writes the line", async () => {
    fetchSpy.mockImplementationOnce(async () => {
      const r = new Response("x", { status: 200 });
      Object.defineProperty(r, "text", { value: async () => { throw new Error("stream reset"); } });
      return r;
    });
    const svc = await authed(ALLOW);
    await expect(svc.proxy({ url: "https://api.github.com/zen" })).rejects.toThrow(/stream reset/);
    expect(audits().at(-1)).toMatchObject({ allowed: true, response_status: 200, error: "stream reset" });
  });

  it("proxy.audit.invalid-url — an unparseable URL is destination_invalid, not destination_denied", async () => {
    const svc = await authed(ALLOW);
    await expect(svc.proxy({ url: "not a url" })).rejects.toThrow(/invalid/);
    expect(audits().at(-1)).toMatchObject({ allowed: false, reason: "destination_invalid" });
  });

  it("proxy.audit.redacted — userinfo and the query are not logged, and the line is bounded", async () => {
    const svc = await authed({ PROXY_ALLOWED_DESTINATIONS: "api.github.com" });
    await svc.proxy({ url: "https://user:hunter2@api.github.com/repos?token=s3cret#frag" });
    const line = logs.at(-1)!;
    expect(line).not.toMatch(/hunter2|s3cret|user:|frag/);
    expect(audits().at(-1).destination).toBe("https://api.github.com/repos?<redacted>");
    await svc.proxy({ url: `https://api.github.com/${"a".repeat(5000)}`, method: "G".repeat(500) });
    const long = audits().at(-1);
    expect(long.destination.length).toBeLessThanOrEqual(512);
    expect(long.method.length).toBeLessThanOrEqual(16);
  });
});
