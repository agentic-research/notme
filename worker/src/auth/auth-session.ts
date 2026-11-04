/**
 * AuthSession — what `AuthService.authenticate()` returns (notme-153f03).
 *
 * WHY AN OBJECT. Each top-level call on a service binding is its own RPC
 * session with a fresh `AuthService` instance — measured over a real
 * loopback binding under notme-fbbfbc. `authenticate()` used to store the
 * certs it had verified on `this`, so they were gone by the caller's next
 * `proxy()` or `sign()` call, and neither worked over a binding at all.
 *
 * An `RpcTarget` returned from an RPC method is not serialized: the caller
 * receives a STUB, and every method called on the stub runs here, on this
 * object, which stays alive until the caller disposes the stub (or the
 * caller's execution context ends). So the verified credentials live exactly
 * as long as the caller's handle on them, and no longer. See
 * https://developers.cloudflare.com/workers/runtime-apis/rpc/#class-instances
 * and https://developers.cloudflare.com/workers/runtime-apis/rpc/lifecycle/.
 *
 * WHAT IS REACHABLE. Over RPC, a stub reaches the prototype's methods AND
 * its public properties and getters ("Properties behave like RPC methods
 * that don't take any arguments"). So every field here is ECMAScript
 * `#private`, never TypeScript `private`, which is erased at compile time
 * and would leave the held certs, the signing key and the env readable on
 * the stub. The reachable surface is `proxy`, `sign`, `identity` and the
 * disposer, pinned by rpc-surface.do.test.ts.
 *
 * NO WAY TO CHANGE WHO IT IS. There is no method that re-authenticates or
 * swaps the held credentials: a session is one proven identity for its whole
 * life, and a caller wanting another calls `authenticate()` again and gets a
 * second session.
 */

import { RpcTarget } from "cloudflare:workers";
import {
  authoritySelfHosts,
  forwardableHeaders,
  isAllowedDestination,
  isDeniedDestination,
  parseDestinationAllowlist,
  urlForLog,
} from "../destination-policy";
import { ED25519 } from "../platform";

/** The credentials a session holds, all of them DERIVED by authenticate(). */
export type HeldCerts = {
  mtlsCert: string;
  signingCert: string;
  /** Held when authenticated in-isolate; CryptoKey does not serialize over RPC. */
  mtlsKey: CryptoKey | null;
  /** In-isolate CryptoKey, or imported (non-extractable) from PKCS#8 bytes. */
  signingKey: CryptoKey | null;
  identity: string;
  scopes: string[];
  expiresAt: number;
  /** CA epoch the certs were issued under; proxy() checks it (notme-baea8c). */
  epoch: number;
};

/** What a session needs from the entrypoint that made it. */
export type AuthSessionDeps = {
  /** The Worker's env: PROXY_ALLOWED_DESTINATIONS, SIGNET_AUTHORITY_URL, SITE_URL. */
  env: Record<string, unknown>;
  /** The authority's current epoch, read per proxy() call. */
  authorityState: () => Promise<{ epoch: number }>;
};

export class AuthSession extends RpcTarget {
  #held: HeldCerts | null;
  #deps: AuthSessionDeps;

  constructor(held: HeldCerts, deps: AuthSessionDeps) {
    super();
    this.#held = held;
    this.#deps = deps;
  }

  /**
   * Runs once the LAST stub to this session is disposed — explicitly
   * (`stub[Symbol.dispose]()`, or a `using` declaration going out of scope),
   * or automatically when the caller's execution context ends. Drops the
   * credentials so nothing holds them past their handle, and writes one
   * audit line. Per the lifecycle docs it runs after the client-side dispose
   * returns, and the client does not wait for it.
   */
  [Symbol.dispose](): void {
    const identity = this.#held?.identity ?? null;
    this.#held = null;
    console.log(
      JSON.stringify({ ts: new Date().toISOString(), type: "session", event: "disposed", identity }),
    );
  }

  /**
   * Proxy an HTTP request for the agent Worker, which calls this instead of
   * fetch() (which is disabled). Gates, in order (notme-baea8c):
   *   1. held certs present (not disposed) and unexpired;
   *   2. destination parses, and is not on the metadata denylist;
   *   3. destination on PROXY_ALLOWED_DESTINATIONS — unset allows nothing —
   *      and not the authority's own host unless that is listed exactly;
   *   4. `bridgeCert` scope held;
   *   5. the held certs' epoch equals the authority's current epoch, so a
   *      revokeEpoch() or rotate() stops them before they expire (an RPC
   *      failure here refuses).
   * Every outcome writes one audit line whose `allowed` is the decision and,
   * on a refusal, `reason` names the gate; the logged URL is redacted.
   * Redirects are returned, not followed: a followed redirect would let a
   * listed host send the request to one the allowlist refuses. Host, cf-*,
   * x-forwarded-* and hop-by-hop headers are not forwarded.
   *
   * The outbound request is a plain fetch — the held P-256 cert is NOT
   * attached (no mTLS on this path). Workers present a client certificate
   * only through an `mtls_certificates` binding to a cert uploaded ahead of
   * time, not one minted per session; ADR-009 records why that stays "Not
   * yet".
   */
  async proxy(request: {
    url: string;
    method?: string;
    headers?: Record<string, string>;
    body?: string;
  }): Promise<{
    status: number;
    headers: Record<string, string>;
    body: string;
  }> {
    const start = Date.now();
    const method = request.method || "GET";
    const held = this.#held;
    const audit = (fields: Record<string, unknown>) =>
      // Structured JSON, feeds into APAS attestations.
      console.log(
        JSON.stringify({
          ts: new Date().toISOString(),
          type: "proxy",
          identity: held?.identity ?? null,
          // Redacted and bounded (review F8): no userinfo, no query values.
          destination: urlForLog(request.url),
          method: String(method).slice(0, 16),
          scope_checked: "bridgeCert",
          ...fields,
          duration_ms: Date.now() - start,
        }),
      );
    const deny = (reason: string, message: string): never => {
      audit({ allowed: false, reason });
      throw new Error(message);
    };

    if (!held) {
      return deny("not_authenticated", "not authenticated — this session was disposed; call authenticate() again");
    }
    if (held.expiresAt <= Math.floor(Date.now() / 1000)) {
      return deny("credentials_expired", "credentials expired — re-authenticate");
    }

    // Destination: parseable, then the hard denylist, then the configured
    // allowlist, then never the authority itself unless listed exactly.
    let destHost: string;
    try {
      destHost = new URL(request.url).host.toLowerCase();
    } catch {
      return deny("destination_invalid", "destination invalid — not a parseable URL");
    }
    if (isDeniedDestination(request.url)) {
      return deny("destination_denied", "destination denied — cloud metadata endpoints are blocked");
    }
    const env = this.#deps.env;
    const allowlist = parseDestinationAllowlist(env.PROXY_ALLOWED_DESTINATIONS);
    if (!isAllowedDestination(request.url, allowlist)) {
      return deny(
        "destination_not_allowed",
        "destination not allowed — not on PROXY_ALLOWED_DESTINATIONS (https only; an unset allowlist allows nothing)",
      );
    }
    if (authoritySelfHosts(env).has(destHost) && !allowlist.has(destHost)) {
      return deny(
        "destination_self",
        "destination not allowed — the authority's own host is proxied only when PROXY_ALLOWED_DESTINATIONS lists it exactly",
      );
    }

    // Scope check
    if (!held.scopes.includes("bridgeCert")) {
      return deny("scope_insufficient", "scope insufficient — bridgeCert required for proxy");
    }

    // Epoch: the revocation lever. Last, because it is the one gate that
    // costs an authority RPC.
    let epoch: number;
    try {
      ({ epoch } = await this.#deps.authorityState());
    } catch {
      return deny("authority_unavailable", "authority unavailable — cannot check the credentials' epoch");
    }
    if (held.epoch !== epoch) {
      return deny(
        "epoch_mismatch",
        `credentials revoked — cert epoch ${held.epoch} is not the authority's epoch ${epoch}; re-authenticate`,
      );
    }

    // Make the request
    let res: Response;
    try {
      res = await fetch(request.url, {
        method,
        // Host, cf-*, x-forwarded-* and hop-by-hop headers stripped (F6).
        headers: forwardableHeaders(request.headers),
        body: request.body,
        redirect: "manual",
      });
    } catch (e) {
      // Allowed, and attempted: the record says so, and why it has no status.
      audit({ allowed: true, error: (e as Error)?.message ?? String(e) });
      throw e;
    }

    const responseHeaders: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      responseHeaders[k] = v;
    });
    let body: string;
    try {
      body = await res.text();
    } catch (e) {
      // Sent and answered, but the body failed: still one line (review F7).
      audit({ allowed: true, response_status: res.status, error: (e as Error)?.message ?? String(e) });
      throw e;
    }

    audit({ allowed: true, response_status: res.status });

    return { status: res.status, headers: responseHeaders, body };
  }

  /**
   * Sign data with the held Ed25519 signing key.
   * Returns the signature + the signing cert (public) + the WIMSE identity.
   *
   * Refuses once the certs have expired: a session can now outlive its certs
   * (it lives as long as the caller's stub), and a signature shipped with an
   * expired cert is one no verifier accepts.
   */
  async sign(
    payload: ArrayBuffer,
    format: "raw" | "dsse" | "git-commit" = "raw",
  ): Promise<{
    signature: ArrayBuffer;
    certificate: string;
    identity: string;
  }> {
    const held = this.#held;
    if (!held) {
      throw new Error("not authenticated — this session was disposed; call authenticate() again");
    }
    if (held.expiresAt <= Math.floor(Date.now() / 1000)) {
      throw new Error("credentials expired — re-authenticate");
    }

    // Scope check for signing
    const signingScopes = ["sign:git", "sign:attestation"];
    const hasSignScope =
      format === "raw"
        ? true // raw signing doesn't require a specific scope
        : held.scopes.some((s) => signingScopes.includes(s));
    if (!hasSignScope) {
      throw new Error(
        `scope insufficient — ${format} requires one of: ${signingScopes.join(", ")}`,
      );
    }

    if (!held.signingKey) {
      throw new Error(
        "no signing key held — pass signingKey (in-isolate) or signingKeyPkcs8 (over a binding) to authenticate()",
      );
    }
    const signature = await crypto.subtle.sign(ED25519, held.signingKey, payload);

    // Audit log
    const payloadHash = Array.from(
      new Uint8Array(await crypto.subtle.digest("SHA-256", payload)),
    )
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    console.log(
      JSON.stringify({
        ts: new Date().toISOString(),
        type: "sign",
        identity: held.identity,
        format,
        payload_hash: `sha256:${payloadHash}`,
        scope_checked:
          format === "raw"
            ? "none"
            : signingScopes.find((s) => held.scopes.includes(s)),
        allowed: true,
      }),
    );

    return {
      signature,
      certificate: held.signingCert,
      identity: held.identity,
    };
  }

  /** The identity and capabilities this session holds. */
  async identity(): Promise<{
    identity: string;
    scopes: string[];
    certificates: { mtls: string; signing: string };
    expires_at: number;
    authenticated: boolean;
  }> {
    const held = this.#held;
    if (!held) {
      return {
        identity: "",
        scopes: [],
        certificates: { mtls: "", signing: "" },
        expires_at: 0,
        authenticated: false,
      };
    }
    return {
      identity: held.identity,
      scopes: [...held.scopes],
      certificates: { mtls: held.mtlsCert, signing: held.signingCert },
      expires_at: held.expiresAt,
      authenticated: true,
    };
  }
}
