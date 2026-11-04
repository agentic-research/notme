// Example agent Worker — runs in the same workerd process as notme.
//
// This Worker has NO direct internet access (no globalOutbound).
// All external communication goes through env.NOTME service binding.
// V8 isolate boundary prevents reading notme's keys or memory.
//
// Usage:
//   1. Add this to config.capnp as a second Worker
//   2. workerd serve config.capnp --experimental
//   3. Agent code runs in this isolate, calls env.NOTME for everything
//
// Credentials: env.NOTME.authenticate() returns a SESSION (notme-153f03).
// proxy(), sign() and identity() are methods of that session, not of
// env.NOTME. Each top-level binding call is its own RPC session with a fresh
// AuthService, so nothing authenticate() verified could be found by a later
// env.NOTME.proxy() call; the session object is what holds it. The caller
// gets a stub, and notme keeps the verified certs exactly as long as that
// stub lives: until it is disposed (`using`, or session[Symbol.dispose]()),
// or until this Worker's request handler finishes, when workerd disposes
// every stub the request created
// (https://developers.cloudflare.com/workers/runtime-apis/rpc/lifecycle/).
//
// authenticate() holds a pair only after the holder PROVES possession of
// both private keys (notme-fbbfbc):
//
//   const { challenge } = await env.NOTME.authChallenge(identity);
//   // sign authenticateBinding(mtlsSPKI, signingSPKI, challenge) — see
//   // worker/src/auth/cert-pair-binding.ts — with the P-256 and Ed25519 keys
//   using session = await env.NOTME.authenticate({
//     mtlsCert, signingCert, challenge, proofs: { mtls, signing },
//   });
//
// No private key is ever passed to notme. session.sign() takes a SIGNER, a
// function this Worker supplies: it crosses the binding as a stub, notme
// calls back to it here with the payload, and returns the signature only if
// it verifies under the signing cert
// (https://developers.cloudflare.com/workers/runtime-apis/rpc/#send-functions-as-parameters-of-rpc-methods).
//
// The challenge is single-use, good for 60 s, and authChallenge() is rate
// limited per binding `props` (set props on this Worker's NOTME binding to
// get a budget of its own). `openSession` below stands for that sequence;
// where the cert pair and keys come from (a launcher's /cert/gha exchange,
// say) is the deployment's choice, not this example's.

/**
 * authChallenge -> prove -> authenticate, returning the session stub.
 * `env.BRIDGE_CREDENTIALS` is a placeholder for however this Worker is handed
 * its cert pair, the proofs over the challenge, and its signing function.
 */
async function openSession(env) {
  const creds = env.BRIDGE_CREDENTIALS;
  const { challenge } = await env.NOTME.authChallenge(creds.identity);
  const proofs = await creds.prove(challenge);
  return env.NOTME.authenticate({
    mtlsCert: creds.mtlsCert,
    signingCert: creds.signingCert,
    challenge,
    proofs,
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Health check
    if (url.pathname === "/health") {
      using session = await openSession(env);
      const id = await session.identity();
      return Response.json({
        status: "ok",
        authenticated: id.authenticated,
        identity: id.identity,
        scopes: id.scopes,
      });
    }

    // Proxy an external request through notme
    if (url.pathname === "/proxy" && request.method === "POST") {
      const body = await request.json();
      try {
        using session = await openSession(env);
        const result = await session.proxy(body);
        return Response.json(result);
      } catch (e) {
        return Response.json({ error: e.message }, { status: 403 });
      }
    }

    // Sign as the session's identity. This Worker's key signs (the signer
    // runs here); notme gates, verifies against the cert, and audits.
    if (url.pathname === "/sign" && request.method === "POST") {
      const body = await request.json();
      try {
        const payload = Uint8Array.from(atob(body.payload), c => c.charCodeAt(0));
        using session = await openSession(env);
        const result = await session.sign(payload.buffer, body.format || "raw", (bytes) =>
          env.BRIDGE_CREDENTIALS.sign(bytes),
        );
        return Response.json({
          signature: btoa(String.fromCharCode(...new Uint8Array(result.signature))),
          certificate: result.certificate,
          identity: result.identity,
        });
      } catch (e) {
        return Response.json({ error: e.message }, { status: 403 });
      }
    }

    // Demonstrate that fetch() is disabled
    if (url.pathname === "/try-fetch") {
      try {
        // This WILL fail if globalOutbound is not configured
        await fetch("https://example.com");
        return Response.json({ error: "fetch should have been blocked!" }, { status: 500 });
      } catch (e) {
        return Response.json({
          blocked: true,
          message: "fetch() is disabled — use session.proxy() instead",
          error: e.message,
        });
      }
    }

    return Response.json({ error: "not found" }, { status: 404 });
  },
};
