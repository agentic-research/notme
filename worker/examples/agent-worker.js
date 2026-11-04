// Example agent Worker — runs in the same workerd process as notme.
//
// This Worker has NO direct internet access (no globalOutbound).
// All external communication goes through env.NOTME service binding.
// V8 isolate boundary prevents reading notme's keys or memory.
//
// Usage:
//   1. Add this to config.capnp as a second Worker (examples/config-colocated.capnp
//      does; note the `props` on its NOTME binding — every agent binding needs
//      its own, see below)
//   2. workerd serve config.capnp --experimental
//   3. Agent code runs in this isolate, calls env.NOTME for everything
//
// Credentials: env.NOTME.authenticate() returns a SESSION (notme-153f03).
// proxy(), sign() and identity() are methods of that session, not of
// env.NOTME. The caller gets a stub, and notme keeps the verified certs
// exactly as long as that stub lives: until it is disposed (`using`, or
// session[Symbol.dispose]()), until the certs expire, or until this Worker's
// request handler finishes, when workerd disposes every stub the request
// created (https://developers.cloudflare.com/workers/runtime-apis/rpc/lifecycle/).
//
// AUTHENTICATE ONCE, REUSE THE SESSION. A session costs an authChallenge(),
// which is rate limited (10 / 60 s per binding props), plus a proof and a DO
// round trip. So this Worker opens at most ONE session per unit of work and
// does all of that work's proxy() and sign() calls on it:
//   - `/health` does not authenticate at all;
//   - `/proxy` and `/sign` open the session lazily, only if they get that far;
//   - `/batch` runs a list of operations on one session.
// A session cannot be cached across requests: the runtime disposes it when
// the request that opened it ends (lifecycle docs above). A long-running agent
// should therefore do its work inside one long request or job, not as many
// short ones that each re-authenticate.
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
// Signing needs a sign:git or sign:attestation scope on the cert, whatever
// `format` is claimed.
//
// Where the cert pair and keys come from (a launcher's /cert/gha exchange,
// say) is the deployment's choice, not this example's: `env.BRIDGE_CREDENTIALS`
// is a placeholder for it.

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

/**
 * One session per unit of work, opened on first use. `get()` authenticates
 * the first time and returns the same stub after; `[Symbol.dispose]` drops it.
 */
function lazySession(env) {
  let session = null;
  return {
    async get() {
      session ??= await openSession(env);
      return session;
    },
    [Symbol.dispose]() {
      session?.[Symbol.dispose]();
      session = null;
    },
  };
}

/** Sign with this Worker's own key; the key never leaves this isolate. */
const signer = (env) => (bytes) => env.BRIDGE_CREDENTIALS.sign(bytes);

async function signOp(session, env, { payload, format }) {
  const bytes = Uint8Array.from(atob(payload), (c) => c.charCodeAt(0));
  const result = await session.sign(bytes.buffer, format || "raw", signer(env));
  return {
    signature: btoa(String.fromCharCode(...new Uint8Array(result.signature))),
    certificate: result.certificate,
    identity: result.identity,
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Health check: this Worker is up. It does not authenticate, so probes
    // never spend the binding's authChallenge budget.
    if (url.pathname === "/health") {
      return Response.json({ status: "ok" });
    }

    // Proxy an external request through notme
    if (url.pathname === "/proxy" && request.method === "POST") {
      const body = await request.json();
      using work = lazySession(env);
      try {
        return Response.json(await (await work.get()).proxy(body));
      } catch (e) {
        return Response.json({ error: e.message }, { status: 403 });
      }
    }

    // Sign as the session's identity. This Worker's key signs (the signer
    // runs here); notme gates, verifies against the cert, and audits.
    if (url.pathname === "/sign" && request.method === "POST") {
      const body = await request.json();
      using work = lazySession(env);
      try {
        return Response.json(await signOp(await work.get(), env, body));
      } catch (e) {
        return Response.json({ error: e.message }, { status: 403 });
      }
    }

    // Several operations, ONE authentication:
    //   { "ops": [ { "proxy": { "url": ... } }, { "sign": { "payload": ..., "format": ... } } ] }
    if (url.pathname === "/batch" && request.method === "POST") {
      const { ops = [] } = await request.json();
      using work = lazySession(env);
      const results = [];
      for (const op of ops) {
        try {
          const session = await work.get();
          if (op.proxy) results.push({ ok: true, proxy: await session.proxy(op.proxy) });
          else if (op.sign) results.push({ ok: true, sign: await signOp(session, env, op.sign) });
          else results.push({ ok: false, error: "unknown op" });
        } catch (e) {
          results.push({ ok: false, error: e.message });
        }
      }
      return Response.json({ results });
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
