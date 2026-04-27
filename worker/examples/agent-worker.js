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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Health check
    if (url.pathname === "/health") {
      const id = await env.NOTME.identity();
      return Response.json({
        status: "ok",
        authenticated: id.authenticated,
        identity: id.identity,
        scopes: id.scopes,
      });
    }

    // Proxy an external request through notme (mTLS)
    if (url.pathname === "/proxy" && request.method === "POST") {
      const body = await request.json();
      try {
        const result = await env.NOTME.proxy(body);
        return Response.json(result);
      } catch (e) {
        return Response.json({ error: e.message }, { status: 403 });
      }
    }

    // Sign data with the Ed25519 signing key
    if (url.pathname === "/sign" && request.method === "POST") {
      const body = await request.json();
      try {
        const payload = Uint8Array.from(atob(body.payload), c => c.charCodeAt(0));
        const result = await env.NOTME.sign(payload.buffer, body.format || "raw");
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
          message: "fetch() is disabled — use env.NOTME.proxy() instead",
          error: e.message,
        });
      }
    }

    return Response.json({ error: "not found" }, { status: 404 });
  },
};
