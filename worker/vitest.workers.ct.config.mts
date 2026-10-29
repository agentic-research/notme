import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";
import { baseMiniflare, CT_BOUND_SUITES, x509Dir } from "./vitest.workers.config.mts";

// Pool config for the suites that mint WITH a transparency log bound
// (notme-1b46a8). Separate from vitest.workers.config.mts on purpose: that
// config is where every other suite proves "no CT_LOG binding, no change", so
// it must not carry the binding at all — a per-test toggle would leave the
// binding present and make the absent case a claim rather than a fact.
//
// CT_LOG is bound to an inline stub log. Its behaviour is selected by the test
// over the SAME service binding (POST /__control), and it records every
// submission it received (GET /__received). That is the simplest channel both
// sides can reach: the DO calls the stub through env.CT_LOG and so can the
// test, so no KV namespace or coordinating DO is needed. State lives in the
// stub isolate's module scope; workerd runs one isolate per worker and handles
// one event at a time, so the request counter cannot race.
//
// Modes:
//   ok            every call returns a structurally valid SCT
//   500           every call returns 500
//   hang          every call is accepted and never answered (30 s)
//   ok-then-fail  the first call succeeds, every later one 500s
//   fail-second   only the second call 500s
//   fail-signing  500 for any chain whose leaf is NOT a P-256 key (the
//                 Ed25519 signing cert) — the order-independent half-logged case
const CT_LOG_STUB = /* js */ `
const ID = new Uint8Array(32).fill(0x5c);
const b64 = (u) => btoa(String.fromCharCode(...u));
const LOG_ID = b64(ID);
// id-ecPublicKey (1.2.840.10045.2.1) as DER: only the mTLS leaf's SPKI has it.
const EC_OID = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
function isEcLeaf(leafB64) {
  const d = Uint8Array.from(atob(leafB64), (c) => c.charCodeAt(0));
  outer: for (let i = 0; i + EC_OID.length <= d.length; i++) {
    for (let j = 0; j < EC_OID.length; j++) if (d[i + j] !== EC_OID[j]) continue outer;
    return true;
  }
  return false;
}
let mode = "ok";
let n = 0;
const received = [];
export default {
  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === "/__control") {
      const b = await req.json();
      mode = b.mode;
      n = 0;
      received.length = 0;
      return Response.json({ id: LOG_ID });
    }
    if (url.pathname === "/__received") return Response.json(received);
    const body = JSON.parse(await req.text());
    const i = ++n;
    received.push({ path: url.pathname, chain: body.chain });
    if (mode === "hang") {
      await new Promise((r) => setTimeout(r, 30000));
      return new Response("too late", { status: 500 });
    }
    const fail =
      mode === "500" ||
      (mode === "ok-then-fail" && i > 1) ||
      (mode === "fail-second" && i === 2) ||
      (mode === "fail-signing" && !isEcLeaf(body.chain[0]));
    if (fail) return new Response("log unavailable", { status: 500 });
    // DigitallySigned: sha256(4) ecdsa(3) uint16 length, then the signature.
    const sig = new Uint8Array(4 + 70);
    sig.set([4, 3, 0, 70]);
    sig.fill(0x11, 4);
    return Response.json({
      sct_version: 0,
      id: LOG_ID,
      timestamp: Date.now(),
      extensions: "AAAFAAAAAAA=",
      signature: b64(sig),
    });
  },
};
`;

export default defineConfig({
  resolve: { alias: { "@peculiar/x509": x509Dir } },
  plugins: [
    cloudflareTest({
      main: "./worker.ts",
      miniflare: {
        ...baseMiniflare,
        serviceBindings: { CT_LOG: "ct-log-stub" },
        workers: [
          {
            name: "ct-log-stub",
            modules: true,
            script: CT_LOG_STUB,
            compatibilityDate: baseMiniflare.compatibilityDate,
          },
        ],
      },
    }),
  ],
  test: {
    include: CT_BOUND_SUITES,
  },
});
