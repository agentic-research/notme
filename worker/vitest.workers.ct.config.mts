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
// stub isolate's module scope.
//
// workerd INTERLEAVES concurrent requests at await points, so arrival order
// between the two concurrent submissions is not defined. The counter is taken
// synchronously, before the first await, so each request gets a distinct
// number — but WHICH cert is "first" is arbitrary, and the order-dependent
// modes are only used by tests whose expected outcome is the same either way
// (both certs backlogged). The order-independent half-logged case is
// `fail-signing`, which keys on the certificate rather than on arrival.
//
// The stub SIGNS REAL SCTs with a fixed P-256 test log key (below): the
// RFC 6962 §3.2 digitally-signed struct for a precert_entry over the
// precertificate's TBSCertificate with the poison removed. The log id is
// SHA-256 of that key's SPKI. So the test can verify each embedded SCT
// against its OWN certificate's bytes — which is what catches an SCT embedded
// in the wrong certificate of the pair, not just a dropped pin.
//
// Modes:
//   ok            every call returns a validly signed SCT
//   500           every call returns 500
//   hang          every call is accepted and never answered (30 s)
//   ok-then-fail  the first-numbered call succeeds, every later one 500s
//   fail-second   only the second-numbered call 500s
//   fail-signing  500 for any chain whose leaf is NOT a P-256 key (the
//                 Ed25519 signing cert) — the order-independent half-logged case

/** TEST-ONLY log key. Not a secret and not any real log's key. */
const STUB_LOG_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "lAU4tUdJD47Ke32vVOcN_o8E0kRGQAxyBL_3YptnXZo",
  y: "LNN91R3krcs0KMuWvvQCNYgOFzANu3BFdkV2zQYQd7Q",
  d: "v9zRMEqJFEiJH-wtFibVn9vdGjDQejLUUkCsyWMAPdo",
};

const CT_LOG_STUB = /* js */ `
const JWK = ${JSON.stringify(STUB_LOG_JWK)};
const b64 = (u) => btoa(String.fromCharCode(...u));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const POISON_OID = "1.3.6.1.4.1.11129.2.4.3";
// id-ecPublicKey (1.2.840.10045.2.1) as DER: only the mTLS leaf's SPKI has it.
const EC_OID = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

let keys = null;
async function logKeys() {
  if (keys) return keys;
  const priv = await crypto.subtle.importKey("jwk", JWK, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const { d, ...pubJwk } = JWK;
  const pub = await crypto.subtle.importKey("jwk", pubJwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pub));
  const id = new Uint8Array(await crypto.subtle.digest("SHA-256", spki));
  keys = { priv, spki: b64(spki), id };
  return keys;
}

// ── minimal DER ──
function tlv(d, at) {
  let len = d[at + 1], body = at + 2;
  if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = len * 256 + d[at + 2 + i]; body = at + 2 + n; }
  return { tag: d[at], start: at, body, end: body + len };
}
function children(d, t) { const out = []; for (let at = t.body; at < t.end; ) { const c = tlv(d, at); out.push(c); at = c.end; } return out; }
function cat(parts) { const o = new Uint8Array(parts.reduce((s, p) => s + p.length, 0)); let at = 0; for (const p of parts) { o.set(p, at); at += p.length; } return o; }
function enc(tag, c) {
  const n = c.length;
  const len = n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff];
  return cat([new Uint8Array([tag, ...len]), c]);
}
function oid(c) {
  const a = [Math.floor(c[0] / 40), c[0] % 40]; let v = 0;
  for (const b of c.subarray(1)) { v = v * 128 + (b & 0x7f); if (!(b & 0x80)) { a.push(v); v = 0; } }
  return a.join(".");
}
const tbsFields = (der) => { const tbs = children(der, tlv(der, 0))[0]; return children(der, tbs); };
/** RFC 6962 §3.2: the precert's TBSCertificate with the poison removed. */
function tbsWithoutPoison(der) {
  const f = tbsFields(der);
  const ext = f.find((x) => x.tag === 0xa3);
  const seq = children(der, ext)[0];
  const kept = children(der, seq).filter((e) => { const o = children(der, e)[0]; return oid(der.subarray(o.body, o.end)) !== POISON_OID; });
  return enc(0x30, cat([
    ...f.filter((x) => x.tag !== 0xa3).map((x) => der.subarray(x.start, x.end)),
    enc(0xa3, enc(0x30, cat(kept.map((e) => der.subarray(e.start, e.end))))),
  ]));
}
function spkiOf(der) { const f = tbsFields(der); const s = f[f[0].tag === 0xa0 ? 6 : 5]; return der.subarray(s.start, s.end); }
/** WebCrypto's raw r||s to the DER ECDSA-Sig-Value a TLS DigitallySigned carries. */
function rawToDer(raw) {
  const int = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.subarray(i); return enc(0x02, b[0] & 0x80 ? cat([new Uint8Array([0]), b]) : b); };
  return enc(0x30, cat([int(raw.subarray(0, 32)), int(raw.subarray(32))]));
}
async function signSct(chain) {
  const k = await logKeys();
  const leaf = unb64(chain[0]);
  const issuerKeyHash = new Uint8Array(await crypto.subtle.digest("SHA-256", spkiOf(unb64(chain[1]))));
  const tbs = tbsWithoutPoison(leaf);
  const ext = unb64("AAAFAAAAAAA="); // leaf_index extension, as azul emits
  const timestamp = Date.now();
  const ts = new Uint8Array(8); let t = BigInt(timestamp);
  for (let i = 7; i >= 0; i--) { ts[i] = Number(t & 0xffn); t >>= 8n; }
  const signed = cat([
    new Uint8Array([0, 0]), // version v1, signature_type certificate_timestamp
    ts,
    new Uint8Array([0, 1]), // entry_type precert_entry
    issuerKeyHash,
    new Uint8Array([tbs.length >> 16, (tbs.length >> 8) & 0xff, tbs.length & 0xff]),
    tbs,
    new Uint8Array([ext.length >> 8, ext.length & 0xff]),
    ext,
  ]);
  const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, k.priv, signed));
  const der = rawToDer(raw);
  // DigitallySigned: sha256(4) ecdsa(3) uint16 length, then the signature.
  const ds = cat([new Uint8Array([4, 3, der.length >> 8, der.length & 0xff]), der]);
  return { sct_version: 0, id: b64(k.id), timestamp, extensions: b64(ext), signature: b64(ds) };
}
function isEcLeaf(leafB64) {
  const d = unb64(leafB64);
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
      const k = await logKeys();
      return Response.json({ id: b64(k.id), spki: k.spki });
    }
    if (url.pathname === "/__received") return Response.json(received);
    // Numbered synchronously, before any await: distinct per request, though
    // which concurrent request is which is up to the scheduler.
    const i = ++n;
    const body = JSON.parse(await req.text());
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
    return Response.json(await signSct(body.chain));
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
