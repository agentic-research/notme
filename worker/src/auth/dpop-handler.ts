// JWKS response builder.
//
// This file used to also export `handleToken` — a composable token-minting
// orchestrator with an injected JTI consumer, built so the flow could be
// tested without Durable Objects. It was deleted (notme-e73c64) because it
// was never on the live path: the `/token` route in worker.ts implements the
// flow inline against `authority.mintDPoPTokenOnce`, and `handleToken` was
// referenced only by its own tests.
//
// That is not a tidiness complaint. The parallel implementation cost real
// work: rosary-9b969c was a genuine JTI-replay window found and fixed IN THE
// ORPHAN (notme commit 95ef0dd) — a review cycle spent on code that could
// never run — and rosary-0b40d2 cited this file as the /token endpoint spec,
// pointing a downstream integrator at the wrong artifact. It also shipped:
// worker.ts dynamically imports `buildJwksResponse` from here, so esbuild
// pulled the whole module, dead orchestrator included, into the bundle.
//
// The DO-free testability argument was real when the Durable Object had no
// atomic consume-and-mint. `mintDPoPTokenOnce` (signing-authority.ts)
// superseded it, and src/dpop-nonce.do.test.ts now drives the real route
// end-to-end against a real DO, which is strictly better evidence than
// testing a stand-in.

export interface JwkPublicKey {
  kty: string;
  crv: string;
  x: string;
  kid: string;
  use: string;
  alg: string;
}

export function buildJwksResponse(publicKey: JwkPublicKey): {
  keys: JwkPublicKey[];
} {
  return { keys: [publicKey] };
}
