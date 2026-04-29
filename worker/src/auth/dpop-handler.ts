// DPoP token handler — orchestrates proof validation + token minting.
//
// Separated from worker.ts routes so it can be tested without DO bindings.
// The Worker route extracts session/proof/audience from the request and
// delegates here. JTI replay is injected as callbacks (KV in prod, in-memory in tests).

import { validateDpopProof } from "./dpop";
import { mintAccessToken } from "./token";

export interface SessionPayload {
  principalId: string;
  scopes: string[];
  authMethod: string;
  exp: number;
}

export interface HandleTokenInput {
  dpopProof: string | null;
  session: SessionPayload | null;
  audience: string;
  /** The token endpoint URL — must match the DPoP proof htu claim exactly. */
  tokenEndpointUrl: string;
  signingKey: CryptoKey;
  keyId: string;
  /** Returns true if this JTI has been seen before. */
  checkJtiReplay: (jti: string) => Promise<boolean>;
  /** Store a JTI to prevent replay. */
  storeJti: (jti: string) => Promise<void>;
}

export type HandleTokenResult =
  | { ok: true; accessToken: string; tokenType: "DPoP"; expiresIn: number }
  | { ok: false; status: number; error: string };

export async function handleToken(input: HandleTokenInput): Promise<HandleTokenResult> {
  // 1. Session required
  if (!input.session) {
    return { ok: false, status: 401, error: "session_required" };
  }

  // 2. DPoP proof required
  if (!input.dpopProof) {
    return { ok: false, status: 400, error: "dpop_proof_required" };
  }

  // 3. Audience required
  if (!input.audience) {
    return { ok: false, status: 400, error: "invalid_audience" };
  }

  // 4. Validate DPoP proof
  let proofResult;
  try {
    proofResult = await validateDpopProof(input.dpopProof, {
      htm: "POST",
      htu: input.tokenEndpointUrl,
    });
  } catch (e: any) {
    return { ok: false, status: 401, error: "invalid_dpop_proof" };
  }

  // 5. JTI replay check
  const replayed = await input.checkJtiReplay(proofResult.jti);
  if (replayed) {
    return { ok: false, status: 401, error: "proof_reused" };
  }

  // 6. Store JTI BEFORE minting — prevents TOCTOU race across concurrent
  // requests (KV is eventually consistent, so two edge nodes can both
  // pass the replay check at step 5 before either's store lands).
  // Matches worker.ts /token order. If mint fails after this, the JTI
  // is burned — acceptable, client retries with a new proof.
  // (rosary-9b969c)
  await input.storeJti(proofResult.jti);

  // 7. Mint access token bound to DPoP key
  const scope = input.session.scopes.join(" ");
  const accessToken = await mintAccessToken({
    sub: input.session.principalId,
    scope,
    audience: input.audience,
    jkt: proofResult.thumbprint,
    signingKey: input.signingKey,
    keyId: input.keyId,
  });

  return {
    ok: true,
    accessToken,
    tokenType: "DPoP",
    expiresIn: 300,
  };
}

// ── JWKS response builder ────────────────────────────────────

export interface JwkPublicKey {
  kty: string;
  crv: string;
  x: string;
  kid: string;
  use: string;
  alg: string;
}

export function buildJwksResponse(publicKey: JwkPublicKey): { keys: JwkPublicKey[] } {
  return { keys: [publicKey] };
}
