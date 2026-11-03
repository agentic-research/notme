/**
 * Stateless pre-check of a tier renewal's proof, run in the front Worker
 * BEFORE the SigningAuthority is called (notme-ed6114).
 *
 * /cert/issuing-ca/renew is unauthenticated by design — the proof of
 * possession IS the authentication — and has no Worker-side rate limit, so
 * every forged renewal cost the singleton authority an Ed25519 verify (the
 * DO checks the proof before it reads the row, notme-c9fc8c). Every byte the
 * renewal bindings cover comes from the request (tier-enrolment-binding.ts),
 * so the same check can run here, with no state at all, and a forgery never
 * reaches the DO.
 *
 * This is an EARLY REJECT, not the check. SigningAuthority.renewTier still
 * runs the same checks itself (defence in depth). It MIRRORS the stateless
 * prefix of renewTier, step for step and reason for reason — up to "Only a
 * holder of the key gets past this line" — so a request it refuses gets
 * exactly the refusal the DO would have given. pre-do-limits.do.test.ts
 * pins that parity against the real DO; change both together.
 */
import { importPublicKey } from "../cert-authority";
import { verifyEd25519PopProof } from "./pop";
import {
  ENROLMENT_ID_HEX,
  tierRenewalBinding,
  tierRenewalBindingV2,
  tierRenewalBindingV3,
} from "./tier-enrolment-binding";

export type RenewalPrecheck = { ok: true } | { ok: false; reason: "invalid_key" | "invalid_proof" | "stale_proof" };

export async function precheckRenewalProof(params: {
  publicKeyPem: string;
  iat: number;
  proof: string;
  generation?: number;
  enrollmentId?: string;
}): Promise<RenewalPrecheck> {
  let key: CryptoKey;
  try {
    key = await importPublicKey(params.publicKeyPem);
  } catch {
    return { ok: false, reason: "invalid_key" };
  }
  if (key.algorithm.name !== "Ed25519") return { ok: false, reason: "invalid_key" };
  const spki = new Uint8Array((await crypto.subtle.exportKey("spki", key)) as ArrayBuffer);

  // v3 names the enrollment, v2 a generation, v1 neither — as renewTier.
  const version: 1 | 2 | 3 = params.enrollmentId !== undefined ? 3 : params.generation !== undefined ? 2 : 1;
  if (!Number.isSafeInteger(params.iat) || params.iat < 0) return { ok: false, reason: "stale_proof" };
  let binding: Uint8Array;
  if (version === 1) {
    binding = tierRenewalBinding(spki, params.iat);
  } else {
    const g = params.generation;
    if (g === undefined || !Number.isSafeInteger(g) || g < 0) return { ok: false, reason: "invalid_proof" };
    if (version === 3) {
      const id = params.enrollmentId as string;
      if (!ENROLMENT_ID_HEX.test(id)) return { ok: false, reason: "invalid_proof" };
      const raw = Uint8Array.from(id.match(/../g)!, (h) => parseInt(h, 16));
      binding = tierRenewalBindingV3(spki, params.iat, g, raw);
    } else {
      binding = tierRenewalBindingV2(spki, params.iat, g);
    }
  }
  if (!(await verifyEd25519PopProof(binding, key, params.proof))) return { ok: false, reason: "invalid_proof" };
  return { ok: true };
}
