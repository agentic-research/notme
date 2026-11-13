/**
 * llo-sign.ts — a thin, host-neutral binding to ley-line-open's released
 * `leyline_sign.wasm` (notme-bc4cd2). Test-only: nothing in the deployed
 * Worker loads it.
 *
 * The wasm has NO imports and exports a C ABI over its own linear memory
 * (LLO rs/ll-open/sign/src/ffi.rs at the pinned tag): `lsign_alloc(n)` /
 * `lsign_free(p, n)`, and
 *
 *   leyline_verify_cert_path(leaf_ptr, leaf_len,
 *                            intermediates_ptr, intermediates_len,
 *                            anchor_ptr, anchor_len,
 *                            expected_profile: u32,
 *                            claims_out_ptr, claims_out_len) -> i32
 *
 * which returns the claims-JSON length on success and -1 on ANY failure.
 * `intermediates` is the DER certificates concatenated, the leaf's issuer
 * first; `anchor` is a bare 32-byte Ed25519 public key; expected_profile 2
 * is Signet (notme / signet).
 *
 * This file only marshals bytes. It takes an already-compiled
 * WebAssembly.Module so the same code runs in both pools: the plain pool
 * compiles the vendored bytes after checking their pinned sha256
 * (llo-sign-node.ts); the workers pool imports the .wasm as a module, which
 * is the only way workerd accepts wasm (it refuses to compile from bytes at
 * runtime).
 */

/** expected_profile codes (LLO CertProfile::FFI_*). */
export const PROFILE_ANY = 0;
export const PROFILE_INTERLACE = 1;
export const PROFILE_SIGNET = 2;

/** The claims JSON leyline_verify_cert_path writes (cert_chain::claims_to_json). */
export interface LloClaims {
  epk: string;
  nb: number;
  na: number;
  pr?: "signet";
  ep?: number;
  pf?: string;
  sc?: string;
  cd?: string;
}

export type LloVerifyResult = { ok: true; claims: LloClaims } | { ok: false };

export interface LloSign {
  verifyCertPath(
    leafDer: Uint8Array,
    intermediatesDer: Uint8Array[],
    anchorRaw: Uint8Array,
    expectedProfile: number,
  ): LloVerifyResult;
}

interface Exports {
  memory: WebAssembly.Memory;
  lsign_alloc(size: number): number;
  lsign_free(ptr: number, size: number): void;
  leyline_verify_cert_path(
    leafPtr: number,
    leafLen: number,
    intPtr: number,
    intLen: number,
    anchorPtr: number,
    anchorLen: number,
    expectedProfile: number,
    outPtr: number,
    outLen: number,
  ): number;
}

const CLAIMS_BUF = 4096;

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** Bind an instance of leyline_sign.wasm. Throws if the export surface moved. */
export function lloSignFrom(module: WebAssembly.Module): LloSign {
  const names = WebAssembly.Module.exports(module).map((e) => e.name);
  for (const want of ["memory", "lsign_alloc", "lsign_free", "leyline_verify_cert_path"]) {
    if (!names.includes(want)) {
      throw new Error(`leyline_sign.wasm does not export ${want}; exports: ${names.join(", ")}`);
    }
  }
  const x = new WebAssembly.Instance(module, {}).exports as unknown as Exports;

  return {
    verifyCertPath(leafDer, intermediatesDer, anchorRaw, expectedProfile) {
      const intermediates = concat(intermediatesDer);
      const allocs: Array<[number, number]> = [];
      // lsign_alloc(0) is a dangling-but-valid Vec pointer; allocate at least
      // one byte so every pointer we pass is a real allocation.
      const put = (bytes: Uint8Array): number => {
        const size = Math.max(bytes.length, 1);
        const ptr = x.lsign_alloc(size);
        allocs.push([ptr, size]);
        // Re-read memory.buffer AFTER alloc: a grow detaches the old view.
        new Uint8Array(x.memory.buffer, ptr, bytes.length).set(bytes);
        return ptr;
      };
      try {
        const leafPtr = put(leafDer);
        const intPtr = put(intermediates);
        const anchorPtr = put(anchorRaw);
        const outPtr = x.lsign_alloc(CLAIMS_BUF);
        allocs.push([outPtr, CLAIMS_BUF]);
        const n = x.leyline_verify_cert_path(
          leafPtr,
          leafDer.length,
          intPtr,
          intermediates.length,
          anchorPtr,
          anchorRaw.length,
          expectedProfile,
          outPtr,
          CLAIMS_BUF,
        );
        if (n < 0) return { ok: false };
        const json = new TextDecoder().decode(new Uint8Array(x.memory.buffer, outPtr, n).slice());
        return { ok: true, claims: JSON.parse(json) as LloClaims };
      } finally {
        for (const [p, s] of allocs) x.lsign_free(p, s);
      }
    },
  };
}
