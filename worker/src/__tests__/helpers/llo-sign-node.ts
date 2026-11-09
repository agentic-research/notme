/**
 * llo-sign-node.ts — load the VENDORED leyline_sign.wasm in the plain
 * (Node) pool, refusing bytes that do not match their pin (notme-bc4cd2).
 *
 * The pin is checked here, on the very bytes that get compiled, and not only
 * by `task docs:check`: a test that ran whatever sat at the path would report
 * "LLO accepts notme chains" about an artifact LLO never released.
 */
import { NodeWasm, readPinnedAsset } from "../../../../scripts/fetch-llo-wasm";
import { lloSignFrom, type LloSign } from "./llo-sign";

export async function loadLloSignVendored(): Promise<LloSign> {
  return lloSignFrom(await NodeWasm.compile(readPinnedAsset("leyline_sign.wasm")));
}
