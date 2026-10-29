import { describe, expect, it } from "vitest";
import {
  TIER_RENEW_V2_TAG,
  tierRenewalBinding,
  tierRenewalBindingV2,
  renewalRequestDigest,
} from "../auth/tier-enrolment-binding";

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

describe("tier renewal binding v2", () => {
  it("v2 binding is tag || SPKI || uint64be(iat) || uint64be(generation)", () => {
    const spki = new Uint8Array([1, 2, 3]);
    const tag = new TextEncoder().encode(TIER_RENEW_V2_TAG);
    const nums = new Uint8Array(16);
    const dv = new DataView(nums.buffer);
    dv.setBigUint64(0, 1_700_000_000n);
    dv.setBigUint64(8, 5n);
    const expected = new Uint8Array([...tag, ...spki, ...nums]);
    expect(tierRenewalBindingV2(spki, 1_700_000_000, 5)).toEqual(expected);
  });

  it("v1 and v2 bindings never coincide", () => {
    const spki = new Uint8Array([1, 2, 3]);
    expect(tierRenewalBinding(spki, 1_700_000_000)).not.toEqual(tierRenewalBindingV2(spki, 1_700_000_000, 0));
  });

  it("generation must be a non-negative safe integer", () => {
    const spki = new Uint8Array([1]);
    expect(() => tierRenewalBindingV2(spki, 1, 0)).not.toThrow();
    for (const g of [-1, 1.5, 2 ** 53]) {
      expect(() => tierRenewalBindingV2(spki, 1, g)).toThrow(/generation/);
    }
  });

  it("the digest is SHA-256 of the binding, lowercase hex", async () => {
    const binding = tierRenewalBindingV2(new Uint8Array([9, 8, 7]), 42, 3);
    const want = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", binding)));
    const got = await renewalRequestDigest(binding);
    expect(got).toBe(want);
    expect(got).toMatch(/^[0-9a-f]{64}$/);
  });
});
