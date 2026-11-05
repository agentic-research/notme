import { describe, expect, it } from "vitest";
import {
  TIER_ENROLMENT_ID_TAG,
  TIER_RENEW_V2_TAG,
  TIER_RENEW_V3_TAG,
  tierEnrolmentId,
  tierRenewalBinding,
  tierRenewalBindingV2,
  tierRenewalBindingV3,
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

  it("v3 binding is tag || SPKI || uint64be(iat) || uint64be(generation) || enrollment_id (notme-c9fc8c)", () => {
    const spki = new Uint8Array([1, 2, 3]);
    const id = new Uint8Array(32).fill(0xab);
    const tag = new TextEncoder().encode(TIER_RENEW_V3_TAG);
    const nums = new Uint8Array(16);
    const dv = new DataView(nums.buffer);
    dv.setBigUint64(0, 1_700_000_000n);
    dv.setBigUint64(8, 5n);
    expect(TIER_RENEW_V3_TAG).toBe("notme/tier-renew/v3\0");
    expect(tierRenewalBindingV3(spki, 1_700_000_000, 5, id)).toEqual(new Uint8Array([...tag, ...spki, ...nums, ...id]));
  });

  it("v3 never coincides with v2, and two enrollments of one key never share a v3 binding", () => {
    const spki = new Uint8Array([1, 2, 3]);
    const a = new Uint8Array(32).fill(1);
    const b = new Uint8Array(32).fill(2);
    expect(tierRenewalBindingV3(spki, 9, 0, a)).not.toEqual(tierRenewalBindingV2(spki, 9, 0));
    expect(tierRenewalBindingV3(spki, 9, 0, a)).not.toEqual(tierRenewalBindingV3(spki, 9, 0, b));
  });

  it("v3 refuses an enrollment id that is not 32 bytes", () => {
    for (const n of [0, 31, 33]) {
      expect(() => tierRenewalBindingV3(new Uint8Array([1]), 1, 0, new Uint8Array(n))).toThrow(/enrollment id/);
    }
  });

  it("the enrollment id is SHA-256 of its tag and the device-code hash", async () => {
    const h = new Uint8Array(32).fill(7);
    const tag = new TextEncoder().encode(TIER_ENROLMENT_ID_TAG);
    const want = new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array([...tag, ...h])));
    expect(await tierEnrolmentId(h)).toEqual(want);
    expect(await tierEnrolmentId(h)).not.toEqual(h);
    await expect(tierEnrolmentId(new Uint8Array(31))).rejects.toThrow(/32 bytes/);
  });

  it("the digest is SHA-256 of the binding, lowercase hex", async () => {
    const binding = tierRenewalBindingV2(new Uint8Array([9, 8, 7]), 42, 3);
    const want = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", binding)));
    const got = await renewalRequestDigest(binding);
    expect(got).toBe(want);
    expect(got).toMatch(/^[0-9a-f]{64}$/);
  });
});
