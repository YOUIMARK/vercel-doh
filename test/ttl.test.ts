import { describe, expect, it } from "vitest";
import { minTtl } from "../src/dns/ttl";
import { buildQuery, buildResponse } from "./helpers";

describe("minTtl", () => {
  it("returns the answer TTL", () => {
    const query = buildQuery();
    const resp = buildResponse(query, { ttl: 300 });
    expect(minTtl(resp)).toBe(300);
  });

  it("takes the minimum across answer and authority (conservative)", () => {
    const query = buildQuery();
    const resp = buildResponse(query, { ttl: 300, authorityTtl: 60 });
    expect(minTtl(resp)).toBe(60);
  });

  it("uses the authority TTL for negative answers", () => {
    const query = buildQuery();
    const resp = buildResponse(query, { rcode: 3, ttl: 0, authorityTtl: 900 });
    expect(minTtl(resp)).toBe(0); // min(0, 900) — conservative
  });

  it("returns null for empty responses", () => {
    const query = buildQuery();
    const resp = buildResponse(query, { answerCount: 0 });
    expect(minTtl(resp)).toBeNull();
  });

  it("returns null for malformed messages", () => {
    expect(minTtl(new Uint8Array([1, 2, 3]))).toBeNull();
  });
});
