import { describe, expect, it } from "vitest";
import { minAnswerTtl, soaNegativeTtl } from "../src/dns/ttl";
import { buildQuery, buildResponse, buildSoaRdata } from "./helpers";

describe("minAnswerTtl", () => {
  it("returns the answer TTL", () => {
    const query = buildQuery();
    const resp = buildResponse(query, { ttl: 300 });
    expect(minAnswerTtl(resp)).toBe(300);
  });

  it("returns null when there are no answers", () => {
    const resp = buildResponse(buildQuery(), { answerCount: 0 });
    expect(minAnswerTtl(resp)).toBeNull();
  });

  it("returns null for malformed messages", () => {
    expect(minAnswerTtl(new Uint8Array([1, 2, 3]))).toBeNull();
  });
});

describe("soaNegativeTtl (RFC 2308: min(SOA TTL, SOA.MINIMUM))", () => {
  it("caps by SOA.MINIMUM when the SOA TTL is larger", () => {
    const query = buildQuery();
    // SOA TTL 3600, MINIMUM 60 → negative TTL 60.
    const resp = buildResponse(query, {
      rcode: 3,
      answerCount: 0,
      authorityTtl: 3600,
      soaMinimum: 60,
    });
    expect(soaNegativeTtl(resp)).toBe(60);
  });

  it("uses the SOA TTL when it is smaller than MINIMUM", () => {
    const resp = buildResponse(buildQuery(), {
      rcode: 3,
      answerCount: 0,
      authorityTtl: 30,
      soaMinimum: 3600,
    });
    expect(soaNegativeTtl(resp)).toBe(30);
  });

  it("reads MINIMUM from an explicit SOA RDATA", () => {
    const resp = buildResponse(buildQuery(), {
      rcode: 3,
      answerCount: 0,
      authorityTtl: 900,
      authorityRdata: buildSoaRdata(
        "ns1.example.com.",
        "hostmaster.example.com.",
        1, 7200, 900, 1209600, 42,
      ),
    });
    expect(soaNegativeTtl(resp)).toBe(42);
  });

  it("returns null when there is no SOA in authority", () => {
    const resp = buildResponse(buildQuery(), { rcode: 3, answerCount: 0 });
    expect(soaNegativeTtl(resp)).toBeNull();
  });
});
