import { describe, expect, it } from "vitest";
import { buildCacheControl } from "../src/cache-control";

const base = {
  method: "GET",
  validResponse: true,
  rcode: 0,
  ecsSensitive: false,
  minAnswerTtl: 300,
  negativeTtl: null,
  cacheMaxAge: 300,
};

describe("buildCacheControl — positive answers", () => {
  it("GET + NOERROR + answer → s-maxage from answer TTL (capped)", () => {
    expect(buildCacheControl(base)).toBe("public, s-maxage=300, stale-while-revalidate=60");
    expect(buildCacheControl({ ...base, minAnswerTtl: 900 })).toBe(
      "public, s-maxage=300, stale-while-revalidate=60",
    );
    expect(buildCacheControl({ ...base, minAnswerTtl: 30 })).toBe(
      "public, s-maxage=30, stale-while-revalidate=60",
    );
  });
});

describe("buildCacheControl — negative answers (RFC 2308)", () => {
  it("NXDOMAIN with SOA negative TTL", () => {
    expect(buildCacheControl({ ...base, rcode: 3, minAnswerTtl: null, negativeTtl: 60 })).toBe(
      "public, s-maxage=60, stale-while-revalidate=60",
    );
  });

  it("NODATA (NOERROR, no answers) uses the negative TTL", () => {
    expect(buildCacheControl({ ...base, rcode: 0, minAnswerTtl: null, negativeTtl: 90 })).toBe(
      "public, s-maxage=90, stale-while-revalidate=60",
    );
  });

  it("NXDOMAIN without a usable SOA → no-store (RFC 2308: no safe TTL)", () => {
    expect(buildCacheControl({ ...base, rcode: 3, minAnswerTtl: null, negativeTtl: null })).toBe(
      "no-store",
    );
  });

  it("NODATA (NOERROR, no answers) without a usable SOA → no-store", () => {
    expect(buildCacheControl({ ...base, rcode: 0, minAnswerTtl: null, negativeTtl: null })).toBe(
      "no-store",
    );
  });
});

describe("buildCacheControl — never cache publicly", () => {
  it("SERVFAIL / REFUSED / FORMERR / other RCODEs → no-store", () => {
    for (const rcode of [1, 2, 4, 5, 9, 16]) {
      expect(buildCacheControl({ ...base, rcode }), `rcode ${rcode}`).toBe("no-store");
    }
  });

  it("POST → no-store", () => {
    expect(buildCacheControl({ ...base, method: "POST" })).toBe("no-store");
  });

  it("ECS-sensitive (incoming or injected) → no-store", () => {
    expect(buildCacheControl({ ...base, ecsSensitive: true })).toBe("no-store");
  });

  it("invalid upstream response → no-store", () => {
    expect(buildCacheControl({ ...base, validResponse: false })).toBe("no-store");
  });
});
