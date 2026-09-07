import { describe, expect, it } from "vitest";
import { buildCacheControl } from "../src/cache-control";

const base = { method: "GET", rcode: 0, ecsAdded: false, minTtl: 300, cacheMaxAge: 300 };

describe("buildCacheControl", () => {
  it("GET + NOERROR + no ECS → s-maxage from TTL (capped)", () => {
    expect(buildCacheControl(base)).toBe("public, s-maxage=300, stale-while-revalidate=60");
    expect(buildCacheControl({ ...base, minTtl: 900 })).toBe(
      "public, s-maxage=300, stale-while-revalidate=60",
    );
    expect(buildCacheControl({ ...base, minTtl: 30 })).toBe(
      "public, s-maxage=30, stale-while-revalidate=60",
    );
  });

  it("falls back to a conservative 60s when TTL is unknown", () => {
    expect(buildCacheControl({ ...base, minTtl: null })).toBe(
      "public, s-maxage=60, stale-while-revalidate=60",
    );
  });

  it("POST → no-store", () => {
    expect(buildCacheControl({ ...base, method: "POST" })).toBe("no-store");
  });

  it("ECS injected → no-store", () => {
    expect(buildCacheControl({ ...base, ecsAdded: true })).toBe("no-store");
  });

  it("negative answers → conservative public cache", () => {
    expect(buildCacheControl({ ...base, rcode: 3 })).toBe("public, s-maxage=60");
  });
});
