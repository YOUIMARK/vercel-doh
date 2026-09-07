import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadConfig } from "../src/config";
import {
  buildUpstreamHeaders,
  getDispatcher,
  pickUpstream,
  queryUpstreams,
  resetCursor,
  resolveProvider,
  UpstreamError,
} from "../src/upstream";
import { buildQuery, buildResponse } from "./helpers";

function config(overrides: Record<string, string> = {}) {
  return loadConfig({
    UPSTREAM_DOH_URLS: "https://up1.example/dns-query,https://up2.example/dns-query,https://up3.example/dns-query",
    ...overrides,
  } as NodeJS.ProcessEnv);
}

/** A valid DNS response body (QR=1, one answer, TTL 300). */
const VALID_BODY = buildResponse(buildQuery(), { ttl: 300 });

const validResponse = (status = 200) =>
  new Response(VALID_BODY, {
    status,
    headers: { "content-type": "application/dns-message" },
  });

const badContentType = () =>
  new Response(VALID_BODY, { status: 200, headers: { "content-type": "text/html" } });

const badBody = () =>
  new Response("<html>not dns</html>", {
    status: 200,
    headers: { "content-type": "application/dns-message" },
  });

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
  resetCursor();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("pickUpstream", () => {
  it("round-robins across upstreams", () => {
    const cfg = config();
    expect(pickUpstream(cfg, null)).toBe("https://up1.example/dns-query");
    expect(pickUpstream(cfg, null)).toBe("https://up2.example/dns-query");
    expect(pickUpstream(cfg, null)).toBe("https://up3.example/dns-query");
    expect(pickUpstream(cfg, null)).toBe("https://up1.example/dns-query");
  });
});

describe("resolveProvider", () => {
  it("normalizes a bare host and appends /dns-query", () => {
    const cfg = config({
      DOMAIN_MAPPINGS: JSON.stringify({ google: { targetDomain: "dns.google" } }),
    });
    expect(resolveProvider(cfg, "google")).toBe("https://dns.google/dns-query");
  });

  it("keeps an explicit full URL", () => {
    const cfg = config({
      DOMAIN_MAPPINGS: JSON.stringify({ cf: { targetDomain: "https://cloudflare-dns.com/dns-query" } }),
    });
    expect(resolveProvider(cfg, "cf")).toBe("https://cloudflare-dns.com/dns-query");
  });

  it("returns null for unknown providers and prototype properties", () => {
    const cfg = config();
    expect(resolveProvider(cfg, "nope")).toBeNull();
    expect(resolveProvider(cfg, "toString")).toBeNull();
    expect(resolveProvider(cfg, "constructor")).toBeNull();
  });
});

describe("sequential failover (default, no broadcast)", () => {
  it("succeeds on the second upstream after the first fails", async () => {
    const cfg = config();
    const fetchMock = vi.mocked(fetch);
    fetchMock
      .mockRejectedValueOnce(new TypeError("network down"))
      .mockResolvedValueOnce(validResponse());

    const result = await queryUpstreams(cfg, cfg.upstreamUrls, (url, signal) => ({ url, init: { signal } }));
    expect(result.status).toBe(200);
    expect(result.body).toEqual(VALID_BODY);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(String(fetchMock.mock.calls[0]![0])).toContain("up1");
    expect(String(fetchMock.mock.calls[1]![0])).toContain("up2");
  });

  it("fails over on 5xx and 4xx statuses", async () => {
    const cfg = config();
    const fetchMock = vi.mocked(fetch);
    fetchMock
      .mockResolvedValueOnce(new Response("err", { status: 503 }))
      .mockResolvedValueOnce(new Response("err", { status: 400 }))
      .mockResolvedValueOnce(validResponse());

    const result = await queryUpstreams(cfg, cfg.upstreamUrls, (url, signal) => ({ url, init: { signal } }));
    expect(result.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(3); // 503 and 400 failed over
  });

  it("fails over on wrong content-type and malformed bodies", async () => {
    const cfg = config();
    const fetchMock = vi.mocked(fetch);
    fetchMock
      .mockResolvedValueOnce(badContentType())
      .mockResolvedValueOnce(badBody())
      .mockResolvedValueOnce(validResponse());

    const result = await queryUpstreams(cfg, cfg.upstreamUrls, (url, signal) => ({ url, init: { signal } }));
    expect(result.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("throws UpstreamError when every upstream fails", async () => {
    const cfg = config();
    vi.mocked(fetch).mockRejectedValue(new TypeError("down"));
    await expect(queryUpstreams(cfg, cfg.upstreamUrls, (url, signal) => ({ url, init: { signal } }))).rejects.toBeInstanceOf(
      UpstreamError,
    );
  });

  it("never exceeds maxAttempts (no broadcast beyond the cap)", async () => {
    const cfg = config();
    vi.mocked(fetch).mockRejectedValue(new TypeError("down"));
    await expect(
      queryUpstreams(cfg, cfg.upstreamUrls, (url, signal) => ({ url, init: { signal } })),
    ).rejects.toBeInstanceOf(UpstreamError);
    expect(vi.mocked(fetch).mock.calls.length).toBeLessThanOrEqual(3);
  });
});

describe("race mode", () => {
  it("resolves with the fastest valid response and forces redirect:error", async () => {
    const cfg = config({ RACE_UPSTREAMS: "true" });
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockImplementation(async (_url, init) => {
      expect((init as RequestInit).redirect).toBe("error");
      return validResponse();
    });

    const result = await queryUpstreams(cfg, cfg.upstreamUrls, (url, signal) => ({ url, init: { signal } }));
    expect(result.status).toBe(200);
    expect(result.body).toEqual(VALID_BODY);
    expect(fetchMock.mock.calls.length).toBe(3); // raced all three
  });

  it("rejects when all upstreams return 5xx", async () => {
    const cfg = config({ RACE_UPSTREAMS: "true" });
    vi.mocked(fetch).mockResolvedValue(new Response("err", { status: 502 }));
    await expect(queryUpstreams(cfg, cfg.upstreamUrls, (url, signal) => ({ url, init: { signal } }))).rejects.toBeInstanceOf(
      UpstreamError,
    );
  });

  it("rejects when upstreams return invalid DNS bodies", async () => {
    const cfg = config({ RACE_UPSTREAMS: "true" });
    vi.mocked(fetch).mockResolvedValue(badBody());
    await expect(queryUpstreams(cfg, cfg.upstreamUrls, (url, signal) => ({ url, init: { signal } }))).rejects.toBeInstanceOf(
      UpstreamError,
    );
  });
});

describe("redirect hardening", () => {
  it("never follows redirects in sequential mode", async () => {
    const cfg = config();
    vi.mocked(fetch).mockImplementation(async (_url, init) => {
      expect((init as RequestInit).redirect).toBe("error");
      return validResponse();
    });
    await queryUpstreams(cfg, cfg.upstreamUrls, (url, signal) => ({ url, init: { signal } }));
  });
});

describe("address-family dispatchers", () => {
  it("selects a dispatcher for v4/v6 and none for auto", () => {
    expect(getDispatcher("auto")).toBeUndefined();
    expect(getDispatcher("v4")).toBeDefined();
    expect(getDispatcher("v6")).toBeDefined();
  });

  it("passes the family dispatcher into the upstream fetch", async () => {
    const cfg = config();
    const fetchMock = vi.mocked(fetch);
    // A fresh Response per call — a shared Response's body can only be read once.
    fetchMock.mockImplementation(async () => validResponse());

    await queryUpstreams(cfg, cfg.upstreamUrls, (url, signal) => ({ url, init: { signal } }), "v4");
    const init = fetchMock.mock.calls[0]![1] as RequestInit & { dispatcher?: unknown };
    expect(init.dispatcher).toBeDefined();

    await queryUpstreams(cfg, cfg.upstreamUrls, (url, signal) => ({ url, init: { signal } }), "auto");
    const autoInit = fetchMock.mock.calls[1]![1] as RequestInit & { dispatcher?: unknown };
    expect(autoInit.dispatcher).toBeUndefined();
  });
});

describe("buildUpstreamHeaders (allowlist)", () => {
  it("only sends Accept, User-Agent and optional Content-Type", () => {
    const headers = buildUpstreamHeaders("application/dns-message", "vercel-doh/1.0.0", "application/dns-message");
    expect(headers.get("accept")).toBe("application/dns-message");
    expect(headers.get("user-agent")).toBe("vercel-doh/1.0.0");
    expect(headers.get("content-type")).toBe("application/dns-message");
    // No client-controlled headers are ever propagated.
    expect(headers.get("authorization")).toBeNull();
    expect(headers.get("cookie")).toBeNull();
    expect(headers.get("accept-language")).toBeNull();
    expect(headers.get("x-forwarded-for")).toBeNull();
    expect(headers.get("x-custom")).toBeNull();
    expect([...headers.keys()].sort()).toEqual(["accept", "content-type", "user-agent"]);
  });
});
