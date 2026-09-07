import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadConfig } from "../src/config";
import {
  buildUpstreamHeaders,
  pickUpstream,
  queryUpstreams,
  resetCursor,
  resolveProvider,
  UpstreamError,
} from "../src/upstream";

function config(overrides: Record<string, string> = {}) {
  return loadConfig({
    UPSTREAM_DOH_URLS: "https://up1.example/dns-query,https://up2.example/dns-query,https://up3.example/dns-query",
    ...overrides,
  } as NodeJS.ProcessEnv);
}

const ok = () => new Response(new Uint8Array([0, 1, 2, 3, 4]), { status: 200 });

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

  it("returns null for unknown providers", () => {
    expect(resolveProvider(config(), "nope")).toBeNull();
  });
});

describe("sequential failover (default, no broadcast)", () => {
  it("succeeds on the second upstream after the first fails", async () => {
    const cfg = config();
    const fetchMock = vi.mocked(fetch);
    fetchMock
      .mockRejectedValueOnce(new TypeError("network down"))
      .mockResolvedValueOnce(ok());

    const res = await queryUpstreams(cfg, cfg.upstreamUrls, (url, signal) => ({ url, init: { signal } }));
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(String(fetchMock.mock.calls[0]![0])).toContain("up1");
    expect(String(fetchMock.mock.calls[1]![0])).toContain("up2");
  });

  it("fails over on 5xx but returns 4xx as-is", async () => {
    const cfg = config();
    const fetchMock = vi.mocked(fetch);
    fetchMock
      .mockResolvedValueOnce(new Response("err", { status: 503 }))
      .mockResolvedValueOnce(new Response("err", { status: 400 }));

    const res = await queryUpstreams(cfg, cfg.upstreamUrls, (url, signal) => ({ url, init: { signal } }));
    expect(res.status).toBe(400);
    expect(fetchMock).toHaveBeenCalledTimes(2); // 503 → next; 400 returned directly
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
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockRejectedValue(new TypeError("down"));
    await expect(
      queryUpstreams(cfg, cfg.upstreamUrls, (url, signal) => ({ url, init: { signal } })),
    ).rejects.toBeInstanceOf(UpstreamError);
    expect(fetchMock.mock.calls.length).toBeLessThanOrEqual(3);
  });
});

describe("race mode", () => {
  it("resolves with the fastest successful response", async () => {
    const cfg = config({ RACE_UPSTREAMS: "true" });
    const fetchMock = vi.mocked(fetch);
    let resolveSlow!: (r: Response) => void;
    fetchMock
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveSlow = resolve;
          }),
      ) // up1: slow
      .mockResolvedValueOnce(ok()); // up2: fast

    const res = await queryUpstreams(cfg, cfg.upstreamUrls, (url, signal) => ({ url, init: { signal } }));
    expect(res.status).toBe(200);
    resolveSlow(ok()); // settle the loser afterwards
    await Promise.resolve();
  });

  it("rejects when all upstreams return 5xx", async () => {
    const cfg = config({ RACE_UPSTREAMS: "true" });
    vi.mocked(fetch).mockResolvedValue(new Response("err", { status: 502 }));
    await expect(queryUpstreams(cfg, cfg.upstreamUrls, (url, signal) => ({ url, init: { signal } }))).rejects.toBeInstanceOf(
      UpstreamError,
    );
  });
});

describe("buildUpstreamHeaders", () => {
  it("strips hop-by-hop and privacy headers, forces DoH Accept", () => {
    const incoming = new Headers({
      Host: "proxy.example",
      Connection: "keep-alive",
      "Keep-Alive": "timeout=5",
      "X-Forwarded-For": "1.2.3.4",
      "X-Real-Ip": "1.2.3.4",
      "X-Vercel-Forwarded-For": "1.2.3.4",
      "User-Agent": "doh-client",
      Accept: "application/dns-json",
    });
    const out = buildUpstreamHeaders(incoming, "application/dns-message");
    expect(out.get("x-forwarded-for")).toBeNull();
    expect(out.get("x-real-ip")).toBeNull();
    expect(out.get("x-vercel-forwarded-for")).toBeNull();
    expect(out.get("connection")).toBeNull();
    expect(out.get("host")).toBeNull();
    expect(out.get("accept")).toBe("application/dns-message");
    expect(out.get("user-agent")).toBe("doh-client");
  });
});
