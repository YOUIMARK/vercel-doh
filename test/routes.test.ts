import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createApp } from "../src/app";
import { loadConfig } from "../src/config";
import { hasMeaningfulEcs } from "../src/dns/ecs";
import { encodeBase64Url, parseHeader, parseSections, rcodeOf } from "../src/dns/wire";
import { buildQuery, buildResponse, buildQuestion } from "./helpers";

const UPSTREAM = "https://up.example/dns-query";

function cfg(overrides: Record<string, string> = {}) {
  return loadConfig({ UPSTREAM_DOH_URLS: UPSTREAM, ...overrides } as NodeJS.ProcessEnv);
}

function makeApp(overrides: Record<string, string> = {}) {
  return createApp(cfg(overrides));
}

const acceptMessage = { accept: "application/dns-message" };

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("GET /dns-query", () => {
  it("proxies a valid query and sets TTL-aware cache headers", async () => {
    const app = makeApp();
    const query = buildQuery();
    const upstreamBody = buildResponse(query, { ttl: 300 });
    vi.mocked(fetch).mockResolvedValue(new Response(upstreamBody, { status: 200 }));

    const res = await app.request(`/dns-query?dns=${encodeBase64Url(query)}`, { headers: acceptMessage });

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/dns-message");
    expect(res.headers.get("cache-control")).toContain("s-maxage=300");
    expect(new Uint8Array(await res.arrayBuffer())).toEqual(upstreamBody);

    const calledUrl = String(vi.mocked(fetch).mock.calls[0]![0]);
    expect(calledUrl.startsWith(`${UPSTREAM}?dns=`)).toBe(true);
  });

  it("returns 400 when the dns parameter is missing", async () => {
    const res = await makeApp().request("/dns-query", { headers: acceptMessage });
    expect(res.status).toBe(400);
  });

  it("returns 400 on invalid base64url", async () => {
    const res = await makeApp().request("/dns-query?dns=!!!", { headers: acceptMessage });
    expect(res.status).toBe(400);
  });

  it("serves an info page to browsers (no DoH accept header)", async () => {
    const res = await makeApp().request("/dns-query", {
      headers: { accept: "text/html" },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
  });
});

describe("POST /dns-query", () => {
  it("proxies a raw dns-message body", async () => {
    const app = makeApp();
    const query = buildQuery();
    const upstreamBody = buildResponse(query, { ttl: 60 });
    vi.mocked(fetch).mockResolvedValue(new Response(upstreamBody, { status: 200 }));

    const res = await app.request("/dns-query", {
      method: "POST",
      headers: { ...acceptMessage, "content-type": "application/dns-message" },
      body: query,
    });

    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store"); // POST never cached
    const sent = vi.mocked(fetch).mock.calls[0]![1] as RequestInit;
    expect((sent.body as Uint8Array).length).toBe(query.length);
  });

  it("returns 415 for a non-dns-message content type", async () => {
    const res = await makeApp().request("/dns-query", {
      method: "POST",
      headers: { ...acceptMessage, "content-type": "application/json" },
      body: "{}",
    });
    expect(res.status).toBe(415);
  });

  it("returns 413 for oversized bodies", async () => {
    const big = new Uint8Array(70 * 1024);
    const res = await makeApp().request("/dns-query", {
      method: "POST",
      headers: { ...acceptMessage, "content-type": "application/dns-message" },
      body: big,
    });
    expect(res.status).toBe(413);
  });
});

describe("failures", () => {
  it("returns a SERVFAIL dns-message when all upstreams fail", async () => {
    const app = makeApp();
    const query = buildQuery();
    vi.mocked(fetch).mockRejectedValue(new TypeError("down"));

    const res = await app.request(`/dns-query?dns=${encodeBase64Url(query)}`, { headers: acceptMessage });

    expect(res.status).toBe(200); // dns-message response
    expect(res.headers.get("content-type")).toBe("application/dns-message");
    const body = new Uint8Array(await res.arrayBuffer());
    const header = parseHeader(body)!;
    expect(header.id).toBe(parseHeader(query)!.id);
    expect(rcodeOf(header.flags)).toBe(2); // SERVFAIL
    expect(res.headers.get("cache-control")).toBe("no-store");
  });

  it("returns 404 for an unknown provider path", async () => {
    const res = await makeApp().request(`/dns-query/nope?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB`, {
      headers: acceptMessage,
    });
    expect(res.status).toBe(404);
  });
});

describe("CORS / aux endpoints", () => {
  it("answers OPTIONS with CORS preflight headers", async () => {
    const res = await makeApp().request("/dns-query", { method: "OPTIONS" });
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBe("*");
  });

  it("rejects PUT", async () => {
    const res = await makeApp().request("/dns-query", { method: "PUT" });
    expect(res.status).toBe(405);
  });

  it("serves /health", async () => {
    const res = await makeApp().request("/health");
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("ok");
  });

  it("serves the DNS lookup tool at /", async () => {
    const res = await makeApp().request("/");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
    const html = await res.text();
    expect(html).toContain('id="dns-form"');
    expect(html).toContain('src="/script.js"');
    expect(html).toContain('href="/style.css"');
  });

  it("serves dns-json for the JSON API", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ Status: 0, Answer: [{ data: "1.2.3.4" }] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    const res = await makeApp().request("/dns-query-json?name=example.com&type=A", {
      headers: { accept: "application/dns-json" },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/json");
    const calledUrl = String(vi.mocked(fetch).mock.calls[0]![0]);
    expect(calledUrl).toContain("dns.google/resolve");
    expect(calledUrl).toContain("name=example.com");
  });
});

describe("ECS /auto_ecs", () => {
  it("injects ECS into a query without an OPT RR (single OPT, no-store)", async () => {
    const app = makeApp();
    const query = buildQuery(); // no OPT
    const upstreamBody = buildResponse(query, { ttl: 300 });
    vi.mocked(fetch).mockResolvedValue(new Response(upstreamBody, { status: 200 }));

    const res = await app.request("/dns-query/auto_ecs", {
      method: "POST",
      headers: {
        ...acceptMessage,
        "content-type": "application/dns-message",
        "x-vercel-forwarded-for": "8.8.8.8",
      },
      body: query,
    });

    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store"); // ECS injected → no shared cache

    const sent = vi.mocked(fetch).mock.calls[0]![1] as RequestInit;
    const sentBody = sent.body as Uint8Array;
    expect(hasMeaningfulEcs(sentBody)).toBe(true);
    const sections = parseSections(sentBody)!;
    expect(sections.additional.rrs.filter((rr) => rr.rrType === 41)).toHaveLength(1);
    expect(sections.header.ar).toBe(1);
  });

  it("merges ECS into an existing OPT RR (ARCOUNT stays 1)", async () => {
    const app = makeApp();
    // Query with an OPT RR carrying NSID (no ECS).
    const nsidOpt = new Uint8Array([0, 3, 0, 2, 65, 65]);
    const optRr = new Uint8Array(11 + nsidOpt.length);
    optRr[0] = 0;
    const optView = new DataView(optRr.buffer);
    optView.setUint16(1, 41);
    optView.setUint16(3, 4096);
    optView.setUint16(9, nsidOpt.length);
    optRr.set(nsidOpt, 11);

    const question = buildQuestion("example.com");
    const query = buildQuery({ question, additional: optRr });
    const upstreamBody = buildResponse(query, { ttl: 120 });
    vi.mocked(fetch).mockResolvedValue(new Response(upstreamBody, { status: 200 }));

    const res = await app.request("/dns-query/auto_ecs", {
      method: "POST",
      headers: {
        ...acceptMessage,
        "content-type": "application/dns-message",
        "x-vercel-forwarded-for": "8.8.8.8",
      },
      body: query,
    });
    expect(res.status).toBe(200);

    const sent = vi.mocked(fetch).mock.calls[0]![1] as RequestInit;
    const sentBody = sent.body as Uint8Array;
    const sections = parseSections(sentBody)!;
    const opts = sections.additional.rrs.filter((rr) => rr.rrType === 41);
    expect(opts).toHaveLength(1); // CRITICAL: never two OPT RRs
    expect(sections.header.ar).toBe(1); // ARCOUNT unchanged
    expect(hasMeaningfulEcs(sentBody)).toBe(true);
  });
});

describe("path-based provider mapping", () => {
  it("routes /dns-query/{provider} to the mapped upstream", async () => {
    const app = makeApp({
      DOMAIN_MAPPINGS: JSON.stringify({ google: { targetDomain: "dns.google" } }),
    });
    const query = buildQuery();
    vi.mocked(fetch).mockResolvedValue(new Response(buildResponse(query, { ttl: 60 }), { status: 200 }));

    const res = await app.request(`/dns-query/google?dns=${encodeBase64Url(query)}`, { headers: acceptMessage });
    expect(res.status).toBe(200);
    const calledUrl = String(vi.mocked(fetch).mock.calls[0]![0]);
    expect(calledUrl.startsWith("https://dns.google/dns-query?dns=")).toBe(true);
  });
});
