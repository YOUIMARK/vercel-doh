import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createApp } from "../src/app";
import { loadConfig } from "../src/config";
import { buildEcsOption, ecsStatus } from "../src/dns/ecs";
import { encodeBase64Url, parseHeader, parseSections, rcodeOf } from "../src/dns/wire";
import { getDispatcher } from "../src/upstream";
import { buildOptRr, buildQuery, buildResponse, buildQuestion, concat } from "./helpers";

const UPSTREAM = "https://up.example/dns-query";

function cfg(overrides: Record<string, string> = {}) {
  return loadConfig({ UPSTREAM_DOH_URLS: UPSTREAM, ...overrides } as NodeJS.ProcessEnv);
}

function makeApp(overrides: Record<string, string> = {}) {
  return createApp(cfg(overrides));
}

const acceptMessage = { accept: "application/dns-message" };

/** A valid upstream response with the correct Content-Type. */
function validUpstream(
  query: Uint8Array<ArrayBuffer>,
  opts: {
    ttl?: number;
    rcode?: number;
    answerCount?: number;
    authorityTtl?: number;
    soaMinimum?: number;
    additional?: Uint8Array<ArrayBuffer>;
  } = {},
) {
  const body = buildResponse(query, {
    ttl: opts.ttl ?? 300,
    rcode: opts.rcode ?? 0,
    answerCount: opts.answerCount,
    authorityTtl: opts.authorityTtl,
    soaMinimum: opts.soaMinimum,
    additional: opts.additional,
  });
  return new Response(body, { status: 200, headers: { "content-type": "application/dns-message" } });
}

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
    vi.mocked(fetch).mockResolvedValue(validUpstream(query, { ttl: 300 }));

    const res = await app.request(`/dns-query?dns=${encodeBase64Url(query)}`, { headers: acceptMessage });

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/dns-message");
    expect(res.headers.get("cache-control")).toContain("s-maxage=300");
    expect(new Uint8Array(await res.arrayBuffer())).toEqual(buildResponse(query, { ttl: 300 }));

    const calledUrl = String(vi.mocked(fetch).mock.calls[0]![0]);
    expect(calledUrl.startsWith(`${UPSTREAM}?dns=`)).toBe(true);
  });

  it("accepts missing Accept and */* headers (RFC 8484: SHOULD, not MUST)", async () => {
    const app = makeApp();
    const query = buildQuery();
    vi.mocked(fetch).mockResolvedValue(validUpstream(query, { ttl: 60 }));

    const resNoAccept = await app.request(`/dns-query?dns=${encodeBase64Url(query)}`);
    expect(resNoAccept.status).toBe(200);
    const resWildcard = await app.request(`/dns-query?dns=${encodeBase64Url(query)}`, {
      headers: { accept: "*/*" },
    });
    expect(resWildcard.status).toBe(200);
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

describe("query validation (protocol gate)", () => {
  it("rejects malformed queries with 400 before touching upstream", async () => {
    const app = makeApp();
    const malformed = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]); // bad qd/truncated
    const res = await app.request(`/dns-query?dns=${encodeBase64Url(malformed)}`, { headers: acceptMessage });
    expect(res.status).toBe(400);
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it("rejects queries without exactly one question", async () => {
    const app = makeApp();
    const zeroQd = buildQuery({ qd: 0 });
    const res = await app.request(`/dns-query?dns=${encodeBase64Url(zeroQd)}`, { headers: acceptMessage });
    expect(res.status).toBe(400);
  });

  it("rejects queries with duplicate OPT RRs", async () => {
    const app = makeApp();
    const dupOpt = buildQuery({
      additional: concat([buildOptRr(new Uint8Array(0)), buildOptRr(new Uint8Array(0))]),
      ar: 2,
    });
    const res = await app.request(`/dns-query?dns=${encodeBase64Url(dupOpt)}`, { headers: acceptMessage });
    expect(res.status).toBe(400);
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it("rejects queries with malformed ECS options", async () => {
    const app = makeApp();
    const truncatedEcs = new Uint8Array([0, 8, 0, 6, 0, 1, 24, 0, 1, 2]); // addr truncated
    const msg = buildQuery({ additional: buildOptRr(truncatedEcs) });
    const res = await app.request(`/dns-query?dns=${encodeBase64Url(msg)}`, { headers: acceptMessage });
    expect(res.status).toBe(400);
  });
});

describe("POST /dns-query", () => {
  it("proxies a raw dns-message body", async () => {
    const app = makeApp();
    const query = buildQuery();
    vi.mocked(fetch).mockResolvedValue(validUpstream(query, { ttl: 60 }));

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

  it("does NOT relay upstream 4xx bodies as DNS answers (fails over to SERVFAIL)", async () => {
    const app = makeApp();
    const query = buildQuery();
    vi.mocked(fetch).mockResolvedValue(new Response("bad request", { status: 400 }));

    const res = await app.request(`/dns-query?dns=${encodeBase64Url(query)}`, { headers: acceptMessage });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/dns-message");
    const body = new Uint8Array(await res.arrayBuffer());
    expect(rcodeOf(parseHeader(body)!.flags)).toBe(2); // SERVFAIL, not a 400 relay
  });

  it("does NOT cache SERVFAIL responses from upstream", async () => {
    const app = makeApp();
    const query = buildQuery();
    vi.mocked(fetch).mockResolvedValue(validUpstream(query, { rcode: 2, answerCount: 0 }));

    const res = await app.request(`/dns-query?dns=${encodeBase64Url(query)}`, { headers: acceptMessage });
    expect(res.status).toBe(200);
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
    expect(html).toContain('window.DOH_ENDPOINT="/dns-query"');
  });

  it("exposes the obfuscated DoH path to the frontend", async () => {
    const res = await makeApp({ DOH_PATH: "/x9k2" }).request("/");
    const html = await res.text();
    expect(html).toContain('window.DOH_ENDPOINT="/x9k2"');
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
    expect(res.headers.get("cache-control")).toContain("s-maxage=300");
    const calledUrl = String(vi.mocked(fetch).mock.calls[0]![0]);
    expect(calledUrl).toContain("dns.google/resolve");
    expect(calledUrl).toContain("name=example.com");
  });

  it("does not publicly cache dns-json responses carrying edns_client_subnet", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ Status: 0 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    const res = await makeApp().request(
      "/dns-query-json?name=example.com&type=A&edns_client_subnet=1.2.3.0/24",
      { headers: { accept: "application/dns-json" } },
    );
    expect(res.headers.get("cache-control")).toBe("no-store");
  });
});

describe("ECS /auto_ecs", () => {
  it("injects ECS into a query without an OPT RR (single OPT, no-store)", async () => {
    const app = makeApp();
    const query = buildQuery(); // no OPT
    vi.mocked(fetch).mockResolvedValue(validUpstream(query, { ttl: 300 }));

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
    expect(ecsStatus(sentBody)).toBe("positive");
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
    vi.mocked(fetch).mockResolvedValue(validUpstream(query, { ttl: 120 }));

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
    expect(ecsStatus(sentBody)).toBe("positive");
  });

  it("respects ECS source prefix 0: never injects the real subnet, never caches", async () => {
    const app = makeApp();
    const zeroEcs = buildEcsOption({ family: 1, addressBytes: new Uint8Array([1, 2, 3, 4]) }, 0);
    const query = buildQuery({ additional: buildOptRr(zeroEcs) });
    vi.mocked(fetch).mockResolvedValue(validUpstream(query, { ttl: 300 }));

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
    expect(res.headers.get("cache-control")).toBe("no-store");

    // The query is forwarded byte-for-byte — no ECS was injected over /0.
    const sent = vi.mocked(fetch).mock.calls[0]![1] as RequestInit;
    const sentBody = sent.body as Uint8Array;
    expect(sentBody).toEqual(query);
    expect(ecsStatus(sentBody)).toBe("zero");
  });

  it("never publicly caches GETs that carry client ECS", async () => {
    const app = makeApp();
    const ecsOption = buildEcsOption({ family: 1, addressBytes: new Uint8Array([1, 2, 3, 4]) }, 24);
    const query = buildQuery({ additional: buildOptRr(ecsOption) });
    vi.mocked(fetch).mockResolvedValue(validUpstream(query, { ttl: 300 }));

    const res = await app.request(`/dns-query?dns=${encodeBase64Url(query)}`, { headers: acceptMessage });
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
  });
});

describe("path-based provider mapping", () => {
  it("routes /dns-query/{provider} to the mapped upstream", async () => {
    const app = makeApp({
      DOMAIN_MAPPINGS: JSON.stringify({ google: { targetDomain: "dns.google" } }),
    });
    const query = buildQuery();
    vi.mocked(fetch).mockResolvedValue(validUpstream(query, { ttl: 60 }));

    const res = await app.request(`/dns-query/google?dns=${encodeBase64Url(query)}`, { headers: acceptMessage });
    expect(res.status).toBe(200);
    const calledUrl = String(vi.mocked(fetch).mock.calls[0]![0]);
    expect(calledUrl.startsWith("https://dns.google/dns-query?dns=")).toBe(true);
  });
});

describe("URL flags (v4/v6/ecs/no-ecs override env defaults)", () => {
  const dispatcherOf = (call: number) =>
    (vi.mocked(fetch).mock.calls[call]![1] as RequestInit & { dispatcher?: unknown }).dispatcher;

  it("/v4 forces an IPv4-only dispatcher", async () => {
    const app = makeApp();
    const query = buildQuery();
    vi.mocked(fetch).mockResolvedValue(validUpstream(query, { ttl: 60 }));

    const res = await app.request(`/dns-query/v4?dns=${encodeBase64Url(query)}`, { headers: acceptMessage });
    expect(res.status).toBe(200);
    expect(dispatcherOf(0)).toBe(getDispatcher("v4"));
  });

  it("/v6 forces an IPv6-only dispatcher", async () => {
    const app = makeApp();
    const query = buildQuery();
    vi.mocked(fetch).mockResolvedValue(validUpstream(query, { ttl: 60 }));

    const res = await app.request(`/dns-query/v6?dns=${encodeBase64Url(query)}`, { headers: acceptMessage });
    expect(res.status).toBe(200);
    expect(dispatcherOf(0)).toBe(getDispatcher("v6"));
  });

  it("URL flag overrides UPSTREAM_FAMILY env", async () => {
    const app = makeApp({ UPSTREAM_FAMILY: "v6" });
    const query = buildQuery();
    vi.mocked(fetch).mockResolvedValue(validUpstream(query, { ttl: 60 }));

    const res = await app.request(`/dns-query/v4?dns=${encodeBase64Url(query)}`, { headers: acceptMessage });
    expect(res.status).toBe(200);
    expect(dispatcherOf(0)).toBe(getDispatcher("v4"));
    expect(dispatcherOf(0)).not.toBe(getDispatcher("v6"));
  });

  it("env UPSTREAM_FAMILY applies when no URL flag is present", async () => {
    const app = makeApp({ UPSTREAM_FAMILY: "v6" });
    const query = buildQuery();
    vi.mocked(fetch).mockResolvedValue(validUpstream(query, { ttl: 60 }));

    const res = await app.request(`/dns-query?dns=${encodeBase64Url(query)}`, { headers: acceptMessage });
    expect(res.status).toBe(200);
    expect(dispatcherOf(0)).toBe(getDispatcher("v6"));
  });

  it("/no-ecs overrides AUTO_ADD_ECS=true env (no injection)", async () => {
    const app = makeApp({ AUTO_ADD_ECS: "true" });
    const query = buildQuery();
    vi.mocked(fetch).mockResolvedValue(validUpstream(query, { ttl: 60 }));

    const res = await app.request(`/dns-query/no-ecs?dns=${encodeBase64Url(query)}`, {
      headers: { ...acceptMessage, "x-vercel-forwarded-for": "8.8.8.8" },
    });
    expect(res.status).toBe(200);
    const sent = vi.mocked(fetch).mock.calls[0]![1] as RequestInit;
    expect(sent.body ?? undefined).toBeUndefined(); // GET has no body; the query went via ?dns=
    // The forwarded query must not have gained an ECS option.
    const calledUrl = String(vi.mocked(fetch).mock.calls[0]![0]);
    const dnsParam = new URL(calledUrl).searchParams.get("dns")!;
    const forwarded = new Uint8Array(Buffer.from(dnsParam.replace(/-/g, "+").replace(/_/g, "/"), "base64"));
    expect(ecsStatus(forwarded)).toBe("absent");
  });

  it("combines flags: /v6/ecs forces family AND injects ECS", async () => {
    const app = makeApp();
    const query = buildQuery();
    vi.mocked(fetch).mockResolvedValue(validUpstream(query, { ttl: 60 }));

    const res = await app.request("/dns-query/v6/ecs", {
      method: "POST",
      headers: {
        ...acceptMessage,
        "content-type": "application/dns-message",
        "x-vercel-forwarded-for": "8.8.8.8",
      },
      body: query,
    });
    expect(res.status).toBe(200);
    expect(dispatcherOf(0)).toBe(getDispatcher("v6"));
    const sent = vi.mocked(fetch).mock.calls[0]![1] as RequestInit;
    expect(ecsStatus(sent.body as Uint8Array)).toBe("positive");
  });

  it("rejects unknown path suffixes with 404", async () => {
    const app = makeApp();
    const query = buildQuery();
    const res = await app.request(`/dns-query/foo/bar?dns=${encodeBase64Url(query)}`, { headers: acceptMessage });
    expect(res.status).toBe(404);
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });
});

describe("DOH_PATH obfuscation", () => {
  it("serves DoH at the custom path", async () => {
    const app = makeApp({ DOH_PATH: "/x9k2" });
    const query = buildQuery();
    vi.mocked(fetch).mockResolvedValue(validUpstream(query, { ttl: 60 }));

    const res = await app.request(`/x9k2?dns=${encodeBase64Url(query)}`, { headers: acceptMessage });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/dns-message");
    const calledUrl = String(vi.mocked(fetch).mock.calls[0]![0]);
    expect(calledUrl).toContain("?dns=");
  });

  it("returns 404 for the standard /dns-query path when obfuscated", async () => {
    const app = makeApp({ DOH_PATH: "/x9k2" });
    const query = buildQuery();
    const res = await app.request(`/dns-query?dns=${encodeBase64Url(query)}`, { headers: acceptMessage });
    expect(res.status).toBe(404);
  });

  it("routes {base}/{provider} to the mapped upstream", async () => {
    const app = makeApp({
      DOH_PATH: "/x9k2",
      DOMAIN_MAPPINGS: JSON.stringify({ google: { targetDomain: "dns.google" } }),
    });
    const query = buildQuery();
    vi.mocked(fetch).mockResolvedValue(validUpstream(query, { ttl: 60 }));

    const res = await app.request(`/x9k2/google?dns=${encodeBase64Url(query)}`, { headers: acceptMessage });
    expect(res.status).toBe(200);
    const calledUrl = String(vi.mocked(fetch).mock.calls[0]![0]);
    expect(calledUrl.startsWith("https://dns.google/dns-query?dns=")).toBe(true);
  });

  it("supports /auto_ecs under the custom path", async () => {
    const app = makeApp({ DOH_PATH: "/x9k2" });
    const query = buildQuery();
    vi.mocked(fetch).mockResolvedValue(validUpstream(query, { ttl: 60 }));
    const res = await app.request("/x9k2/auto_ecs", {
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
    expect(ecsStatus(sent.body as Uint8Array)).toBe("positive");
  });
});
