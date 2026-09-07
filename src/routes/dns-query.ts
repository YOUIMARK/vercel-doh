// The core RFC 8484 DoH handler (GET + POST).

import type { Context } from "hono";
import type { DoHConfig } from "../config";
import { buildCacheControl } from "../cache-control";
import { corsHeaders, servfailResponse, textError } from "../errors";
import { debugLog } from "../log";
import {
  addOrMergeEcs,
  buildEcsOption,
  hasMeaningfulEcs,
  parseClientIp,
} from "../dns/ecs";
import { padResponse } from "../dns/padding";
import { minTtl } from "../dns/ttl";
import {
  decodeBase64Url,
  encodeBase64Url,
  parseHeader,
  rcodeOf,
} from "../dns/wire";
import { buildUpstreamHeaders, queryUpstreams, resolveProvider, UpstreamError } from "../upstream";
import { handleJsonQuery } from "./json";

export const DNS_MESSAGE = "application/dns-message";

export type EcsBehavior = "default" | "force_enable" | "force_disable";

/** Extracts the optional provider segment from paths like /dns-query/{provider}. */
export function providerFromPath(pathname: string): string | null {
  const segments = pathname.split("/").filter((s) => s.length > 0);
  if (segments.length >= 2 && segments[0] === "dns-query") {
    const provider = segments[1];
    if (provider && provider !== "auto_ecs" && provider !== "no_ecs") return provider;
  }
  return null;
}

export function handleDnsQuery(config: DoHConfig, behavior: EcsBehavior) {
  return async (c: Context): Promise<Response> => {
    const method = c.req.method;

    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }
    if (method !== "GET" && method !== "POST") {
      return textError(405, "Method Not Allowed: only GET/POST supported", corsHeaders());
    }

    const accept = c.req.header("accept") ?? "";
    const wantsMessage = accept.includes(DNS_MESSAGE);

    // Browser-style GET with no dns param and no DoH accept → explain the endpoint.
    if (method === "GET" && !c.req.query("dns")) {
      const wantsJson = accept.includes("application/dns-json") || c.req.query("ct") === "application/dns-json";
      if (wantsJson) return handleJsonQuery(config)(c);
      if (!wantsMessage) return infoText(config);
      return textError(400, "Missing dns parameter", corsHeaders());
    }

    if (method === "GET" && !wantsMessage) {
      return textError(406, "Not Acceptable: application/dns-message required", corsHeaders());
    }

    let message: Uint8Array<ArrayBuffer>;
    if (method === "POST") {
      const contentType = (c.req.header("content-type") ?? "").toLowerCase();
      if (!contentType.startsWith(DNS_MESSAGE)) {
        return textError(415, "Unsupported Media Type: application/dns-message required", corsHeaders());
      }
      const buf = await c.req.arrayBuffer();
      message = new Uint8Array(buf);
    } else {
      const dnsParam = c.req.query("dns") ?? "";
      const decoded = decodeBase64Url(dnsParam);
      if (!decoded) return textError(400, "Invalid dns parameter (base64url)", corsHeaders());
      message = decoded;
    }

    if (message.length === 0) return textError(400, "Empty DNS message", corsHeaders());
    if (message.length > config.maxBodyBytes) {
      return textError(413, "Payload Too Large", corsHeaders());
    }

    // ── ECS handling (privacy: only when explicitly enabled) ──
    const hasEcsInitially = hasMeaningfulEcs(message);
    const shouldAddEcs =
      behavior === "force_enable" || (behavior === "default" && config.autoAddEcs);
    let ecsAdded = false;
    if (shouldAddEcs && !hasEcsInitially) {
      const clientIp = parseClientIp(c.req.raw.headers);
      if (clientIp) {
        const prefix =
          clientIp.family === 1 ? config.ipv4EcsPrefixLength : config.ipv6EcsPrefixLength;
        const merged = addOrMergeEcs(message, buildEcsOption(clientIp, prefix));
        if (merged !== message) {
          message = merged;
          ecsAdded = true;
        }
      }
    }

    // ── Upstream selection ──
    const hasEcs = hasEcsInitially || ecsAdded;
    let upstreamList =
      hasEcs && config.ecsUpstreamUrls.length > 0 ? config.ecsUpstreamUrls : config.upstreamUrls;
    const provider = providerFromPath(c.req.path);
    if (provider) {
      const mapped = resolveProvider(config, provider);
      if (!mapped) return textError(404, `Unknown provider: ${provider}`, corsHeaders());
      upstreamList = [mapped];
    }

    const upstreamHeaders = buildUpstreamHeaders(c.req.raw.headers, DNS_MESSAGE);
    const encoded = encodeBase64Url(message);

    try {
      const res = await queryUpstreams(config, upstreamList, (url, signal) => {
        if (method === "POST") {
          return { url, init: { method: "POST", headers: upstreamHeaders, body: message, signal } };
        }
        const target = new URL(url);
        target.searchParams.set("dns", encoded);
        return { url: target.href, init: { method: "GET", headers: upstreamHeaders, signal } };
      });

      const upstreamBody = new Uint8Array(await res.arrayBuffer());
      const header = parseHeader(upstreamBody);
      const rcode = header ? rcodeOf(header.flags) : -1;
      const ttl = minTtl(upstreamBody);

      let finalBody = upstreamBody;
      if (config.forceResponsePadding) finalBody = padResponse(upstreamBody);

      const cacheControl = buildCacheControl({
        method,
        rcode,
        ecsAdded,
        minTtl: ttl,
        cacheMaxAge: config.cacheMaxAge,
      });

      const headers = new Headers(corsHeaders());
      headers.set("Content-Type", DNS_MESSAGE);
      headers.set("Cache-Control", cacheControl);
      headers.set("Content-Length", String(finalBody.length));
      debugLog(`dns-query ${method} rcode=${rcode} ttl=${ttl} cache=${cacheControl}`);
      return new Response(finalBody, { status: res.status, headers });
    } catch (err) {
      if (err instanceof UpstreamError) {
        debugLog("all upstreams failed");
        return servfailResponse(message, corsHeaders());
      }
      debugLog(`dns-query error: ${err instanceof Error ? err.message : String(err)}`);
      return textError(502, "Bad Gateway", corsHeaders());
    }
  };
}

function infoText(config: DoHConfig): Response {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>vercel-doh</title>
<style>body{font-family:system-ui,sans-serif;max-width:52rem;margin:3rem auto;padding:0 1rem;line-height:1.6}code{background:#f0f0f0;padding:.1rem .35rem;border-radius:4px}</style>
</head>
<body>
<h1>vercel-doh</h1>
<p>v${config.appVersion} — DNS over HTTPS 转发代理(部署于 Vercel,Hono + Node.js + Fluid compute)。</p>
<p>这是一个 <b>DoH 端点</b>,请用支持 DoH 的客户端访问,而不是浏览器:</p>
<pre>  GET  /dns-query?dns=&lt;base64url&gt;        (Accept: application/dns-message)
  POST /dns-query                          (Content-Type: application/dns-message)</pre>
<ul>
<li><code>/dns-query</code> — 标准端点(默认不附加 ECS)</li>
<li><code>/dns-query/auto_ecs</code> — 强制为请求附加 EDNS Client Subnet</li>
<li><code>/dns-query/no_ecs</code> — 强制禁用 ECS</li>
<li><code>/dns-query-json</code> — dns-json API(浏览器查询工具)</li>
<li><code>/health</code> — 健康检查</li>
</ul>
<p>上游: ${config.upstreamUrls.join(", ")}</p>
</body>
</html>`;
  return new Response(html, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "public, s-maxage=60",
    },
  });
}
