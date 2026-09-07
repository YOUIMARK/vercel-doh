// The core RFC 8484 DoH handler (GET + POST).

import type { Context } from "hono";
import type { DoHConfig, Family } from "../config.js";
import { buildCacheControl } from "../cache-control.js";
import { corsHeaders, servfailResponse, textError } from "../errors.js";
import { debugLog } from "../log.js";
import { addOrMergeEcs, buildEcsOption, ecsStatus, parseClientIp } from "../dns/ecs.js";
import { padResponse } from "../dns/padding.js";
import { minAnswerTtl, soaNegativeTtl } from "../dns/ttl.js";
import { countOptRrs, decodeBase64Url, encodeBase64Url, parseHeader, parseSections, questionType, rcodeOf, setQuestionType } from "../dns/wire.js";
import { buildUpstreamHeaders, queryUpstreams, resolveProvider, UpstreamError } from "../upstream.js";
import { handleJsonQuery } from "./json.js";

export const DNS_MESSAGE = "application/dns-message";

export type EcsBehavior = "default" | "force_enable" | "force_disable";

const INVALID_PATH = "__invalid__";

/**
 * URL flags parsed from path suffixes after the base path, e.g.
 *   {base}/v4          → IPv4-only upstream connection
 *   {base}/v6          → IPv6-only upstream connection
 *   {base}/ecs         → force ECS on (alias: /auto_ecs)
 *   {base}/no-ecs      → force ECS off (alias: /no_ecs)
 *   {base}/{provider}  → provider routing
 * Flags are combinable in any order: {base}/v4/ecs, {base}/ecs/v6/...
 * URL flags override environment defaults per request.
 */
export interface PathFlags {
  family: Family | null;
  behavior: EcsBehavior | null;
  provider: string | null;
}

const ECS_FLAGS = new Map<string, EcsBehavior>([
  ["ecs", "force_enable"],
  ["auto_ecs", "force_enable"],
  ["no-ecs", "force_disable"],
  ["no_ecs", "force_disable"],
]);

export function parsePathFlags(pathname: string, basePath: string): PathFlags {
  const base = basePath.replace(/\/+$/, "");
  if (pathname === base) return { family: null, behavior: null, provider: null };
  if (!pathname.startsWith(`${base}/`)) return { family: null, behavior: null, provider: null };
  const segments = pathname.slice(base.length + 1).split("/").filter((s) => s.length > 0);
  const flags: PathFlags = { family: null, behavior: null, provider: null };
  for (const segment of segments) {
    if (segment === "v4") flags.family = "v4";
    else if (segment === "v6") flags.family = "v6";
    else if (ECS_FLAGS.has(segment)) flags.behavior = ECS_FLAGS.get(segment)!;
    else if (flags.provider === null) flags.provider = segment;
    else flags.provider = INVALID_PATH; // more than one unknown segment
  }
  return flags;
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

    // Media-type negotiation: RFC 8484 says clients SHOULD send Accept, not
    // MUST. Absent or `*/*` Accept headers are treated as accepting
    // application/dns-message.
    const accept = (c.req.header("accept") ?? "").trim();
    const wantsJson =
      accept.includes("application/dns-json") || c.req.query("ct") === "application/dns-json";
    const acceptsMessage =
      accept === "" || accept === "*/*" || accept.includes(DNS_MESSAGE) || accept.includes("application/*");

    // Browser-style GET with no dns param → JSON query (name param), explain
    // the endpoint, or serve the JSON tool.
    if (method === "GET" && !c.req.query("dns")) {
      // A `name` param makes this a dns-json query (dns.google/resolve style),
      // regardless of the Accept header the tool sends.
      if (c.req.query("name") || wantsJson) {
        const flags = parsePathFlags(c.req.path, config.dohPath);
        return handleJsonQuery(config, {
          family: flags.family,
          ecs:
            flags.behavior === "force_enable"
              ? true
              : flags.behavior === "force_disable"
                ? false
                : null,
        })(c);
      }
      if (acceptsMessage) return textError(400, "Missing dns parameter", corsHeaders());
      return infoText(config);
    }

    if (method === "GET" && !acceptsMessage) {
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

    // ── Query validation (protocol gate before touching any upstream) ──
    const queryHeader = parseHeader(message);
    if (!queryHeader || queryHeader.qd !== 1) {
      return textError(400, "Invalid DNS query (exactly one question required)", corsHeaders());
    }
    if (parseSections(message) === null) {
      return textError(400, "Malformed DNS query", corsHeaders());
    }
    if (countOptRrs(message) > 1) {
      return textError(400, "Malformed DNS query (multiple OPT RRs)", corsHeaders());
    }
    const ecs = ecsStatus(message);
    if (ecs === "malformed") {
      return textError(400, "Malformed EDNS/ECS option", corsHeaders());
    }

    // ── ECS handling (privacy: only when explicitly enabled) ──
    // ECS with source prefix 0 is a client's explicit "do not disclose my
    // address" signal — never inject the real subnet over it.
    const flags = parsePathFlags(c.req.path, config.dohPath);
    if (flags.provider === INVALID_PATH) {
      return textError(404, "Unknown path", corsHeaders());
    }
    // URL flags override the route's registered behavior and env defaults.
    const effectiveBehavior = flags.behavior ?? behavior;
    const family = flags.family ?? config.upstreamFamily;

    const incomingEcs = ecs !== "absent";
    const shouldAddEcs =
      effectiveBehavior === "force_enable" ||
      (effectiveBehavior === "default" && config.autoAddEcs);
    let ecsAdded = false;
    if (shouldAddEcs && ecs === "absent") {
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

    // ── Answer-family flag: force the question type to A (v4) / AAAA (v6) ──
    // Only rewrites address-type queries (A / AAAA / ANY); other types (MX…)
    // pass through unchanged.
    if (family !== "auto") {
      const current = questionType(message);
      if (current === 1 || current === 28 || current === 255) {
        const rewritten = setQuestionType(message, family === "v4" ? 1 : 28);
        if (rewritten) message = rewritten;
      }
    }

    // ── Upstream selection ──
    const ecsSensitive = incomingEcs || ecsAdded;
    let upstreamList =
      ecsSensitive && config.ecsUpstreamUrls.length > 0
        ? config.ecsUpstreamUrls
        : config.upstreamUrls;
    const provider = flags.provider;
    if (provider) {
      const mapped = resolveProvider(config, provider);
      if (!mapped) return textError(404, `Unknown provider: ${provider}`, corsHeaders());
      upstreamList = [mapped];
    }

    const upstreamHeaders = buildUpstreamHeaders(
      DNS_MESSAGE,
      `vercel-doh/${config.appVersion}`,
      method === "POST" ? DNS_MESSAGE : undefined,
    );
    const encoded = encodeBase64Url(message);

    try {
      // queryUpstreams resolves only with a validated, fully-read DNS payload.
      const result = await queryUpstreams(config, upstreamList, (url, signal) => {
        if (method === "POST") {
          return { url, init: { method: "POST", headers: upstreamHeaders, body: message, signal } };
        }
        const target = new URL(url);
        target.searchParams.set("dns", encoded);
        return { url: target.href, init: { method: "GET", headers: upstreamHeaders, signal } };
      });

      const upstreamBody = result.body;
      const resHeader = parseHeader(upstreamBody)!; // validated in upstream layer
      const rcode = rcodeOf(resHeader.flags);

      let finalBody = upstreamBody;
      if (config.forceResponsePadding) finalBody = padResponse(upstreamBody);

      const cacheControl = buildCacheControl({
        method,
        validResponse: true,
        rcode,
        ecsSensitive,
        minAnswerTtl: minAnswerTtl(upstreamBody),
        negativeTtl: soaNegativeTtl(upstreamBody),
        cacheMaxAge: config.cacheMaxAge,
      });

      const headers = new Headers(corsHeaders());
      headers.set("Content-Type", DNS_MESSAGE);
      headers.set("Cache-Control", cacheControl);
      headers.set("Content-Length", String(finalBody.length));
      debugLog(`dns-query ${method} rcode=${rcode} cache=${cacheControl}`);
      return new Response(finalBody, { status: 200, headers });
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
  const base = config.dohPath;
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>vercel-doh</title>
<style>body{font-family:system-ui,sans-serif;max-width:52rem;margin:3rem auto;padding:0 1rem;line-height:1.6}code{background:#f0f0f0;padding:.1rem .35rem;border-radius:4px}</style>
</head>
<body>
<h1>vercel-doh</h1>
<p>v${config.appVersion} — DNS over HTTPS 转发代理(部署于 Vercel,Hono + Node.js + Fluid compute)。</p>
<p>这是一个 <b>DoH 端点</b>,请用支持 DoH 的客户端访问,而不是浏览器:</p>
<pre>  GET  ${base}?dns=&lt;base64url&gt;        (Accept: application/dns-message)
  POST ${base}                          (Content-Type: application/dns-message)</pre>
<ul>
<li><code>${base}</code> — 标准端点(默认不附加 ECS)</li>
<li><code>${base}/v4</code> — 仅用 IPv4 连接上游; <code>${base}/v6</code> — 仅用 IPv6</li>
<li><code>${base}/ecs</code> — 强制附加 EDNS Client Subnet; <code>${base}/no-ecs</code> — 强制禁用</li>
<li><code>${base}/{provider}</code> — 按 <code>DOMAIN_MAPPINGS</code> 路由指定上游(可与上面的 flag 组合,如 <code>${base}/v4/ecs</code>)</li>
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
