// Google-style dns-json API (for the browser query tool).
// Same trust boundary as the dns-message path: only 2xx JSON responses with
// the right Content-Type are accepted; attempts fail over sequentially.
//
// URL flags (path suffixes, URL overrides env):
//   /dns-query-json/v4        → IPv4-only upstream connection
//   /dns-query-json/v6        → IPv6-only upstream connection
//   /dns-query-json/ecs       → inject edns_client_subnet from the client IP
//   /dns-query-json/no-ecs    → strip any edns_client_subnet (privacy)
//   combinable: /dns-query-json/v4/ecs

import type { Context } from "hono";
import type { DoHConfig, Family } from "../config.js";
import { corsHeaders, textError } from "../errors.js";
import { parseClientIp } from "../dns/ecs.js";
import { formatEcsPrefix } from "../dns/ip.js";
import { debugLog } from "../log.js";
import { UpstreamError } from "../upstream.js";

const JSON_PARAMS = ["name", "type", "cd", "do", "edns_client_subnet"] as const;
const JSON_MIME = "application/dns-json";
const JSON_BASE = "/dns-query-json";
const INVALID = "__invalid__";

interface JsonFlags {
  family: Family | null;
  ecs: boolean | null; // true = force on, false = force off
}

function parseJsonFlags(pathname: string): JsonFlags {
  if (!pathname.startsWith(`${JSON_BASE}/`)) return { family: null, ecs: null };
  const segments = pathname.slice(JSON_BASE.length + 1).split("/").filter((s) => s.length > 0);
  const flags: JsonFlags = { family: null, ecs: null };
  for (const segment of segments) {
    if (segment === "v4") flags.family = "v4";
    else if (segment === "v6") flags.family = "v6";
    else if (segment === "ecs" || segment === "auto_ecs") flags.ecs = true;
    else if (segment === "no-ecs" || segment === "no_ecs") flags.ecs = false;
    else flags.family = INVALID as Family;
  }
  return flags;
}

export function handleJsonQuery(config: DoHConfig, baseFlags?: JsonFlags) {
  return async (c: Context): Promise<Response> => {
    if (c.req.method !== "GET") {
      return textError(405, "Method Not Allowed", corsHeaders());
    }
    const flags = parseJsonFlags(c.req.path);
    if (flags.family === (INVALID as Family)) {
      return textError(404, "Unknown path", corsHeaders());
    }
    // Base-path flags (e.g. /youimark/v6/ecs dispatched from the DoH base)
    // apply when no /dns-query-json/{flag} suffix is present.
    const family = flags.family ?? baseFlags?.family ?? config.upstreamFamily;
    const ecsFlag = flags.ecs ?? baseFlags?.ecs ?? null;

    const accept = c.req.header("accept") ?? "";
    // Lenient negotiation: absent / */* / application/json all accept dns-json
    // (a request carrying `name` is a JSON query regardless of what Accept
    // third-party tools happen to send — RFC 8484 says SHOULD, not MUST).
    const wantsJson =
      accept === "" ||
      accept === "*/*" ||
      accept.includes(JSON_MIME) ||
      accept.includes("application/json") ||
      c.req.query("ct") === JSON_MIME;
    if (!wantsJson) return textError(406, "Not Acceptable: application/dns-json required", corsHeaders());

    const name = c.req.query("name");
    if (!name) return textError(400, "Missing name parameter", corsHeaders());

    const upstreams = config.jsonUpstreamUrls;
    if (upstreams.length === 0) return textError(500, "No JSON upstream configured", corsHeaders());

    const params = new URLSearchParams();
    for (const key of JSON_PARAMS) {
      const value = c.req.query(key);
      if (value) params.set(key, value);
    }

    // ── ECS flag: inject the client subnet (proxy knows the client IP) ──
    if (ecsFlag === true) {
      const clientIp = parseClientIp(c.req.raw.headers);
      if (clientIp) {
        const prefix =
          clientIp.family === 1 ? config.ipv4EcsPrefixLength : config.ipv6EcsPrefixLength;
        params.set("edns_client_subnet", formatEcsPrefix(clientIp, prefix));
      }
    } else if (ecsFlag === false) {
      params.delete("edns_client_subnet"); // privacy: never leak the subnet
    }
    const ecsSensitive = params.has("edns_client_subnet");

    // ── Answer-family flag: force type=A (v4) / type=AAAA (v6) ──
    if (family !== "auto") {
      const current = (params.get("type") ?? "").toUpperCase();
      const target = family === "v4" ? "A" : "AAAA";
      if (current === "" || current === "A" || current === "AAAA" || current === "ANY") {
        params.set("type", target);
      }
    }

    const headers = new Headers();
    headers.set("Accept", JSON_MIME);
    headers.set("User-Agent", `vercel-doh/${config.appVersion}`);

    try {
      const body = await fetchJsonWithFailover(config, upstreams, params, headers);
      const out = new Headers(corsHeaders());
      out.set("Content-Type", "application/json");
      out.set("Cache-Control", ecsSensitive ? "no-store" : "public, s-maxage=300");
      debugLog(`dns-json ${name} -> ok (family=${family} ecs=${ecsSensitive})`);
      return new Response(body, { status: 200, headers: out });
    } catch (err) {
      if (err instanceof UpstreamError) {
        debugLog(`dns-json all upstreams failed: ${err.message}`);
      } else {
        debugLog(`dns-json error: ${err instanceof Error ? err.message : String(err)}`);
      }
      return textError(502, "Bad Gateway", corsHeaders());
    }
  };
}

async function fetchJsonWithFailover(
  config: DoHConfig,
  upstreams: string[],
  params: URLSearchParams,
  headers: Headers,
): Promise<Uint8Array<ArrayBuffer>> {
  const attempts = Math.min(config.maxAttempts, upstreams.length);
  let lastError: Error | null = null;
  for (let i = 0; i < attempts; i++) {
    const upstream = upstreams[i] as string;
    const target = new URL(upstream);
    target.search = params.toString();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), config.upstreamTimeoutMs);
    try {
      const res = await fetch(target.href, {
        method: "GET",
        headers,
        signal: controller.signal,
        redirect: "error", // SSRF: never follow redirects
      });
      if (!res.ok) throw new UpstreamError(`upstream ${target.href} -> ${res.status}`);
      const contentType = (res.headers.get("content-type") ?? "").toLowerCase();
      if (!contentType.includes("json")) {
        throw new UpstreamError(`upstream ${target.href} -> unexpected content-type ${contentType}`);
      }
      return new Uint8Array(await res.arrayBuffer());
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
    } finally {
      clearTimeout(timer);
    }
  }
  throw lastError instanceof UpstreamError ? lastError : new UpstreamError("all JSON upstreams failed");
}
