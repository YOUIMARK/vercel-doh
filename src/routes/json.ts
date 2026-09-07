// Google-style dns-json API (for the browser query tool).

import type { Context } from "hono";
import type { DoHConfig } from "../config";
import { corsHeaders, textError } from "../errors";
import { debugLog } from "../log";
import { buildUpstreamHeaders } from "../upstream";

const JSON_PARAMS = ["name", "type", "cd", "do", "edns_client_subnet"] as const;

export function handleJsonQuery(config: DoHConfig) {
  return async (c: Context): Promise<Response> => {
    if (c.req.method !== "GET") {
      return textError(405, "Method Not Allowed", corsHeaders());
    }
    const accept = c.req.header("accept") ?? "";
    const wantsJson =
      accept.includes("application/dns-json") || c.req.query("ct") === "application/dns-json";
    if (!wantsJson) return textError(406, "Not Acceptable: application/dns-json required", corsHeaders());

    const name = c.req.query("name");
    if (!name) return textError(400, "Missing name parameter", corsHeaders());

    const upstream = config.jsonUpstreamUrls[0];
    if (!upstream) return textError(500, "No JSON upstream configured", corsHeaders());

    const target = new URL(upstream);
    for (const key of JSON_PARAMS) {
      const value = c.req.query(key);
      if (value) target.searchParams.set(key, value);
    }

    const headers = buildUpstreamHeaders(c.req.raw.headers, "application/dns-json");
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), config.upstreamTimeoutMs);
    try {
      const res = await fetch(target.href, { method: "GET", headers, signal: controller.signal });
      const body = await res.arrayBuffer();
      const out = new Headers(corsHeaders());
      out.set("Content-Type", res.headers.get("content-type") ?? "application/json");
      out.set("Cache-Control", "public, s-maxage=300");
      debugLog(`dns-json ${name} -> ${res.status}`);
      return new Response(body, { status: res.status, headers: out });
    } catch {
      return textError(502, "Bad Gateway", corsHeaders());
    } finally {
      clearTimeout(timer);
    }
  };
}
