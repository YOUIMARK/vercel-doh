// Google-style dns-json API (for the browser query tool).
// Same trust boundary as the dns-message path: only 2xx JSON responses with
// the right Content-Type are accepted; attempts fail over sequentially.

import type { Context } from "hono";
import type { DoHConfig } from "../config";
import { corsHeaders, textError } from "../errors";
import { debugLog } from "../log";
import { getDispatcher, UpstreamError } from "../upstream";

const JSON_PARAMS = ["name", "type", "cd", "do", "edns_client_subnet"] as const;
const JSON_MIME = "application/dns-json";

export function handleJsonQuery(config: DoHConfig) {
  return async (c: Context): Promise<Response> => {
    if (c.req.method !== "GET") {
      return textError(405, "Method Not Allowed", corsHeaders());
    }
    const accept = c.req.header("accept") ?? "";
    const wantsJson =
      accept.includes(JSON_MIME) || c.req.query("ct") === JSON_MIME;
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
    const ecsSensitive = c.req.query("edns_client_subnet") !== undefined;

    const headers = new Headers();
    headers.set("Accept", JSON_MIME);
    headers.set("User-Agent", `vercel-doh/${config.appVersion}`);

    try {
      const body = await fetchJsonWithFailover(config, upstreams, params, headers);
      const out = new Headers(corsHeaders());
      out.set("Content-Type", "application/json");
      out.set("Cache-Control", ecsSensitive ? "no-store" : "public, s-maxage=300");
      debugLog(`dns-json ${name} -> ok`);
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
  const dispatcher = getDispatcher(config.upstreamFamily);
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
        // undici Agent vs Node's bundled undici-types: same object, distinct
        // type worlds — the runtime contract is identical, so cast explicitly.
        ...(dispatcher ? { dispatcher: dispatcher as unknown as never } : {}),
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
