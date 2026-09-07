// Upstream selection and query execution.
//
// Default mode (privacy-preserving): pick one upstream (round-robin) and, only
// on network failure / timeout / 5xx, fail over sequentially to the next one —
// never broadcasting the query to multiple resolvers at once.
//
// RACE_UPSTREAMS mode: query all upstreams concurrently and take the fastest
// successful response (latency over privacy).

import type { DoHConfig } from "./config";
import { debugLog } from "./log";

const HOP_BY_HOP = new Set([
  "host",
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailers",
  "transfer-encoding",
  "upgrade",
  "content-length",
]);

/** Headers we must never forward upstream: they reveal the client's IP. */
const PRIVACY_STRIPPED = new Set(["x-forwarded-for", "x-real-ip", "x-vercel-forwarded-for"]);

export class UpstreamError extends Error {}

/** Round-robin cursor (per instance; serverless instances share nothing, which is fine). */
let cursor = 0;

/** Resolves a path-mapped provider to an upstream URL, or null. */
export function resolveProvider(config: DoHConfig, provider: string): string | null {
  const mapping = config.domainMappings[provider];
  if (!mapping) return null;
  const target = mapping.targetDomain;
  const withScheme = target.includes("://") ? target : `https://${target}`;
  const url = new URL(withScheme);
  if (url.pathname === "" || url.pathname === "/") url.pathname = "/dns-query";
  return url.href.replace(/\/$/, "");
}

/** Test helper: resets the round-robin cursor. */
export function resetCursor(): void {
  cursor = 0;
}

/** Picks the next upstream URL: provider mapping first, else round-robin. */
export function pickUpstream(config: DoHConfig, provider: string | null): string | null {
  if (provider) {
    const mapped = resolveProvider(config, provider);
    if (mapped) return mapped;
  }
  const list = config.upstreamUrls;
  if (list.length === 0) return null;
  const idx = cursor % list.length;
  cursor = (idx + 1) % list.length;
  return list[idx] as string;
}

export interface UpstreamRequest {
  /** The exact URL to fetch (callers may rewrite it, e.g. append ?dns=). */
  url: string;
  init: RequestInit;
}

/**
 * Runs the configured strategy over `urls` (starting at the round-robin cursor).
 * Resolves with the first usable Response. Rejects with UpstreamError when all fail.
 * A response with status >= 500 is treated as an upstream failure and failed over;
 * 4xx responses are returned as-is (they reflect a client error, not our problem).
 */
export async function queryUpstreams(
  config: DoHConfig,
  urls: string[],
  init: (url: string, signal: AbortSignal) => UpstreamRequest,
): Promise<Response> {
  if (urls.length === 0) throw new UpstreamError("no upstream configured");
  if (config.raceUpstreams && urls.length > 1) {
    return raceUpstreams(urls, init, config.upstreamTimeoutMs);
  }
  return sequentialFailover(config, urls, init);
}

async function sequentialFailover(
  config: DoHConfig,
  urls: string[],
  init: (url: string, signal: AbortSignal) => UpstreamRequest,
): Promise<Response> {
  const attempts = Math.min(config.maxAttempts, urls.length);
  const start = cursor % urls.length;
  cursor = (start + 1) % urls.length;

  for (let i = 0; i < attempts; i++) {
    const url = urls[(start + i) % urls.length] as string;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), config.upstreamTimeoutMs);
    try {
      const { url: fetchUrl, init: requestInit } = init(url, controller.signal);
      const res = await fetch(fetchUrl, requestInit);
      if (res.status >= 500) {
        debugLog(`upstream ${fetchUrl} -> ${res.status}, failing over`);
        res.body?.cancel().catch(() => {});
        continue;
      }
      debugLog(`upstream ${fetchUrl} -> ${res.status}`);
      return res;
    } catch (err) {
      debugLog(`upstream ${url} failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      clearTimeout(timer);
    }
  }
  throw new UpstreamError("all upstreams failed");
}

async function raceUpstreams(
  urls: string[],
  init: (url: string, signal: AbortSignal) => UpstreamRequest,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const attempts = urls.map(async (url) => {
      const { url: fetchUrl, init: requestInit } = init(url, controller.signal);
      const res = await fetch(fetchUrl, requestInit);
      if (res.status >= 500) throw new UpstreamError(`upstream ${fetchUrl} -> ${res.status}`);
      debugLog(`race: ${fetchUrl} -> ${res.status}`);
      return res;
    });
    return await Promise.any(attempts);
  } catch (err) {
    if (err instanceof AggregateError) {
      throw new UpstreamError("all upstreams failed (race)");
    }
    throw err;
  } finally {
    clearTimeout(timer);
    controller.abort(); // cancel the losers
  }
}

/** Copies incoming headers minus hop-by-hop and privacy headers, forcing a DoH Accept. */
export function buildUpstreamHeaders(incoming: Headers, accept: string): Headers {
  const out = new Headers();
  incoming.forEach((value, key) => {
    const lower = key.toLowerCase();
    if (HOP_BY_HOP.has(lower) || PRIVACY_STRIPPED.has(lower)) return;
    out.set(key, value);
  });
  out.set("Accept", accept);
  out.delete("accept-encoding"); // let undici negotiate gzip/br itself
  return out;
}
