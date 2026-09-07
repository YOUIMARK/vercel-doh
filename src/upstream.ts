// Upstream selection and query execution.
//
// Default mode (privacy-preserving): pick one upstream (round-robin) and, only
// on failure, fail over sequentially to the next one — never broadcasting the
// query to multiple resolvers at once.
//
// RACE_UPSTREAMS mode: query all upstreams concurrently and take the fastest
// successful response (latency over privacy).
//
// Trust boundary: everything about the upstream HTTP exchange — redirects,
// status codes, Content-Type, DNS validation and body reading — is resolved
// INSIDE this layer. The caller only ever receives a validated DNS payload.

import type { DoHConfig, Family } from "./config";
import { validateDnsResponse } from "./dns/validate";
import { debugLog } from "./log";
import { Agent } from "undici";
import { lookup as dnsLookup, type LookupAddress } from "node:dns";

export class UpstreamError extends Error {}

/** A validated, fully-read DNS response from an upstream. */
export interface UpstreamDnsResult {
  body: Uint8Array<ArrayBuffer>;
  status: number;
}

export interface UpstreamRequest {
  /** The exact URL to fetch (callers may rewrite it, e.g. append ?dns=). */
  url: string;
  init: RequestInit;
}

/** Round-robin cursor (per instance; serverless instances share nothing, which is fine). */
let cursor = 0;

// ── Address-family dispatchers (v4-only / v6-only upstream connections) ──
// A custom undici Agent with a family-filtered lookup replaces Node's default
// resolver for those requests. "auto" keeps the default (both families).

function familyLookup(family: 4 | 6) {
  return (
    hostname: string,
    options: { family?: number | "IPv4" | "IPv6"; hints?: number; all?: boolean; verbatim?: boolean },
    callback: (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void,
  ) => {
    dnsLookup(hostname, { ...options, family }, (err, address, fam) => callback(err, address, fam));
  };
}

const v4Agent = new Agent({ connect: { lookup: familyLookup(4) } });
const v6Agent = new Agent({ connect: { lookup: familyLookup(6) } });

/** Returns the undici dispatcher for a family preference, or undefined for auto. */
export function getDispatcher(family: Family): Agent | undefined {
  if (family === "v4") return v4Agent;
  if (family === "v6") return v6Agent;
  return undefined;
}

/** Resolves a path-mapped provider to an upstream URL, or null. */
export function resolveProvider(config: DoHConfig, provider: string): string | null {
  if (!Object.hasOwn(config.domainMappings, provider)) return null;
  const target = config.domainMappings[provider]!.targetDomain;
  const withScheme = target.includes("://") ? target : `https://${target}`;
  const url = new URL(withScheme);
  if (url.protocol !== "https:") return null;
  if (url.pathname === "" || url.pathname === "/") url.pathname = "/dns-query";
  return url.href.replace(/\/$/, "");
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

/** Test helper: resets the round-robin cursor. */
export function resetCursor(): void {
  cursor = 0;
}

/**
 * Runs the configured strategy over `urls`. Resolves with the first validated
 * DNS response, rejects with UpstreamError when all attempts fail.
 */
export async function queryUpstreams(
  config: DoHConfig,
  urls: string[],
  buildRequest: (url: string, signal: AbortSignal) => UpstreamRequest,
  family: Family = "auto",
): Promise<UpstreamDnsResult> {
  if (urls.length === 0) throw new UpstreamError("no upstream configured");
  if (config.raceUpstreams && urls.length > 1) {
    return raceUpstreams(urls, buildRequest, config.upstreamTimeoutMs, family);
  }
  return sequentialFailover(config, urls, buildRequest, family);
}

/**
 * Performs one upstream request and returns a validated, fully-read response.
 * Rejects on: network error/timeout, redirect, non-2xx status, wrong
 * Content-Type, or structurally invalid DNS payload — all treated as failures
 * that trigger failover.
 */
async function fetchValidated(
  url: string,
  buildRequest: (url: string, signal: AbortSignal) => UpstreamRequest,
  signal: AbortSignal,
  family: Family,
): Promise<UpstreamDnsResult> {
  const { url: fetchUrl, init } = buildRequest(url, signal);
  const dispatcher = getDispatcher(family);
  const res = await fetch(fetchUrl, {
    ...init,
    redirect: "error", // SSRF: never follow redirects
    // undici Agent vs Node's bundled undici-types: same object, distinct type
    // worlds — the runtime contract is identical, so cast explicitly.
    ...(dispatcher ? { dispatcher: dispatcher as unknown as never } : {}),
  });
  if (!res.ok) throw new UpstreamError(`upstream ${fetchUrl} -> ${res.status}`);
  const contentType = (res.headers.get("content-type") ?? "").toLowerCase();
  if (!contentType.includes("application/dns-message")) {
    throw new UpstreamError(`upstream ${fetchUrl} -> unexpected content-type ${contentType}`);
  }
  const body = new Uint8Array(await res.arrayBuffer());
  if (!validateDnsResponse(body)) {
    throw new UpstreamError(`upstream ${fetchUrl} -> invalid DNS response`);
  }
  return { body, status: res.status };
}

async function sequentialFailover(
  config: DoHConfig,
  urls: string[],
  buildRequest: (url: string, signal: AbortSignal) => UpstreamRequest,
  family: Family,
): Promise<UpstreamDnsResult> {
  const attempts = Math.min(config.maxAttempts, urls.length);
  const start = cursor % urls.length;
  cursor = (start + 1) % urls.length;

  for (let i = 0; i < attempts; i++) {
    const url = urls[(start + i) % urls.length] as string;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), config.upstreamTimeoutMs);
    try {
      const result = await fetchValidated(url, buildRequest, controller.signal, family);
      debugLog(`upstream ${url} -> ${result.status}`);
      return result;
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
  buildRequest: (url: string, signal: AbortSignal) => UpstreamRequest,
  timeoutMs: number,
  family: Family,
): Promise<UpstreamDnsResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    // Body is read (and validated) inside each attempt, so aborting the losers
    // after the winner resolves can never abort an unread winner body.
    const attempts = urls.map(async (url) => {
      const result = await fetchValidated(url, buildRequest, controller.signal, family);
      debugLog(`race: ${url} -> ${result.status}`);
      return result;
    });
    return await Promise.any(attempts);
  } catch (err) {
    if (err instanceof AggregateError) {
      throw new UpstreamError("all upstreams failed (race)");
    }
    throw err;
  } finally {
    clearTimeout(timer);
    controller.abort(); // cancel the losers (winner body already consumed)
  }
}

/**
 * Builds the outbound header set for upstream requests — an ALLOWLIST, not a
 * denylist. Client headers (Authorization, Cookie, Accept-Language, arbitrary
 * X-*, ...) must never leak to the DNS resolver.
 */
export function buildUpstreamHeaders(
  accept: string,
  userAgent: string,
  contentType?: string,
): Headers {
  const out = new Headers();
  out.set("Accept", accept);
  out.set("User-Agent", userAgent);
  if (contentType) out.set("Content-Type", contentType);
  return out;
}
