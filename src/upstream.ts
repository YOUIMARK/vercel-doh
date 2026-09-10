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

import type { DoHConfig } from "./config.js";
import { parseMediaType } from "./media.js";
import { validateDnsResponse } from "./dns/validate.js";
import { debugLog } from "./log.js";

export class UpstreamError extends Error {}

/**
 * Error-safe URL for log messages: scheme/host/path only. The query string
 * (e.g. a DoH GET's `?dns=<base64url payload>`) and any userinfo are stripped
 * so debug logs never contain the DNS query content or credentials.
 */
export function redactUrl(url: string): string {
  try {
    const u = new URL(url);
    u.username = "";
    u.password = "";
    u.search = "";
    u.hash = "";
    return u.href.replace(/\/$/, "");
  } catch {
    return "(invalid url)";
  }
}

/** A validated, fully-read DNS response from an upstream. */
export interface UpstreamDnsResult {
  body: Uint8Array<ArrayBuffer>;
  status: number;
  /** Full RCODE (incl. EDNS extended-rcode bits), from the validated response. */
  rcode: number;
  /** Index of the winning upstream inside the `urls` array passed to queryUpstreams. */
  providerIndex: number;
}

export interface UpstreamRequest {
  /** The exact URL to fetch (callers may rewrite it, e.g. append ?dns=). */
  url: string;
  init: RequestInit;
}

/** Round-robin cursor (per instance; serverless instances share nothing, which is fine). */
let cursor = 0;

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
 * `requestMessage` is the exact message sent upstream (after ECS/QTYPE
 * modification); the winning response must echo its ID + question.
 */
export async function queryUpstreams(
  config: DoHConfig,
  urls: string[],
  buildRequest: (url: string, signal: AbortSignal) => UpstreamRequest,
  requestMessage: Uint8Array<ArrayBuffer>,
): Promise<UpstreamDnsResult> {
  if (urls.length === 0) throw new UpstreamError("no upstream configured");
  // Absolute wall-clock deadline for the whole resolution (all attempts).
  // Each attempt is bounded by min(UPSTREAM_TIMEOUT_MS, remaining) so the
  // worst-case latency is TOTAL_TIMEOUT_MS, not attempts × timeout.
  const deadlineMs = Date.now() + config.totalTimeoutMs;
  if (config.raceUpstreams && urls.length > 1) {
    return raceUpstreams(config, urls, buildRequest, requestMessage, deadlineMs);
  }
  return sequentialFailover(config, urls, buildRequest, requestMessage, deadlineMs);
}

/**
 * Performs one upstream request and returns a validated, fully-read response.
 * Rejects on: network error/timeout, redirect, non-2xx status, wrong
 * Content-Type, oversized body, or an invalid/mismatched DNS payload — all
 * treated as failures that trigger failover.
 */
async function fetchValidated(
  config: DoHConfig,
  url: string,
  buildRequest: (url: string, signal: AbortSignal) => UpstreamRequest,
  signal: AbortSignal,
  requestMessage: Uint8Array<ArrayBuffer>,
): Promise<Omit<UpstreamDnsResult, "providerIndex">> {
  const { url: fetchUrl, init } = buildRequest(url, signal);
  const logUrl = redactUrl(fetchUrl);
  const res = await fetch(fetchUrl, { ...init, redirect: "error" }); // SSRF: never follow redirects
  if (!res.ok) throw new UpstreamError(`upstream ${logUrl} -> ${res.status}`);
  const contentType = res.headers.get("content-type") ?? "";
  if (parseMediaType(contentType) !== "application/dns-message") {
    throw new UpstreamError(`upstream ${logUrl} -> unexpected content-type ${contentType}`);
  }
  // Reject oversized responses up front (Content-Length) and after reading.
  const contentLength = res.headers.get("content-length");
  if (contentLength !== null) {
    const n = Number.parseInt(contentLength, 10);
    if (!Number.isNaN(n) && n > config.maxBodyBytes) {
      throw new UpstreamError(`upstream ${logUrl} -> response too large (${n} bytes)`);
    }
  }
  const body = new Uint8Array(await res.arrayBuffer());
  if (body.length > config.maxBodyBytes) {
    throw new UpstreamError(`upstream ${logUrl} -> response too large (${body.length} bytes)`);
  }
  const validated = validateDnsResponse(body, requestMessage);
  if (!validated) {
    throw new UpstreamError(`upstream ${logUrl} -> invalid DNS response`);
  }
  return { body, status: res.status, rcode: validated.rcode };
}

async function sequentialFailover(
  config: DoHConfig,
  urls: string[],
  buildRequest: (url: string, signal: AbortSignal) => UpstreamRequest,
  requestMessage: Uint8Array<ArrayBuffer>,
  deadlineMs: number,
): Promise<UpstreamDnsResult> {
  const attempts = Math.min(config.maxAttempts, urls.length);
  const start = cursor % urls.length;
  cursor = (start + 1) % urls.length;

  for (let i = 0; i < attempts; i++) {
    const url = urls[(start + i) % urls.length] as string;
    const remaining = deadlineMs - Date.now();
    if (remaining <= 0) throw new UpstreamError("resolution deadline exceeded");
    const attemptTimeout = Math.max(50, Math.min(config.upstreamTimeoutMs, remaining));
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), attemptTimeout);
    try {
      const result = await fetchValidated(config, url, buildRequest, controller.signal, requestMessage);
      debugLog(`upstream ${url} -> ${result.status}`);
      return { ...result, providerIndex: (start + i) % urls.length };
    } catch (err) {
      debugLog(`upstream ${url} failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      clearTimeout(timer);
    }
  }
  throw new UpstreamError("all upstreams failed");
}

async function raceUpstreams(
  config: DoHConfig,
  urls: string[],
  buildRequest: (url: string, signal: AbortSignal) => UpstreamRequest,
  requestMessage: Uint8Array<ArrayBuffer>,
  deadlineMs: number,
): Promise<UpstreamDnsResult> {
  // All attempts start together; the shared timer is bounded by the total
  // deadline as well (min of per-upstream timeout and remaining budget).
  const remaining = Math.max(50, deadlineMs - Date.now());
  const raceTimeout = Math.min(config.upstreamTimeoutMs, remaining);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), raceTimeout);
  try {
    // Body is read (and validated) inside each attempt, so aborting the losers
    // after the winner resolves can never abort an unread winner body.
    const attempts = urls.map(async (url, i) => {
      const result = await fetchValidated(config, url, buildRequest, controller.signal, requestMessage);
      debugLog(`race: ${url} -> ${result.status}`);
      return { ...result, providerIndex: i };
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
