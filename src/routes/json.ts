// Google-style dns-json API (for the browser query tool), served ON the DoH
// base path: the dns-query dispatcher routes GET ?name= (and no ?dns=) here,
// dns.google/resolve style. One path serves both protocols; URL flags come
// from the shared base-path suffixes (parsed by the dispatcher, passed in as
// baseFlags): {base}/v4, {base}/v6, {base}/ecs, {base}/no-ecs, {base}/ecs-<ip>
// (combinable, e.g. {base}/v4/ecs-8.8.8.8).
//
// Same trust boundary as the dns-message path: only 2xx JSON responses with
// the right Content-Type that actually parse as the dns-json schema are
// accepted; malformed bodies fail over sequentially.

import type { Context } from "hono";
import type { DoHConfig, Family } from "../config.js";
import { corsHeaders, textError } from "../errors.js";
import { parseMediaType } from "../media.js";
import { parseClientIp } from "../dns/ecs.js";
import { formatEcsPrefix, parseCidr, parseIp } from "../dns/ip.js";
import { debugLog } from "../log.js";
import { discardBody, readStreamBounded } from "../read-body.js";
import { redactUrl, UpstreamError } from "../upstream.js";
import { ALLOWED_TYPES } from "./proxy.js";

const JSON_PARAMS = ["name", "type", "cd", "do", "edns_client_subnet"] as const;
const JSON_MIME = "application/dns-json";
/** RFC 1035 §2.3.4: a domain name is at most 253 characters of text. */
const MAX_DOMAIN_TEXT = 253;
/** Canonical boolean forms accepted for the cd/do dns-json flags. */
const BOOLEAN_FLAG = /^(0|1|true|false)$/i;
/** Text form of a domain name (letters, digits, dots, hyphen, underscore). */
const DOMAIN_CHARS = /^[a-zA-Z0-9._-]+$/;

/** Minimal dns-json schema (Google resolve style) after validation. */
interface JsonResponse {
  Status?: unknown;
  Question?: unknown;
  Answer?: unknown;
  Authority?: unknown;
  Additional?: unknown;
}

interface JsonFlags {
  family: Family | null;
  ecs: boolean | null; // true = force on, false = force off
  /** Fixed ECS source IP from the ecs-<ip> flag (null when unset). */
  ecsOverrideIp: string | null;
}

export function handleJsonQuery(config: DoHConfig, baseFlags?: JsonFlags) {
  return async (c: Context): Promise<Response> => {
    if (c.req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }
    if (c.req.method !== "GET") {
      return textError(405, "Method Not Allowed", corsHeaders());
    }
    // URL flags come from the shared DoH base-path suffixes (parsed by the
    // dns-query dispatcher); env defaults apply when no flag is present.
    const family = baseFlags?.family ?? config.upstreamFamily;
    const ecsFlag = baseFlags?.ecs ?? null;
    const ecsOverrideIp = baseFlags?.ecsOverrideIp ?? config.ecsOverrideIp;

    const name = c.req.query("name");
    if (!name) {
      return textError(400, "Missing name parameter", corsHeaders());
    }

    const upstreams = config.jsonUpstreamUrls;
    if (upstreams.length === 0) return textError(500, "No JSON upstream configured", corsHeaders());

    // ── Input validation before anything is forwarded upstream (abuse /
    //    amplification guard): bounded name, whitelisted type, canonical
    //    boolean flags, valid CIDR for edns_client_subnet.
    const rawType = c.req.query("type");
    const rawCidr = c.req.query("edns_client_subnet");
    const rawCd = c.req.query("cd");
    const rawDo = c.req.query("do");
    if (name.length > MAX_DOMAIN_TEXT || !DOMAIN_CHARS.test(name)) {
      return textError(400, "Invalid name parameter", corsHeaders());
    }
    if (rawType !== undefined && rawType !== "" && !ALLOWED_TYPES.has(rawType.toUpperCase())) {
      return textError(400, `unsupported type: ${rawType}`, corsHeaders());
    }
    if (rawCidr !== undefined && rawCidr !== "" && parseCidr(rawCidr) === null) {
      return textError(400, "Invalid edns_client_subnet (expected ip/prefix)", corsHeaders());
    }
    for (const flag of [rawCd, rawDo]) {
      if (flag !== undefined && flag !== "" && !BOOLEAN_FLAG.test(flag)) {
        return textError(400, "Invalid cd/do flag (expected 0|1|true|false)", corsHeaders());
      }
    }

    const params = new URLSearchParams();
    for (const key of JSON_PARAMS) {
      const value = c.req.query(key);
      if (value) params.set(key, value);
    }

    // ── ECS flag: inject the client subnet (proxy knows the client IP) ──
    // Source precedence: ecs-<ip> flag > ECS_OVERRIDE_IP env > real client IP.
    // When ECS is disabled (no-ecs) this block is skipped — override is inert.
    if (ecsFlag === true) {
      const sourceIp = ecsOverrideIp ? parseIp(ecsOverrideIp) : parseClientIp(c.req.raw.headers);
      if (sourceIp) {
        const prefix =
          sourceIp.family === 1 ? config.ipv4EcsPrefixLength : config.ipv6EcsPrefixLength;
        params.set("edns_client_subnet", formatEcsPrefix(sourceIp, prefix));
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
      const { data, providerIndex } = await fetchJsonWithFailover(config, upstreams, params, headers);
      const cacheControl = jsonCacheControl(config, data, ecsSensitive);
      const out = new Headers(corsHeaders());
      out.set("Content-Type", "application/json");
      out.set("Cache-Control", cacheControl);
      if (config.debugLogging) {
        out.set("X-DOH-upstream", String(providerIndex));
        out.set("X-DOH-cache", cacheControl);
      }
      debugLog(`dns-json ok (family=${family} ecs=${ecsSensitive} cache=${cacheControl})`);
      return new Response(JSON.stringify(data), { status: 200, headers: out });
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

/**
 * TTL-aware Cache-Control for dns-json responses, mirroring the dns-message
 * path: Status 0 with answers → min Answer TTL; NXDOMAIN/NODATA → RFC 2308
 * negative TTL `min(SOA TTL, SOA.MINIMUM)` derived from the SOA record's
 * `data` string (MNAME RNAME SERIAL REFRESH RETRY EXPIRE MINIMUM); anything
 * else or a negative answer WITHOUT a parseable SOA → no-store (RFC 2308 §5:
 * a negative response without SOA must not be cached — same rule as the
 * dns-message path). ECS-sensitive responses are never shared. No
 * `stale-while-revalidate`: a DNS TTL is a hard expiry. `config.ttlJitter`
 * (0..1) jitters the s-maxage DOWN only (min 1s) to spread CDN expiry; the
 * optional `rng` makes it deterministic in tests. Exported for unit tests.
 */
export function jsonCacheControl(
  config: DoHConfig,
  parsed: JsonResponse,
  ecsSensitive: boolean,
  rng: () => number = Math.random,
): string {
  if (ecsSensitive) return "no-store";
  const status = typeof parsed.Status === "number" ? parsed.Status : -1;
  if (status !== 0 && status !== 3) return "no-store";

  const answerTtl = minTtlOf(parsed.Answer);
  const negativeTtl = soaJsonNegativeTtl(parsed.Authority); // RFC 2308 only — no authority-TTL fallback
  let ttl: number | null = null;
  if (status === 0 && answerTtl !== null) ttl = answerTtl;
  else if (negativeTtl !== null) ttl = negativeTtl;
  if (ttl === null) return "no-store"; // no usable TTL (e.g. negative w/o SOA)

  const capped = Math.max(0, Math.min(ttl, config.cacheMaxAge));
  let effective = capped;
  if (config.ttlJitter > 0 && effective > 1) {
    effective = Math.max(1, Math.floor(effective * (1 - rng() * config.ttlJitter)));
  }
  return `public, s-maxage=${effective}`;
}

/**
 * RFC 2308 negative TTL from a dns-json SOA record: min(SOA TTL, SOA.MINIMUM).
 * The SOA `data` string is "MNAME RNAME SERIAL REFRESH RETRY EXPIRE MINIMUM"
 * (7 whitespace-separated fields). Returns null when no parseable SOA exists.
 */
function soaJsonNegativeTtl(authority: unknown): number | null {
  if (!Array.isArray(authority)) return null;
  for (const record of authority) {
    const rec = record as Record<string, unknown> | null;
    if (!rec || rec.type !== 6) continue; // SOA
    const ttl = rec.TTL;
    const data = rec.data;
    if (typeof ttl !== "number" || !Number.isFinite(ttl)) continue;
    if (typeof data !== "string") continue;
    const fields = data.trim().split(/\s+/);
    if (fields.length < 7) continue;
    const minimum = Number(fields[6]);
    if (!Number.isFinite(minimum) || minimum < 0) continue;
    return Math.min(ttl, minimum);
  }
  return null;
}

/** Minimum numeric TTL across a dns-json record array, or null. */
function minTtlOf(records: unknown): number | null {
  if (!Array.isArray(records)) return null;
  let min: number | null = null;
  for (const record of records) {
    const ttl = (record as Record<string, unknown> | null)?.TTL;
    if (typeof ttl === "number" && Number.isFinite(ttl)) {
      min = min === null ? ttl : Math.min(min, ttl);
    }
  }
  return min;
}

/**
 * Fetches one JSON upstream at a time with sequential failover. Only 2xx
 * responses whose Content-Type is exactly application/dns-json or
 * application/json AND whose body parses as the dns-json schema are accepted;
 * anything else throws UpstreamError and fails over. Bounded by
 * config.maxBodyBytes like the dns-message path, and by the total wall-clock
 * budget config.totalTimeoutMs (each attempt gets
 * `min(UPSTREAM_TIMEOUT_MS, remaining)`).
 */
async function fetchJsonWithFailover(
  config: DoHConfig,
  upstreams: string[],
  params: URLSearchParams,
  headers: Headers,
): Promise<{ data: JsonResponse; providerIndex: number }> {
  const attempts = Math.min(config.maxAttempts, upstreams.length);
  const deadlineMs = Date.now() + config.totalTimeoutMs;
  let lastError: Error | null = null;
  for (let i = 0; i < attempts; i++) {
    const remaining = deadlineMs - Date.now();
    if (remaining <= 0) break;
    const upstream = upstreams[i] as string;
    const target = new URL(upstream);
    target.search = params.toString();
    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      Math.max(50, Math.min(config.upstreamTimeoutMs, remaining)),
    );
    const logUrl = redactUrl(target.href);
    try {
      const res = await fetch(target.href, {
        method: "GET",
        headers,
        signal: controller.signal,
        redirect: "error", // SSRF: never follow redirects
      });
      if (!res.ok) {
        await discardBody(res);
        throw new UpstreamError(`upstream ${logUrl} -> ${res.status}`);
      }
      const contentType = res.headers.get("content-type") ?? "";
      const essence = parseMediaType(contentType);
      if (essence !== JSON_MIME && essence !== "application/json") {
        await discardBody(res);
        throw new UpstreamError(`upstream ${logUrl} -> unexpected content-type ${contentType}`);
      }
      const contentLength = res.headers.get("content-length");
      if (contentLength !== null) {
        const n = Number.parseInt(contentLength, 10);
        if (!Number.isNaN(n) && n > config.maxBodyBytes) {
          await discardBody(res);
          throw new UpstreamError(`upstream ${logUrl} -> response too large (${n} bytes)`);
        }
      }
      // Incremental cap: a chunked / lying upstream must never be fully
      // buffered before the size limit applies.
      const body = await readStreamBounded(res.body, config.maxBodyBytes);
      if (body === null) {
        throw new UpstreamError(`upstream ${logUrl} -> response too large (> ${config.maxBodyBytes} bytes streamed)`);
      }
      const parsed = validateJsonResponse(body);
      if (!parsed) {
        throw new UpstreamError(`upstream ${logUrl} -> invalid dns-json response`);
      }
      return { data: parsed, providerIndex: i };
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
    } finally {
      clearTimeout(timer);
    }
  }
  throw lastError instanceof UpstreamError ? lastError : new UpstreamError("all JSON upstreams failed");
}

/**
 * Parses and structurally validates a dns-json body (Google resolve style):
 * a JSON object with a numeric `Status` when present and array-typed
 * Question/Answer/Authority/Additional sections with object entries. Returns
 * null when the body is not trustworthy as a dns-json response.
 */
function validateJsonResponse(body: Uint8Array): JsonResponse | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(body));
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const obj = parsed as Record<string, unknown>;
  if ("Status" in obj && typeof obj.Status !== "number") return null;
  for (const key of ["Question", "Answer", "Authority", "Additional"] as const) {
    const value = obj[key];
    if (value === undefined) continue;
    if (!Array.isArray(value)) return null;
    if (value.some((entry) => entry === null || typeof entry !== "object" || Array.isArray(entry))) {
      return null;
    }
  }
  return obj as JsonResponse;
}
