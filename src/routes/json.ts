// Google-style dns-json API (for the browser query tool).
// Same trust boundary as the dns-message path: only 2xx JSON responses with
// the right Content-Type that actually parse as the dns-json schema are
// accepted; malformed bodies fail over sequentially.
//
// URL flags (path suffixes, URL overrides env):
//   /dns-query-json/v4        → force type=A (answer family)
//   /dns-query-json/v6        → force type=AAAA
//   /dns-query-json/ecs       → inject edns_client_subnet from the client IP
//   /dns-query-json/ecs-<ip>  → inject edns_client_subnet from a fixed IP
//   /dns-query-json/no-ecs    → strip any edns_client_subnet (privacy)
//   combinable: /dns-query-json/v4/ecs-8.8.8.8

import type { Context } from "hono";
import type { DoHConfig, Family } from "../config.js";
import { corsHeaders, textError } from "../errors.js";
import { acceptsMediaType, parseMediaType } from "../media.js";
import { parseClientIp } from "../dns/ecs.js";
import { formatEcsPrefix, parseCidr, parseIp } from "../dns/ip.js";
import { debugLog } from "../log.js";
import { redactUrl, UpstreamError } from "../upstream.js";
import { ALLOWED_TYPES } from "./proxy.js";

const JSON_PARAMS = ["name", "type", "cd", "do", "edns_client_subnet"] as const;
const JSON_MIME = "application/dns-json";
const JSON_BASE = "/dns-query-json";
const INVALID = "__invalid__";
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

function parseJsonFlags(pathname: string): JsonFlags {
  if (!pathname.startsWith(`${JSON_BASE}/`)) return { family: null, ecs: null, ecsOverrideIp: null };
  const segments = pathname.slice(JSON_BASE.length + 1).split("/").filter((s) => s.length > 0);
  const flags: JsonFlags = { family: null, ecs: null, ecsOverrideIp: null };
  for (const segment of segments) {
    if (segment === "v4") flags.family = "v4";
    else if (segment === "v6") flags.family = "v6";
    else if (segment === "ecs" || segment === "auto_ecs") flags.ecs = true;
    else if (segment === "no-ecs" || segment === "no_ecs") flags.ecs = false;
    else if (segment.startsWith("ecs-")) {
      const ip = segment.slice(4);
      if (!parseIp(ip)) {
        flags.family = INVALID as Family;
      } else {
        flags.ecs = true;
        flags.ecsOverrideIp = ip;
      }
    } else flags.family = INVALID as Family;
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
    const ecsOverrideIp = flags.ecsOverrideIp ?? baseFlags?.ecsOverrideIp ?? config.ecsOverrideIp;

    const accept = c.req.header("accept") ?? "";
    // Accept is only enforced when there is no `name` param: a request that
    // carries `name` IS a JSON query regardless of what Accept third-party
    // tools / browsers happen to send (RFC 8484 says SHOULD, not MUST).
    const wantsJson =
      acceptsMediaType(accept, JSON_MIME) ||
      acceptsMediaType(accept, "application/json") ||
      c.req.query("ct") === JSON_MIME;

    const name = c.req.query("name");
    if (!name) {
      if (!wantsJson) return textError(406, "Not Acceptable: application/dns-json required", corsHeaders());
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
      const parsed = await fetchJsonWithFailover(config, upstreams, params, headers);
      const cacheControl = jsonCacheControl(config, parsed, ecsSensitive);
      const out = new Headers(corsHeaders());
      out.set("Content-Type", "application/json");
      out.set("Cache-Control", cacheControl);
      debugLog(`dns-json ok (family=${family} ecs=${ecsSensitive} cache=${cacheControl})`);
      return new Response(JSON.stringify(parsed), { status: 200, headers: out });
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
 * `data` string (MNAME RNAME SERIAL REFRESH RETRY EXPIRE MINIMUM); falling
 * back to the minimum Authority TTL when the SOA cannot be parsed; anything
 * else or missing TTL information → no-store. ECS-sensitive responses are
 * never shared. No `stale-while-revalidate`: a DNS TTL is a hard expiry.
 * Exported for unit tests.
 */
export function jsonCacheControl(config: DoHConfig, parsed: JsonResponse, ecsSensitive: boolean): string {
  if (ecsSensitive) return "no-store";
  const status = typeof parsed.Status === "number" ? parsed.Status : -1;
  if (status !== 0 && status !== 3) return "no-store";

  const answerTtl = minTtlOf(parsed.Answer);
  const negativeTtl = soaJsonNegativeTtl(parsed.Authority) ?? minTtlOf(parsed.Authority);
  let ttl: number | null = null;
  if (status === 0 && answerTtl !== null) ttl = answerTtl;
  else if (negativeTtl !== null) ttl = negativeTtl;
  if (ttl === null) return "no-store"; // no usable TTL (e.g. negative w/o SOA)

  const capped = Math.max(0, Math.min(ttl, config.cacheMaxAge));
  return `public, s-maxage=${capped}`;
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
 * config.maxBodyBytes like the dns-message path.
 */
async function fetchJsonWithFailover(
  config: DoHConfig,
  upstreams: string[],
  params: URLSearchParams,
  headers: Headers,
): Promise<JsonResponse> {
  const attempts = Math.min(config.maxAttempts, upstreams.length);
  let lastError: Error | null = null;
  for (let i = 0; i < attempts; i++) {
    const upstream = upstreams[i] as string;
    const target = new URL(upstream);
    target.search = params.toString();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), config.upstreamTimeoutMs);
    const logUrl = redactUrl(target.href);
    try {
      const res = await fetch(target.href, {
        method: "GET",
        headers,
        signal: controller.signal,
        redirect: "error", // SSRF: never follow redirects
      });
      if (!res.ok) throw new UpstreamError(`upstream ${logUrl} -> ${res.status}`);
      const contentType = res.headers.get("content-type") ?? "";
      const essence = parseMediaType(contentType);
      if (essence !== JSON_MIME && essence !== "application/json") {
        throw new UpstreamError(`upstream ${logUrl} -> unexpected content-type ${contentType}`);
      }
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
      const parsed = validateJsonResponse(body);
      if (!parsed) {
        throw new UpstreamError(`upstream ${logUrl} -> invalid dns-json response`);
      }
      return parsed;
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
