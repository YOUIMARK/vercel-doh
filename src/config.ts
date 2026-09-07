// Single source of truth for all configuration.
// Every env var is parsed and validated here; bad values fail fast at boot.

import { setDebugLogging } from "./log.js";

export interface DomainMapping {
  /**
   * Upstream base for the provider. A bare hostname is normalized to https;
   * an explicit scheme must be https: (validated at parse time — SSRF guard).
   */
  targetDomain: string;
}

/**
 * Answer-family preference: v4 forces the question type to A, v6 to AAAA
 * (the "仅v4 / 仅v6" semantics — the RESOLVED answer family, not the
 * upstream connection family). "auto" leaves the query unchanged.
 */
export type Family = "auto" | "v4" | "v6";

export interface DoHConfig {
  /** Regular dns-message upstreams, tried in order (no broadcast by default). */
  upstreamUrls: string[];
  /** Upstreams used when the query carries (or we added) ECS. */
  ecsUpstreamUrls: string[];
  /** dns-json upstreams for the JSON API. */
  jsonUpstreamUrls: string[];
  /** Base path for the DoH endpoints (path obfuscation). Default: /dns-query. */
  dohPath: string;
  /** Answer family: auto | v4 (force A answers) | v6 (force AAAA answers). */
  upstreamFamily: Family;
  /** Whether the frontend may display the DoH endpoint path (default: hidden). */
  showDohEndpoint: boolean;
  /** Globally auto-attach ECS to queries without one (privacy: default off). */
  autoAddEcs: boolean;
  ipv4EcsPrefixLength: number;
  ipv6EcsPrefixLength: number;
  /** Cap for s-maxage on successful GET answers (seconds). */
  cacheMaxAge: number;
  /** Concurrently race all upstreams and take the fastest (default off). */
  raceUpstreams: boolean;
  /** RFC 8467 response padding (default off). */
  forceResponsePadding: boolean;
  /** Optional path -> upstream mapping for /dns-query/{provider}. */
  domainMappings: Record<string, DomainMapping>;
  debugLogging: boolean;
  appVersion: string;
  /** Hard cap on the DNS message size we accept. */
  maxBodyBytes: number;
  /** Per-upstream fetch timeout. */
  upstreamTimeoutMs: number;
  /** How many upstreams to try in sequential failover mode. */
  maxAttempts: number;
}

export const DEFAULTS = {
  UPSTREAM_DOH_URLS: "https://cloudflare-dns.com/dns-query",
  ECS_UPSTREAM_DOH_URLS: "https://dns.google/dns-query",
  JSON_UPSTREAM_DOH_URLS: "https://dns.google/resolve",
  DOH_PATH: "/dns-query",
  UPSTREAM_FAMILY: "auto",
  SHOW_DOH_ENDPOINT: false,
  AUTO_ADD_ECS: false,
  IPV4_ECS_PREFIX_LENGTH: 24,
  IPV6_ECS_PREFIX_LENGTH: 56,
  CACHE_MAX_AGE: 300,
  RACE_UPSTREAMS: false,
  FORCE_RESPONSE_PADDING: false,
  DEBUG_LOGGING: false,
  APP_VERSION: "1.0.0",
  MAX_BODY_BYTES: 64 * 1024,
  UPSTREAM_TIMEOUT_MS: 3000,
  MAX_ATTEMPTS: 3,
} as const;

export function parseBool(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined || value === "") return fallback;
  const v = value.toLowerCase();
  if (v === "true" || v === "1" || v === "yes") return true;
  if (v === "false" || v === "0" || v === "no") return false;
  throw new Error(`invalid boolean value: "${value}"`);
}

function parseNumber(value: string | undefined, fallback: number, min: number, max: number, name: string): number {
  if (value === undefined || value === "") return fallback;
  // Strict integer only — "3000foo" / "24.9" must be rejected, not truncated.
  if (!/^\d+$/.test(value)) {
    throw new Error(`invalid ${name}: "${value}" (expected an integer ${min}..${max})`);
  }
  const n = Number.parseInt(value, 10);
  if (Number.isNaN(n) || !Number.isFinite(n) || n < min || n > max) {
    throw new Error(`invalid ${name}: "${value}" (expected ${min}..${max})`);
  }
  return n;
}

function parseUrlList(value: string | undefined, fallback: string): string[] {
  const raw = (value === undefined || value === "") ? fallback : value;
  const urls = raw
    .split(",")
    .map((u) => u.trim())
    .filter((u) => u.length > 0);
  if (urls.length === 0) throw new Error("upstream URL list must not be empty");
  for (const u of urls) {
    let parsed: URL;
    try {
      parsed = new URL(u);
    } catch {
      throw new Error(`invalid upstream URL: "${u}"`);
    }
    if (parsed.protocol !== "https:") throw new Error(`upstream URL must be https: "${u}"`);
  }
  return urls;
}

function parseDomainMappings(value: string | undefined): Record<string, DomainMapping> {
  if (value === undefined || value === "") return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error("DOMAIN_MAPPINGS must be a valid JSON object");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("DOMAIN_MAPPINGS must be a JSON object");
  }
  const out: Record<string, DomainMapping> = {};
  for (const [prefix, mapping] of Object.entries(parsed as Record<string, unknown>)) {
    if (mapping === null || typeof mapping !== "object" || Array.isArray(mapping)) {
      throw new Error(`DOMAIN_MAPPINGS["${prefix}"] must be an object`);
    }
    const m = mapping as Record<string, unknown>;
    if (typeof m.targetDomain !== "string" || m.targetDomain.length === 0) {
      throw new Error(`DOMAIN_MAPPINGS["${prefix}"].targetDomain must be a non-empty string`);
    }
    // Same https-only rule as the regular upstreams (SSRF guard).
    const raw = m.targetDomain.includes("://") ? m.targetDomain : `https://${m.targetDomain}`;
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      throw new Error(`DOMAIN_MAPPINGS["${prefix}"].targetDomain is not a valid URL`);
    }
    if (url.protocol !== "https:") {
      throw new Error(`DOMAIN_MAPPINGS["${prefix}"].targetDomain must be https`);
    }
    out[prefix] = { targetDomain: m.targetDomain };
  }
  return out;
}

/**
 * Parses the DoH base path. Must be a single URL path segment starting with "/",
 * e.g. "/dns-query" or "/3f9a2b7c". Used for path obfuscation: when set to a
 * non-default value, the standard /dns-query endpoints are NOT registered.
 */
export function parseDohPath(value: string | undefined): string {
  const raw = value === undefined || value === "" ? DEFAULTS.DOH_PATH : value.trim();
  if (!/^\/[A-Za-z0-9_-]+$/.test(raw)) {
    throw new Error(`invalid DOH_PATH: "${raw}" (expected a single path segment, e.g. /dns-query)`);
  }
  return raw;
}

export function parseFamily(value: string | undefined): Family {
  if (value === undefined || value === "") return "auto";
  const v = value.trim().toLowerCase();
  if (v === "auto" || v === "v4" || v === "v6") return v;
  throw new Error(`invalid UPSTREAM_FAMILY: "${value}" (expected auto | v4 | v6)`);
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): DoHConfig {
  const config: DoHConfig = {
    upstreamUrls: parseUrlList(env.UPSTREAM_DOH_URLS, DEFAULTS.UPSTREAM_DOH_URLS),
    ecsUpstreamUrls: parseUrlList(env.ECS_UPSTREAM_DOH_URLS, DEFAULTS.ECS_UPSTREAM_DOH_URLS),
    jsonUpstreamUrls: parseUrlList(env.JSON_UPSTREAM_DOH_URLS, DEFAULTS.JSON_UPSTREAM_DOH_URLS),
    dohPath: parseDohPath(env.DOH_PATH),
    upstreamFamily: parseFamily(env.UPSTREAM_FAMILY),
    showDohEndpoint: parseBool(env.SHOW_DOH_ENDPOINT, DEFAULTS.SHOW_DOH_ENDPOINT),
    autoAddEcs: parseBool(env.AUTO_ADD_ECS, DEFAULTS.AUTO_ADD_ECS),
    ipv4EcsPrefixLength: parseNumber(env.IPV4_ECS_PREFIX_LENGTH, DEFAULTS.IPV4_ECS_PREFIX_LENGTH, 0, 32, "IPV4_ECS_PREFIX_LENGTH"),
    ipv6EcsPrefixLength: parseNumber(env.IPV6_ECS_PREFIX_LENGTH, DEFAULTS.IPV6_ECS_PREFIX_LENGTH, 0, 128, "IPV6_ECS_PREFIX_LENGTH"),
    cacheMaxAge: parseNumber(env.CACHE_MAX_AGE, DEFAULTS.CACHE_MAX_AGE, 0, 86400, "CACHE_MAX_AGE"),
    raceUpstreams: parseBool(env.RACE_UPSTREAMS, DEFAULTS.RACE_UPSTREAMS),
    forceResponsePadding: parseBool(env.FORCE_RESPONSE_PADDING, DEFAULTS.FORCE_RESPONSE_PADDING),
    domainMappings: parseDomainMappings(env.DOMAIN_MAPPINGS),
    debugLogging: parseBool(env.DEBUG_LOGGING, DEFAULTS.DEBUG_LOGGING),
    appVersion: env.APP_VERSION || DEFAULTS.APP_VERSION,
    maxBodyBytes: DEFAULTS.MAX_BODY_BYTES,
    upstreamTimeoutMs: parseNumber(env.UPSTREAM_TIMEOUT_MS, DEFAULTS.UPSTREAM_TIMEOUT_MS, 500, 30000, "UPSTREAM_TIMEOUT_MS"),
    maxAttempts: DEFAULTS.MAX_ATTEMPTS,
  };
  setDebugLogging(config.debugLogging);
  return config;
}
