// Server-side query proxy for third-party DoH providers.
//
// This replicates CF-Workers-DoH's `?doh=&domain=&type=` handler: the worker
// fetches the selected provider's dns-json endpoint on the client's behalf,
// so the frontend never hits CORS walls and /dns-query-style JSON endpoints
// (Cloudflare, Tencent, DNS.SB, …) work exactly like in the original.
//
// Safety notes (kept from the original behavior, tightened where free):
//  - the proxied URL must be https: (cleartext http would leak queries);
//  - `redirect: "error"` — never follow redirects;
//  - responses are bounded by config.maxBodyBytes and must parse as JSON;
//  - only fixed Accept/UA variants are sent (no client headers forwarded).

import type { Context } from "hono";
import type { DoHConfig } from "../config.js";
import { corsHeaders, textError } from "../errors.js";

const JSON_MIME = "application/dns-json";

/** Record types we accept in the `type` param (plus the `all` aggregate). */
const ALLOWED_TYPES = new Set([
  "ALL", "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV",
  "CAA", "HTTPS", "SVCB", "DS", "DNSKEY", "TLSA", "ANY",
]);

interface JsonRecord {
  type?: number;
  name?: string;
  data?: unknown;
  TTL?: number;
}

interface JsonSections {
  Status?: unknown;
  TC?: unknown;
  RD?: unknown;
  RA?: unknown;
  AD?: unknown;
  CD?: unknown;
  Question?: unknown;
  Answer?: unknown;
  Authority?: unknown;
}

/** Accept-header variants tried in order (original queryDns behavior). */
const ACCEPT_VARIANTS: ReadonlyArray<Record<string, string>> = [
  { Accept: JSON_MIME },
  {},
  { Accept: "application/json" },
  { Accept: JSON_MIME, "User-Agent": "Mozilla/5.0 DNS Client" },
];

export function handleDohProxy(config: DoHConfig) {
  return async (c: Context): Promise<Response> => {
    if (c.req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }
    if (c.req.method !== "GET") {
      return textError(405, "Method Not Allowed", corsHeaders());
    }

    const doh = c.req.query("doh");
    const domain = c.req.query("domain") ?? c.req.query("name");
    const type = (c.req.query("type") ?? "all").toUpperCase();
    if (!doh || !domain) return textError(400, "Missing doh/domain parameters", corsHeaders());
    if (!/^https:\/\//i.test(doh)) return textError(400, "doh must be an https:// URL", corsHeaders());
    if (!ALLOWED_TYPES.has(type)) return textError(400, `unsupported type: ${type}`, corsHeaders());
    if (domain.length > 253 || !/^[a-zA-Z0-9._-]+$/.test(domain)) {
      return textError(400, "invalid domain", corsHeaders());
    }

    try {
      if (type === "ALL") {
        const [a, aaaa, ns] = await Promise.all([
          queryDnsJson(config, doh, domain, "A"),
          queryDnsJson(config, doh, domain, "AAAA"),
          queryDnsJson(config, doh, domain, "NS"),
        ]);
        return jsonOk(mergeAll(a, aaaa, ns));
      }
      return jsonOk(await queryDnsJson(config, doh, domain, type));
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return new Response(JSON.stringify({ error: `DNS 查询失败: ${msg}` }, null, 2), {
        status: 502,
        headers: {
          "content-type": "application/json; charset=utf-8",
          "cache-control": "no-store",
          ...corsHeaders(),
        },
      });
    }
  };
}

/** One dns-json query against the selected provider (multi-Accept fallback). */
async function queryDnsJson(
  config: DoHConfig,
  doh: string,
  domain: string,
  type: string,
): Promise<JsonSections> {
  const url = new URL(doh);
  url.searchParams.set("name", domain);
  url.searchParams.set("type", type);

  let lastError: Error | null = null;
  for (const headers of ACCEPT_VARIANTS) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), config.upstreamTimeoutMs);
    try {
      const res = await fetch(url.toString(), {
        headers,
        signal: controller.signal,
        redirect: "error", // SSRF guard: never follow redirects
      });
      if (!res.ok) {
        const t = await res.text().catch(() => "");
        lastError = new Error(`DoH 服务器返回错误 (${res.status}): ${t.slice(0, 200)}`);
        continue;
      }
      const text = await res.text();
      if (text.length > config.maxBodyBytes) {
        lastError = new Error("响应超过大小上限");
        continue;
      }
      const parsed = JSON.parse(text) as unknown;
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        lastError = new Error("无法解析响应为 JSON");
        continue;
      }
      return parsed as JsonSections;
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
    } finally {
      clearTimeout(timer);
    }
  }
  throw lastError ?? new Error("无法完成 DNS 查询");
}

function recordsOf(section: JsonSections | null): JsonRecord[] {
  if (!section || !Array.isArray(section.Answer)) return [];
  return section.Answer as JsonRecord[];
}

function statusOf(section: JsonSections | null): unknown {
  return section?.Status;
}

function truthyOf(section: JsonSections | null, key: keyof JsonSections): unknown {
  return section?.[key];
}

/** Merges the A/AAAA/NS results into CF-Workers-DoH's combined shape. */
function mergeAll(a: JsonSections, aaaa: JsonSections, ns: JsonSections): Record<string, unknown> {
  const nsRecords: JsonRecord[] = [];
  for (const key of ["Answer", "Authority"] as const) {
    const arr = ns[key];
    if (!Array.isArray(arr)) continue;
    for (const r of arr as JsonRecord[]) {
      if (r.type === 2 || r.type === 6) nsRecords.push(r);
    }
  }

  const questions: unknown[] = [];
  for (const section of [a, aaaa, ns]) {
    if (Array.isArray(section.Question)) questions.push(...(section.Question as unknown[]));
  }

  return {
    Status: statusOf(a) || statusOf(aaaa) || statusOf(ns) || 0,
    TC: truthyOf(a, "TC") || truthyOf(aaaa, "TC") || truthyOf(ns, "TC") || false,
    RD: truthyOf(a, "RD") || truthyOf(aaaa, "RD") || truthyOf(ns, "RD") || false,
    RA: truthyOf(a, "RA") || truthyOf(aaaa, "RA") || truthyOf(ns, "RA") || false,
    AD: truthyOf(a, "AD") || truthyOf(aaaa, "AD") || truthyOf(ns, "AD") || false,
    CD: truthyOf(a, "CD") || truthyOf(aaaa, "CD") || truthyOf(ns, "CD") || false,
    Question: questions,
    Answer: [...recordsOf(a), ...recordsOf(aaaa), ...nsRecords],
    ipv4: { records: recordsOf(a) },
    ipv6: { records: recordsOf(aaaa) },
    ns: { records: nsRecords },
  };
}

function jsonOk(data: unknown): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status: 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...corsHeaders(),
    },
  });
}
