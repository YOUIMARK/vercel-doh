// Cache-Control strategy (RFC 8484 §5 + RFC 2308 negative caching).
//
//   NOERROR + Answer        -> public, s-maxage=<min answer TTL capped>
//   NXDOMAIN / NODATA + SOA -> public, s-maxage=<RFC 2308 negative TTL capped>
//   NXDOMAIN / NODATA w/o SOA -> no-store (RFC 2308: no SOA, no safe TTL)
//   SERVFAIL / REFUSED / FORMERR / other RCODE (incl. extended) -> no-store
//   POST / ECS-sensitive / invalid response   -> no-store
//
// Rationale: a shared cache (Vercel CDN) reuses these responses across
// invocations, so anything client-specific (ECS) or transiently wrong
// (SERVFAIL) must never be cached publicly. Negative responses without a
// usable SOA MINIMUM cannot be given a safe TTL, so they are not cached.

export interface CacheControlInput {
  method: string;
  /** Whether the upstream response passed DNS validation. */
  validResponse: boolean;
  /** Full RCODE, including EDNS(0) extended-rcode bits (BADVERS = 16, …). */
  rcode: number;
  /** True when the request carried ECS, the proxy injected ECS, or the response carries ECS. */
  ecsSensitive: boolean;
  /** Minimum ANSWER-section TTL (positive answers only). */
  minAnswerTtl: number | null;
  /** RFC 2308 negative TTL from the SOA record (NXDOMAIN/NODATA). */
  negativeTtl: number | null;
  cacheMaxAge: number;
}

export function buildCacheControl(input: CacheControlInput): string {
  if (input.method === "POST" || input.ecsSensitive || !input.validResponse) return "no-store";

  // Only NOERROR (possibly NODATA) and NXDOMAIN are cacheable.
  const cacheable = input.rcode === 0 || input.rcode === 3;
  if (!cacheable) return "no-store";

  let ttl: number | null = null;
  if (input.rcode === 0 && input.minAnswerTtl !== null) {
    ttl = input.minAnswerTtl;
  } else if (input.negativeTtl !== null) {
    ttl = input.negativeTtl; // RFC 2308: min(SOA TTL, SOA.MINIMUM)
  }
  // NXDOMAIN/NODATA without a usable SOA → no safe negative TTL → no-store.
  if (ttl === null) return "no-store";

  const capped = Math.max(0, Math.min(ttl, input.cacheMaxAge));
  // The serve-stale window never exceeds the entry's own TTL (bounded at 60s):
  // the CDN may revalidate in the background, but stale data is never served
  // for longer than the answer would have been considered fresh anyway.
  const stale = Math.max(0, Math.min(60, capped));
  return `public, s-maxage=${capped}, stale-while-revalidate=${stale}`;
}
