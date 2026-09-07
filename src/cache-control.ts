// Cache-Control strategy (RFC 8484 §5 + RFC 2308 negative caching).
//
//   NOERROR + Answer        -> public, s-maxage=<min answer TTL capped>
//   NXDOMAIN / NODATA       -> public, s-maxage=<RFC 2308 negative TTL capped>
//   SERVFAIL / REFUSED / FORMERR / other RCODE -> no-store (never cache failures)
//   POST / ECS-sensitive / invalid response   -> no-store
//
// Rationale: a shared cache (Vercel CDN) reuses these responses across
// invocations, so anything client-specific (ECS) or transiently wrong
// (SERVFAIL) must never be cached publicly.

export interface CacheControlInput {
  method: string;
  /** Whether the upstream response passed DNS validation. */
  validResponse: boolean;
  rcode: number;
  /** True when the request carried ECS or the proxy injected ECS. */
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

  const ttl =
    input.rcode === 0 && input.minAnswerTtl !== null
      ? input.minAnswerTtl
      : (input.negativeTtl ?? 60);
  const capped = Math.max(0, Math.min(ttl, input.cacheMaxAge));
  return `public, s-maxage=${capped}, stale-while-revalidate=60`;
}
