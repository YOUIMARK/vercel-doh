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
//
// Deliberately NO `stale-while-revalidate`: a DNS record's TTL is a HARD
// expiry (RFC 1035 §3.2.1: "the time interval that the resource record may
// be cached before it should be discarded"). Serving stale DNS past the TTL
// would hand clients answers older than the record's own lifetime — the CDN
// must refetch once s-maxage elapses, never extend it with a serve-stale
// window.

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
  /** 0..1 jitter fraction applied DOWN to the s-maxage (default 0 = off). */
  ttlJitter?: number;
}

/**
 * Builds the Cache-Control value. Optional `rng` (default Math.random) makes
 * the TTL jitter deterministic in tests: with rng()=0 the value stays at the
 * exact TTL, with rng()=1 it is reduced by the full jitter fraction.
 */
export function buildCacheControl(input: CacheControlInput, rng: () => number = Math.random): string {
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

  // Thundering-herd protection: jitter the shared-cache TTL DOWN only, so
  // freshness can never exceed the authoritative DNS TTL (RFC 1035 hard
  // expiry). A floor of 1s keeps the entry at least briefly cacheable.
  const jitter = input.ttlJitter ?? 0;
  let effective = capped;
  if (jitter > 0 && effective > 1) {
    effective = Math.max(1, Math.floor(effective * (1 - rng() * jitter)));
  }
  return `public, s-maxage=${effective}`;
}
