// Cache-Control strategy (RFC 8484 §5 + DNS TTL semantics).
//   GET + NOERROR + no ECS  -> public, s-maxage=<min TTL capped>
//   GET + other RCODE       -> public, s-maxage=60 (conservative negative cache)
//   POST or ECS injected    -> no-store (privacy: query lives in the body / subnets exposed)

export interface CacheControlInput {
  method: string;
  rcode: number;
  ecsAdded: boolean;
  minTtl: number | null;
  cacheMaxAge: number;
}

export function buildCacheControl(input: CacheControlInput): string {
  if (input.method === "POST" || input.ecsAdded) return "no-store";
  if (input.rcode !== 0) return "public, s-maxage=60";
  const ttl = input.minTtl === null ? 60 : Math.max(0, Math.min(input.minTtl, input.cacheMaxAge));
  return `public, s-maxage=${ttl}, stale-while-revalidate=60`;
}
