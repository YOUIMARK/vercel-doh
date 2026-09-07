// TTL extraction for RFC-8484-friendly Cache-Control on GET responses.

import { parseSections } from "./wire";

/**
 * Returns the minimum TTL across the ANSWER section, falling back to the
 * AUTHORITY section (relevant for negative answers). Returns null when the
 * message has no resource records or cannot be parsed.
 */
export function minTtl(msg: Uint8Array): number | null {
  const parsed = parseSections(msg);
  if (!parsed) return null;
  const candidates: number[] = [];
  for (const rr of parsed.answers.rrs) candidates.push(rr.ttl);
  for (const rr of parsed.authority.rrs) candidates.push(rr.ttl);
  if (candidates.length === 0) return null;
  return Math.min(...candidates);
}
