// TTL extraction for RFC-8484-friendly Cache-Control on GET responses.
//
// Positive answers:  use the minimum TTL of the ANSWER section.
// Negative answers (NXDOMAIN / NODATA): per RFC 2308 the negative TTL is
// min(SOA TTL, SOA.MINIMUM) from the AUTHORITY section's SOA record.

import { parseSections, skipName, toView } from "./wire";

const SOA_RR_TYPE = 6;

/** Minimum TTL across the ANSWER section, or null when there are no answers. */
export function minAnswerTtl(msg: Uint8Array): number | null {
  const parsed = parseSections(msg);
  if (!parsed || parsed.answers.rrs.length === 0) return null;
  return Math.min(...parsed.answers.rrs.map((rr) => rr.ttl));
}

/**
 * Negative-caching TTL per RFC 2308: min(SOA TTL, SOA.MINIMUM).
 * Returns null when no valid SOA is present in the AUTHORITY section.
 */
export function soaNegativeTtl(msg: Uint8Array): number | null {
  const parsed = parseSections(msg);
  if (!parsed) return null;
  const view = toView(msg);
  for (const rr of parsed.authority.rrs) {
    if (rr.rrType !== SOA_RR_TYPE) continue;
    // SOA RDATA: MNAME (name) + RNAME (name) + 5 × uint32
    let o = skipName(view, rr.rdataOffset);
    if (o === -1 || o >= rr.rdataOffset + rr.rdLength) return null;
    o = skipName(view, o);
    if (o === -1 || o + 20 > rr.rdataOffset + rr.rdLength) return null;
    const minimum = view.getUint32(o + 16); // SERIAL REFRESH RETRY EXPIRE MINIMUM
    return Math.min(rr.ttl, minimum);
  }
  return null;
}
