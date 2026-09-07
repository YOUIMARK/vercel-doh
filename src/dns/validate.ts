// DNS response validation — the trust boundary between upstream bytes and
// everything downstream (caching, relaying, further parsing).
//
// A valid DoH response (RFC 8484) must be:
//   - HTTP 2xx with Content-Type application/dns-message (checked in upstream.ts)
//   - a structurally sound DNS message: parseable header + sections, QR=1,
//     standard opcode, no trailing garbage, ≤1 OPT RR with a root owner name,
//     type-consistent RDATA, and — when the request message is known — an ID
//     and question section that echo the request sent upstream.

import { parseHeader, parseSections, type DnsHeader } from "./wire.js";
import { checkRdataTypes, countOptRrs, extendedRcode, questionMatches, toView } from "./wire.js";

export interface ValidatedResponse {
  header: DnsHeader;
  /** Full RCODE including EDNS(0) extended-rcode bits (e.g. BADVERS = 16). */
  rcode: number;
}

/**
 * Returns a validated view of a DNS response message, or null when the bytes
 * cannot be trusted as a DNS response. When `request` is provided, the
 * response ID and question section must echo the request (the exact message
 * that was sent upstream, after any ECS/QTYPE modification).
 */
export function validateDnsResponse(msg: Uint8Array, request?: Uint8Array): ValidatedResponse | null {
  const header = parseHeader(msg);
  if (!header) return null;
  if ((header.flags & 0x8000) === 0) return null; // QR must be 1 (response)
  const opcode = (header.flags >> 11) & 0x0f;
  if (opcode !== 0) return null; // only standard queries are proxied
  const sections = parseSections(msg);
  if (!sections) return null;
  if (sections.additional.nextOffset !== msg.length) return null; // trailing garbage
  if (countOptRrs(msg) > 1) return null; // RFC 6891: at most one OPT
  const view = toView(msg);
  // RFC 6891 §6.1.2: the OPT owner name MUST be the root domain.
  for (const rr of sections.additional.rrs) {
    if (rr.rrType !== 41) continue;
    if (rr.offset - rr.nameStart !== 1 || msg[rr.nameStart] !== 0) return null;
  }
  if (!checkRdataTypes(view, sections)) return null; // type-consistent RDATA
  if (request && !questionMatches(msg, request)) return null; // ID + question echo
  return { header, rcode: extendedRcode(msg) };
}
