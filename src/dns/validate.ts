// DNS response validation — the trust boundary between upstream bytes and
// everything downstream (caching, relaying, further parsing).
//
// A valid DoH response (RFC 8484) must be:
//   - HTTP 2xx with Content-Type application/dns-message (checked in upstream.ts)
//   - a structurally sound DNS message: parseable header + sections, QR=1,
//     standard opcode, no trailing garbage

import { parseHeader, parseSections, type DnsHeader } from "./wire.js";

export interface ValidatedResponse {
  header: DnsHeader;
  rcode: number;
}

/**
 * Returns a validated view of a DNS response message, or null when the bytes
 * cannot be trusted as a DNS response.
 */
export function validateDnsResponse(msg: Uint8Array): ValidatedResponse | null {
  const header = parseHeader(msg);
  if (!header) return null;
  if ((header.flags & 0x8000) === 0) return null; // QR must be 1 (response)
  const opcode = (header.flags >> 11) & 0x0f;
  if (opcode !== 0) return null; // only standard queries are proxied
  const sections = parseSections(msg);
  if (!sections) return null;
  if (sections.additional.nextOffset !== msg.length) return null; // trailing garbage
  return { header, rcode: header.flags & 0x0f };
}
