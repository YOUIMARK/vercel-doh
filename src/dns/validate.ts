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
import { ecsStatus, findEcs } from "./ecs.js";

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
 *
 * EDNS(0)/ECS is part of the trust boundary, not an afterthought: a
 * structurally broken OPT option set (overruns, duplicate ECS, invalid ECS
 * family/length) rejects the response outright, and when the response carries
 * an ECS option the FAMILY / SOURCE PREFIX-LENGTH / address bits must echo the
 * request's ECS (RFC 7871 §7.2.1) — a response claiming a different subnet
 * than we sent is not trustworthy. (A response WITHOUT ECS is always accepted:
 * resolvers may omit it. A non-zero response SCOPE is legal and not rejected.)
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
  if (ecsStatus(msg) === "malformed") return null; // broken EDNS/ECS option structure
  if (request && !questionMatches(msg, request)) return null; // ID + question echo
  if (request && !ecsEchoMatches(msg, request)) return null; // ECS echo (when present)
  return { header, rcode: extendedRcode(msg) };
}

/**
 * RFC 7871 §7.2.1 consistency: when the response carries an ECS option it
 * MUST echo the FAMILY, SOURCE PREFIX-LENGTH and address (prefix bits) of the
 * request's ECS. Responses without ECS (or for requests without ECS) always
 * pass — omitting ECS is a resolver's right; inventing a mismatched one is not.
 */
function ecsEchoMatches(response: Uint8Array, request: Uint8Array): boolean {
  const respEcs = findEcs(response);
  if (!respEcs) return true;
  const reqEcs = findEcs(request);
  if (!reqEcs) return true; // response ECS without a request ECS → tolerated (still sensitive downstream)
  if (respEcs.family !== reqEcs.family || respEcs.sourcePrefix !== reqEcs.sourcePrefix) return false;
  const addrLen = Math.ceil(reqEcs.sourcePrefix / 8);
  for (let i = 0; i < addrLen; i++) {
    if ((respEcs.address[i] ?? 0) !== (reqEcs.address[i] ?? 0)) return false;
  }
  return true;
}
