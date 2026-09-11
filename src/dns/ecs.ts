// EDNS Client Subnet (ECS, RFC 7871) handling.
//
// Key correctness rules:
//  1. A DNS message must never contain two OPT RRs (RFC 6891).
//  2. ECS source prefix 0 is a VALID ECS meaning "don't provide client
//     address info" — it must never be treated as "no ECS" and overridden
//     with the real client subnet.
//  3. Malformed ECS options must be rejected, not silently ignored.

import { countOptRrs, parseSections, toView } from "./wire.js";
import { isPrivateOrReserved, parseIp, type IpAddress } from "./ip.js";
import { debugLog } from "../log.js";

export const ECS_OPTION_CODE = 8;
export const OPT_RR_TYPE = 41; // EDNS(0)

const FAMILY_IPV4 = 1;
const FAMILY_IPV6 = 2;

export type EcsStatus = "absent" | "zero" | "positive" | "malformed";

/** A parsed ECS option (family, prefixes, address bytes). */
export interface EcsOption {
  family: number;
  sourcePrefix: number;
  scopePrefix: number;
  /** Address bytes (exactly ceil(sourcePrefix / 8) octets). */
  address: Uint8Array<ArrayBuffer>;
}

export interface EcsStatusOptions {
  /**
   * Whether the message is a QUERY (client → proxy). RFC 7871 §7.1.1: in a
   * query the SCOPE PREFIX-LENGTH MUST be 0 and the address bits beyond the
   * source prefix MUST be zero. Responses legitimately carry a non-zero scope
   * (and may echo a truncated address), so those checks only apply to queries.
   */
  asQuery?: boolean;
}

/**
 * Classifies the ECS state of a message:
 *  - "absent":     no ECS option (auto-injection is allowed by policy)
 *  - "zero":       ECS with source prefix 0 (client explicitly opts out of
 *                  address disclosure — never inject over it)
 *  - "positive":   ECS with source prefix > 0 (client-provided subnet)
 *  - "malformed":  broken OPT/ECS structure (must be rejected)
 */
export function ecsStatus(msg: Uint8Array, opts: EcsStatusOptions = {}): EcsStatus {
  const parsed = parseSections(msg);
  if (!parsed) return "malformed";
  if (countOptRrs(msg) > 1) return "malformed"; // RFC 6891: at most one OPT

  const view = toView(msg);
  let sawEcs = false;
  let status: "zero" | "positive" | null = null;

  for (const opt of parsed.additional.rrs) {
    if (opt.rrType !== OPT_RR_TYPE) continue;
    // RFC 6891 §6.1.2: the OPT owner name MUST be the root domain.
    if (opt.offset - opt.nameStart !== 1 || msg[opt.nameStart] !== 0) return "malformed";
    const end = opt.rdataOffset + opt.rdLength;
    let o = opt.rdataOffset;
    while (o + 4 <= end) {
      const code = view.getUint16(o);
      const len = view.getUint16(o + 2);
      if (o + 4 + len > end) return "malformed"; // option overruns RDATA
      if (code === ECS_OPTION_CODE) {
        if (sawEcs) return "malformed"; // duplicate ECS option
        sawEcs = true;
        if (len < 4) return "malformed";
        const family = view.getUint16(o + 4);
        const sourcePrefix = view.getUint8(o + 6);
        const scopePrefix = view.getUint8(o + 7);
        if (family !== FAMILY_IPV4 && family !== FAMILY_IPV6) return "malformed";
        const bits = family === FAMILY_IPV4 ? 32 : 128;
        if (sourcePrefix > bits) return "malformed";
        if (opts.asQuery && scopePrefix !== 0) return "malformed"; // RFC 7871 §7.1.1
        if (len !== 4 + Math.ceil(sourcePrefix / 8)) return "malformed";
        if (opts.asQuery && !addressTrailingBitsZero(view, o + 8, sourcePrefix)) {
          return "malformed"; // RFC 7871 §7.1.1: bits beyond the prefix MUST be zero
        }
        status = sourcePrefix === 0 ? "zero" : "positive";
      }
      o += 4 + len;
    }
    // RFC 6891 §6.1.2: OPT RDATA is a sequence of options that must exactly
    // fill it. 1–3 trailing bytes (a truncated option header) are malformed,
    // NOT "no ECS" — treating them as absent would let a query slip past the
    // protocol gate and have ECS injected into a corrupt OPT.
    if (o !== end) return "malformed";
  }

  if (sawEcs) return status ?? "malformed";
  return "absent";
}

/** Whether the address's bits beyond `sourcePrefix` are all zero. */
function addressTrailingBitsZero(view: DataView, addressStart: number, sourcePrefix: number): boolean {
  const addrLen = Math.ceil(sourcePrefix / 8);
  const remBits = sourcePrefix % 8;
  if (remBits === 0) return true;
  const lastByte = view.getUint8(addressStart + addrLen - 1);
  return (lastByte & (0xff << (8 - remBits))) === lastByte;
}

/** Returns the first ECS option of a message, or null when absent/malformed. */
export function findEcs(msg: Uint8Array): EcsOption | null {
  if (ecsStatus(msg) === "malformed") return null;
  const parsed = parseSections(msg);
  if (!parsed) return null;
  const view = toView(msg);
  for (const opt of parsed.additional.rrs) {
    if (opt.rrType !== OPT_RR_TYPE) continue;
    const end = opt.rdataOffset + opt.rdLength;
    let o = opt.rdataOffset;
    while (o + 4 <= end) {
      const code = view.getUint16(o);
      const len = view.getUint16(o + 2);
      if (o + 4 + len > end) return null;
      if (code === ECS_OPTION_CODE && len >= 4) {
        const family = view.getUint16(o + 4);
        const sourcePrefix = view.getUint8(o + 6);
        const scopePrefix = view.getUint8(o + 7);
        const addrLen = len - 4;
        const address = new Uint8Array(addrLen);
        for (let i = 0; i < addrLen; i++) address[i] = view.getUint8(o + 8 + i);
        return { family, sourcePrefix, scopePrefix, address };
      }
      o += 4 + len;
    }
    if (o !== end) return null; // truncated trailing option bytes (see ecsStatus)
  }
  return null;
}

/** Builds the ECS option wire bytes (option code + option data). */
export function buildEcsOption(ip: IpAddress, prefixLength: number): Uint8Array<ArrayBuffer> {
  const bits = ip.family === FAMILY_IPV4 ? 32 : 128;
  const prefix = Math.max(0, Math.min(prefixLength, bits));
  const addrLen = Math.ceil(prefix / 8);
  const optionLength = 4 + addrLen; // FAMILY(2) + SOURCE(1) + SCOPE(1) + ADDRESS
  const out = new Uint8Array(4 + optionLength);
  const view = toView(out);
  view.setUint16(0, ECS_OPTION_CODE);
  view.setUint16(2, optionLength);
  view.setUint16(4, ip.family);
  view.setUint8(6, prefix);
  view.setUint8(7, 0); // SCOPE PREFIX-LENGTH
  out.set(ip.addressBytes.subarray(0, addrLen), 8);
  // RFC 7871 §7.1.1: bits beyond the source prefix MUST be zero. For a
  // non-octet prefix (e.g. /21) the raw address byte carries real host bits
  // below the prefix — mask them off or the option is non-canonical.
  const remBits = prefix % 8;
  if (remBits !== 0) {
    out[8 + addrLen - 1] = (out[8 + addrLen - 1] ?? 0) & (0xff << (8 - remBits));
  }
  return out;
}

/**
 * Adds the given ECS option to the message:
 *  - merges into the existing OPT RR's RDATA when one exists (ARCOUNT unchanged);
 *  - appends a brand-new OPT RR otherwise (ARCOUNT + 1).
 * Returns the original message unchanged on any malformed input.
 * Callers MUST only invoke this when ecsStatus(msg) === "absent".
 */
export function addOrMergeEcs(
  msg: Uint8Array<ArrayBuffer>,
  ecsOption: Uint8Array,
): Uint8Array<ArrayBuffer> {
  const parsed = parseSections(msg);
  if (!parsed) return msg;

  const opt = parsed.additional.rrs.find((rr) => rr.rrType === OPT_RR_TYPE);

  if (opt) {
    // Merge: insert the option bytes at the end of the OPT RR's RDATA.
    const rdataEnd = opt.rdataOffset + opt.rdLength;
    const out = new Uint8Array(msg.length + ecsOption.length);
    out.set(msg.subarray(0, rdataEnd), 0);
    out.set(ecsOption, rdataEnd);
    out.set(msg.subarray(rdataEnd), rdataEnd + ecsOption.length);
    // Update RDLENGTH of the OPT RR.
    const view = toView(out);
    view.setUint16(opt.rdataOffset - 2, opt.rdLength + ecsOption.length);
    return out;
  }

  // No OPT RR: append one at the very end (RFC 6891: only one OPT RR allowed).
  const out = new Uint8Array(msg.length + 11 + ecsOption.length);
  out.set(msg, 0);
  let o = msg.length;
  out[o] = 0; // root name
  o += 1;
  const view = toView(out);
  view.setUint16(o, OPT_RR_TYPE);
  view.setUint16(o + 2, 4096); // UDP payload size
  view.setUint32(o + 4, 0); // extended RCODE / flags / version / Z
  view.setUint16(o + 8, ecsOption.length);
  out.set(ecsOption, o + 10);
  // ARCOUNT + 1
  view.setUint16(10, parsed.header.ar + 1);
  return out;
}

/**
 * Removes any ECS option from the message (privacy: `/no-ecs` must STRIP a
 * client-provided subnet, not merely skip injection):
 *  - when the OPT RR still carries other options, its RDATA is rebuilt
 *    (RDLENGTH updated, ARCOUNT unchanged);
 *  - when the OPT RDATA becomes empty, the whole OPT RR is removed and
 *    ARCOUNT is decremented (an OPT RR with no options is useless).
 * Returns the original message when there is no ECS to remove or the input is
 * malformed (callers validate the message first).
 */
export function removeEcsOption(msg: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  const parsed = parseSections(msg);
  if (!parsed) return msg;
  const opt = parsed.additional.rrs.find((rr) => rr.rrType === OPT_RR_TYPE);
  if (!opt) return msg;
  const view = toView(msg);
  const end = opt.rdataOffset + opt.rdLength;
  const kept: Uint8Array[] = [];
  let sawEcs = false;
  let o = opt.rdataOffset;
  while (o + 4 <= end) {
    const code = view.getUint16(o);
    const len = view.getUint16(o + 2);
    if (o + 4 + len > end) return msg; // malformed option → leave untouched
    if (code === ECS_OPTION_CODE) sawEcs = true;
    else kept.push(msg.subarray(o, o + 4 + len));
    o += 4 + len;
  }
  if (o !== end) return msg; // truncated option header → leave untouched
  if (!sawEcs) return msg;

  if (kept.length > 0) {
    const keptBytes = concatBytes(kept);
    const out = new Uint8Array(msg.length - opt.rdLength + keptBytes.length);
    out.set(msg.subarray(0, opt.rdataOffset), 0);
    out.set(keptBytes, opt.rdataOffset);
    out.set(msg.subarray(end), opt.rdataOffset + keptBytes.length);
    toView(out).setUint16(opt.rdataOffset - 2, keptBytes.length); // new RDLENGTH
    return out;
  }

  // No options left: drop the entire OPT RR and decrement ARCOUNT.
  const rrStart = opt.nameStart;
  const out = new Uint8Array(msg.length - (end - rrStart));
  out.set(msg.subarray(0, rrStart), 0);
  out.set(msg.subarray(end), rrStart);
  toView(out).setUint16(10, parsed.header.ar - 1);
  return out;
}

function concatBytes(chunks: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const total = chunks.reduce((acc, c) => acc + c.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return out;
}

/**
 * Extracts the client IP from trusted headers for ECS injection.
 * Chain: x-vercel-forwarded-for → x-real-ip → x-forwarded-for (rightmost entry,
 * which is the value appended by Vercel's edge — the leftmost is client-spoofable).
 * Private/reserved addresses are rejected.
 */
export function parseClientIp(headers: Headers): IpAddress | null {
  for (const name of ["x-vercel-forwarded-for", "x-real-ip"]) {
    const value = headers.get(name);
    if (!value) continue;
    const ip = firstPublic(value);
    if (ip) {
      debugLog(`ECS: client IP from ${name}`);
      return ip;
    }
  }
  const xff = headers.get("x-forwarded-for");
  if (xff) {
    const parts = xff.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
    for (let i = parts.length - 1; i >= 0; i--) {
      const ip = parseIp(parts[i] as string);
      if (ip && !isPrivateOrReserved(ip)) {
        debugLog("ECS: client IP from x-forwarded-for (rightmost)");
        return ip;
      }
    }
  }
  return null;
}

function firstPublic(value: string): IpAddress | null {
  for (const part of value.split(",")) {
    const ip = parseIp(part);
    if (ip && !isPrivateOrReserved(ip)) return ip;
  }
  return null;
}
