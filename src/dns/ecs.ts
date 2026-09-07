// EDNS Client Subnet (ECS, RFC 7871) handling.
// Key correctness rule: a DNS message must never contain two OPT RRs.
// If an OPT RR already exists we merge the ECS option into its RDATA;
// we only append a new OPT RR when the message has none.

import { parseSections, toView } from "./wire";
import { isPrivateOrReserved, parseIp, type IpAddress } from "./ip";
import { debugLog } from "../log";

export const ECS_OPTION_CODE = 8;
export const OPT_RR_TYPE = 41; // EDNS(0)

const FAMILY_IPV4 = 1;
const FAMILY_IPV6 = 2;

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
  return out;
}

/** Returns true when the message already carries a meaningful (non-zero prefix) ECS option. */
export function hasMeaningfulEcs(msg: Uint8Array): boolean {
  const opt = findOptRr(msg);
  if (!opt) return false;
  const view = toView(msg);
  const end = opt.rdataOffset + opt.rdLength;
  let o = opt.rdataOffset;
  while (o + 4 <= end) {
    const code = view.getUint16(o);
    const len = view.getUint16(o + 2);
    if (o + 4 + len > end) return false; // malformed option
    if (code === ECS_OPTION_CODE && len >= 4) {
      const family = view.getUint16(o + 4);
      const sourcePrefix = view.getUint8(o + 6);
      if (sourcePrefix > 0 && (family === FAMILY_IPV4 || family === FAMILY_IPV6)) return true;
    }
    o += 4 + len;
  }
  return false;
}

/** Locates the OPT RR in the ADDITIONAL section, or null when absent/malformed. */
function findOptRr(msg: Uint8Array) {
  const parsed = parseSections(msg);
  if (!parsed) return null;
  const opt = parsed.additional.rrs.find((rr) => rr.rrType === OPT_RR_TYPE);
  return opt ?? null;
}

/**
 * Adds the given ECS option to the message:
 *  - merges into the existing OPT RR's RDATA when one exists (ARCOUNT unchanged);
 *  - appends a brand-new OPT RR otherwise (ARCOUNT + 1).
 * Returns the original message unchanged on any malformed input.
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
