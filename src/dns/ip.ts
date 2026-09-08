// Minimal IPv4/IPv6 parsing and private/reserved address filtering.
// Used only to derive an ECS source subnet from trusted Vercel headers.

export const FAMILY_IPV4 = 1;
export const FAMILY_IPV6 = 2;

export interface IpAddress {
  family: 1 | 2;
  addressBytes: Uint8Array<ArrayBuffer>; // 4 bytes for v4, 16 bytes for v6
}

/** Parses a dotted-quad IPv4 address. Returns null on any invalid input. */
export function parseIpv4(s: string): IpAddress | null {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const p = parts[i] as string;
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number.parseInt(p, 10);
    if (n > 255) return null;
    bytes[i] = n;
  }
  return { family: FAMILY_IPV4, addressBytes: bytes };
}

/** Parses an IPv6 address (supports `::` compression and IPv4-mapped tails). Returns null on invalid input. */
export function parseIpv6(s: string): IpAddress | null {
  const raw = s.trim();
  if (raw.length === 0) return null;
  if ((raw.match(/::/g) ?? []).length > 1) return null;
  if (raw.includes(":::")) return null;
  const doubleColon = raw.indexOf("::");
  const leftRaw = doubleColon === -1 ? raw : raw.slice(0, doubleColon);
  const rightRaw = doubleColon === -1 ? "" : raw.slice(doubleColon + 2);

  /** Splits a segment into 16-bit hex groups, converting a trailing IPv4 tail into two groups. */
  const toGroups = (seg: string): string[] | null => {
    if (seg.length === 0) return [];
    const parts = seg.split(":");
    const groups: string[] = [];
    for (let i = 0; i < parts.length; i++) {
      const p = parts[i] as string;
      if (i === parts.length - 1 && p.includes(".")) {
        const ip4 = parseIpv4(p);
        if (!ip4) return null;
        const b = ip4.addressBytes;
        groups.push(((b[0]! << 8) | b[1]!).toString(16), ((b[2]! << 8) | b[3]!).toString(16));
      } else {
        groups.push(p);
      }
    }
    return groups;
  };

  // Fail closed on any malformed component: a bad IPv4 tail (e.g.
  // "1::2.3.4.999") must invalidate the whole address, not be swallowed.
  const left = toGroups(leftRaw);
  const right = toGroups(rightRaw);
  if (left === null || right === null) return null;
  const leftGroups = left.filter((g) => g.length > 0);
  const rightGroups = right.filter((g) => g.length > 0);
  if (leftGroups.length === 0 && rightGroups.length === 0 && doubleColon === -1) return null;
  const total = leftGroups.length + rightGroups.length;
  if (doubleColon === -1 ? total !== 8 : total > 7) return null;

  const groups: string[] = [...leftGroups, ...Array(8 - total).fill("0"), ...rightGroups];
  if (groups.length !== 8) return null;
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const g = groups[i] as string;
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    const v = Number.parseInt(g, 16);
    bytes[i * 2] = (v >> 8) & 0xff;
    bytes[i * 2 + 1] = v & 0xff;
  }
  return { family: FAMILY_IPV6, addressBytes: bytes };
}

export function parseIp(s: string): IpAddress | null {
  const trimmed = s.trim();
  if (trimmed.length === 0) return null;
  if (trimmed.includes(":")) return parseIpv6(trimmed);
  return parseIpv4(trimmed);
}

function ipToBigInt(bytes: Uint8Array): bigint {
  let v = 0n;
  for (let i = 0; i < bytes.length; i++) v = (v << 8n) | BigInt(bytes[i] as number);
  return v;
}

interface Cidr {
  base: bigint;
  prefix: number;
  bits: number;
}

/** Builds a CIDR entry by parsing the base address with the same parser used on input. */
function cidr(base: string, prefix: number, family: 1 | 2): Cidr {
  const ip = family === FAMILY_IPV4 ? parseIpv4(base) : parseIpv6(base);
  if (!ip) throw new Error(`bad CIDR base: ${base}`);
  return { base: ipToBigInt(ip.addressBytes), prefix, bits: ip.addressBytes.length * 8 };
}

const PRIVATE_V4: Cidr[] = [
  cidr("0.0.0.0", 8, FAMILY_IPV4),
  cidr("10.0.0.0", 8, FAMILY_IPV4),
  cidr("100.64.0.0", 10, FAMILY_IPV4), // CGNAT
  cidr("127.0.0.0", 8, FAMILY_IPV4),
  cidr("169.254.0.0", 16, FAMILY_IPV4), // link-local
  cidr("172.16.0.0", 12, FAMILY_IPV4),
  cidr("192.0.0.0", 24, FAMILY_IPV4),
  cidr("192.0.2.0", 24, FAMILY_IPV4), // documentation
  cidr("192.168.0.0", 16, FAMILY_IPV4),
  cidr("198.18.0.0", 15, FAMILY_IPV4), // benchmarking
  cidr("198.51.100.0", 24, FAMILY_IPV4), // documentation
  cidr("203.0.113.0", 24, FAMILY_IPV4), // documentation
  cidr("224.0.0.0", 4, FAMILY_IPV4), // multicast
  cidr("240.0.0.0", 4, FAMILY_IPV4), // reserved
];

const PRIVATE_V6: Cidr[] = [
  cidr("::", 128, FAMILY_IPV6),
  cidr("::1", 128, FAMILY_IPV6),
  cidr("::ffff:0:0", 96, FAMILY_IPV6), // v4-mapped
  cidr("64:ff9b::", 96, FAMILY_IPV6), // NAT64
  cidr("100::", 64, FAMILY_IPV6),
  cidr("2001:db8::", 32, FAMILY_IPV6), // documentation
  cidr("fc00::", 7, FAMILY_IPV6), // ULA
  cidr("fe80::", 10, FAMILY_IPV6), // link-local
  cidr("ff00::", 8, FAMILY_IPV6), // multicast
];

export function isPrivateOrReserved(ip: IpAddress): boolean {
  const value = ipToBigInt(ip.addressBytes);
  const table = ip.family === FAMILY_IPV4 ? PRIVATE_V4 : PRIVATE_V6;
  for (const c of table) {
    if (((value ^ c.base) >> BigInt(c.bits - c.prefix)) === 0n) return true;
  }
  return false;
}

/**
 * Masks an IP to `prefixLen` bits and formats it as "a.b.c.d/prefix"
 * (IPv4) or "xxxx:xxxx:.../prefix" (IPv6, uncompressed) — the form used by
 * the `edns_client_subnet` query parameter of dns-json APIs.
 */
export function formatEcsPrefix(ip: IpAddress, prefixLen: number): string {
  const bits = ip.family === FAMILY_IPV4 ? 32 : 128;
  const prefix = Math.max(0, Math.min(prefixLen, bits));
  const bytes = Array.from(ip.addressBytes);
  const fullBytes = Math.floor(prefix / 8);
  const remBits = prefix % 8;
  for (let i = fullBytes; i < bytes.length; i++) bytes[i] = 0;
  if (remBits > 0 && fullBytes < bytes.length) {
    bytes[fullBytes] = (bytes[fullBytes] as number) & (0xff << (8 - remBits));
  }
  if (ip.family === FAMILY_IPV4) {
    return `${bytes.join(".")}/${prefix}`;
  }
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(((bytes[i] as number) << 8 | (bytes[i + 1] as number)).toString(16).padStart(4, "0"));
  }
  return `${groups.join(":")}/${prefix}`;
}
