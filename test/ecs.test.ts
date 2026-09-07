import { describe, expect, it } from "vitest";
import {
  addOrMergeEcs,
  buildEcsOption,
  ecsStatus,
  parseClientIp,
} from "../src/dns/ecs";
import { countOptRrs, parseHeader, parseSections } from "../src/dns/wire";
import { buildOptRr, buildQuery, concat } from "./helpers";

const IP_V4 = { family: 1 as const, addressBytes: new Uint8Array([1, 2, 3, 4]) };

function countOptRrsIn(msg: Uint8Array): number {
  const sections = parseSections(msg);
  if (!sections) return -1;
  return sections.additional.rrs.filter((rr) => rr.rrType === 41).length;
}

describe("buildEcsOption", () => {
  it("builds a v4 /24 ECS option", () => {
    const opt = buildEcsOption(IP_V4, 24);
    // code(2)=8, len(2)=7, family(2)=1, source(1)=24, scope(1)=0, addr(3)=1.2.3
    expect(Array.from(opt)).toEqual([0, 8, 0, 7, 0, 1, 24, 0, 1, 2, 3]);
  });

  it("clamps prefix length", () => {
    expect(buildEcsOption(IP_V4, 40).length).toBe(4 + 4 + 4); // clamped to /32
    expect(buildEcsOption(IP_V4, 0).length).toBe(4 + 4 + 0);
  });
});

describe("ecsStatus", () => {
  it("returns absent when there is no OPT RR or no ECS", () => {
    expect(ecsStatus(buildQuery())).toBe("absent");
    const nsidOpt = buildOptRr(new Uint8Array([0, 3, 0, 2, 65, 65])); // NSID "AA"
    expect(ecsStatus(buildQuery({ additional: nsidOpt }))).toBe("absent");
  });

  it("returns positive for a non-zero-prefix ECS", () => {
    const msg = buildQuery({ additional: buildOptRr(buildEcsOption(IP_V4, 24)) });
    expect(ecsStatus(msg)).toBe("positive");
  });

  it("returns zero for ECS source prefix 0 (client opts out — must NOT inject)", () => {
    const zeroEcs = buildEcsOption({ family: 1, addressBytes: new Uint8Array([1, 2, 3, 4]) }, 0);
    expect(ecsStatus(buildQuery({ additional: buildOptRr(zeroEcs) }))).toBe("zero");
  });

  it("returns malformed for truncated / over-long ECS options", () => {
    // Valid /24 option is 11 bytes; truncate the address to 2 bytes.
    const truncated = new Uint8Array([0, 8, 0, 6, 0, 1, 24, 0, 1, 2]);
    expect(ecsStatus(buildQuery({ additional: buildOptRr(truncated) }))).toBe("malformed");
    // Valid /24 option is 11 bytes; pad the address to 4 bytes.
    const overlong = new Uint8Array([0, 8, 0, 8, 0, 1, 24, 0, 1, 2, 3, 4]);
    expect(ecsStatus(buildQuery({ additional: buildOptRr(overlong) }))).toBe("malformed");
  });

  it("returns malformed for invalid family or oversized prefix", () => {
    const badFamily = new Uint8Array([0, 8, 0, 7, 0, 9, 24, 0, 1, 2, 3]); // family 9
    expect(ecsStatus(buildQuery({ additional: buildOptRr(badFamily) }))).toBe("malformed");
    const badPrefix = new Uint8Array([0, 8, 0, 8, 0, 1, 40, 0, 1, 2, 3, 4]); // /40 > /32
    expect(ecsStatus(buildQuery({ additional: buildOptRr(badPrefix) }))).toBe("malformed");
  });

  it("returns malformed for duplicate ECS options", () => {
    const two = concat([
      buildEcsOption(IP_V4, 24),
      buildEcsOption(IP_V4, 16),
    ]);
    expect(ecsStatus(buildQuery({ additional: buildOptRr(two) }))).toBe("malformed");
  });

  it("returns malformed when the message carries multiple OPT RRs", () => {
    const msg = buildQuery({ additional: concat([buildOptRr(new Uint8Array(0)), buildOptRr(new Uint8Array(0))]), ar: 2 });
    expect(countOptRrs(msg)).toBe(2);
    expect(ecsStatus(msg)).toBe("malformed");
  });
});

describe("countOptRrs", () => {
  it("counts OPT RRs in the additional section", () => {
    expect(countOptRrs(buildQuery())).toBe(0);
    expect(countOptRrs(buildQuery({ additional: buildOptRr(new Uint8Array(0)) }))).toBe(1);
    const two = concat([buildOptRr(new Uint8Array(0)), buildOptRr(new Uint8Array(0))]);
    expect(countOptRrs(buildQuery({ additional: two, ar: 2 }))).toBe(2);
  });
});

describe("addOrMergeEcs", () => {
  it("appends a single new OPT RR when none exists (ARCOUNT +1)", () => {
    const msg = buildQuery();
    const merged = addOrMergeEcs(msg, buildEcsOption(IP_V4, 24));
    const header = parseHeader(merged)!;
    expect(header.ar).toBe(1);
    expect(countOptRrsIn(merged)).toBe(1);
    expect(ecsStatus(merged)).toBe("positive");
  });

  it("merges into the existing OPT RR without adding a second one", () => {
    const nsidOpt = buildOptRr(new Uint8Array([0, 3, 0, 2, 65, 65])); // NSID "AA"
    const msg = buildQuery({ additional: nsidOpt });
    const before = parseHeader(msg)!;
    expect(before.ar).toBe(1);

    const merged = addOrMergeEcs(msg, buildEcsOption(IP_V4, 24));
    const after = parseHeader(merged)!;
    // CRITICAL: exactly one OPT RR, ARCOUNT unchanged.
    expect(after.ar).toBe(1);
    expect(countOptRrsIn(merged)).toBe(1);
    expect(ecsStatus(merged)).toBe("positive");

    // Original NSID option must still be present inside the same OPT RR.
    const sections = parseSections(merged)!;
    const opt = sections.additional.rrs.find((rr) => rr.rrType === 41)!;
    const view = new DataView(merged.buffer, merged.byteOffset, merged.byteLength);
    let o = opt.rdataOffset;
    const end = opt.rdataOffset + opt.rdLength;
    const codes: number[] = [];
    while (o + 4 <= end) {
      codes.push(view.getUint16(o));
      o += 4 + view.getUint16(o + 2);
    }
    expect(codes).toContain(3); // NSID
    expect(codes).toContain(8); // ECS
  });

  it("returns the original message on malformed input", () => {
    const truncated = new Uint8Array([0, 0]); // too short
    expect(addOrMergeEcs(truncated, buildEcsOption(IP_V4, 24))).toBe(truncated);
  });
});

describe("parseClientIp", () => {
  it("prefers x-vercel-forwarded-for (trusted)", () => {
    const headers = new Headers({
      "x-vercel-forwarded-for": "8.8.8.8",
      "x-forwarded-for": "6.6.6.6",
    });
    const ip = parseClientIp(headers)!;
    expect(Array.from(ip.addressBytes)).toEqual([8, 8, 8, 8]);
  });

  it("takes the rightmost public entry of x-forwarded-for (spoof-resistant)", () => {
    // Attacker sets leftmost; Vercel appends the real IP at the right.
    const headers = new Headers({ "x-forwarded-for": "6.6.6.6, 8.8.8.8" });
    const ip = parseClientIp(headers)!;
    expect(Array.from(ip.addressBytes)).toEqual([8, 8, 8, 8]);
  });

  it("skips private entries when scanning", () => {
    const headers = new Headers({ "x-forwarded-for": "10.0.0.1, 192.168.1.1, 9.9.9.9" });
    const ip = parseClientIp(headers)!;
    expect(Array.from(ip.addressBytes)).toEqual([9, 9, 9, 9]);
  });

  it("returns null when nothing usable", () => {
    expect(parseClientIp(new Headers())).toBeNull();
    expect(parseClientIp(new Headers({ "x-forwarded-for": "10.0.0.1, ::1" }))).toBeNull();
  });

  it("parses IPv6", () => {
    const headers = new Headers({ "x-vercel-forwarded-for": "2001:4860:4860::8888" });
    const ip = parseClientIp(headers)!;
    expect(ip.family).toBe(2);
    expect(ip.addressBytes[0]).toBe(0x20);
  });
});
