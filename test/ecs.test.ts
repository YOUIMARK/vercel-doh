import { describe, expect, it } from "vitest";
import {
  addOrMergeEcs,
  buildEcsOption,
  hasMeaningfulEcs,
  parseClientIp,
} from "../src/dns/ecs";
import { parseHeader, parseSections, toView } from "../src/dns/wire";
import { buildOptRr, buildQuery } from "./helpers";

const IP_V4 = { family: 1 as const, addressBytes: new Uint8Array([1, 2, 3, 4]) };

function countOptRrs(msg: Uint8Array): number {
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

describe("hasMeaningfulEcs", () => {
  it("returns true when the OPT carries a non-zero-prefix ECS", () => {
    const ecsOption = buildEcsOption(IP_V4, 24);
    const msg = buildQuery({ additional: buildOptRr(ecsOption) });
    expect(hasMeaningfulEcs(msg)).toBe(true);
  });

  it("returns false when the OPT has no ECS or zero prefix", () => {
    const plainOpt = buildOptRr(new Uint8Array([0, 3, 0, 2, 65, 65])); // NSID "AA"
    expect(hasMeaningfulEcs(buildQuery({ additional: plainOpt }))).toBe(false);
    const zeroPrefix = buildEcsOption({ family: 1, addressBytes: new Uint8Array([1, 2, 3, 4]) }, 0);
    expect(hasMeaningfulEcs(buildQuery({ additional: buildOptRr(zeroPrefix) }))).toBe(false);
  });

  it("returns false when there is no OPT RR", () => {
    expect(hasMeaningfulEcs(buildQuery())).toBe(false);
  });
});

describe("addOrMergeEcs", () => {
  it("appends a single new OPT RR when none exists (ARCOUNT +1)", () => {
    const msg = buildQuery();
    const merged = addOrMergeEcs(msg, buildEcsOption(IP_V4, 24));
    const header = parseHeader(merged)!;
    expect(header.ar).toBe(1);
    expect(countOptRrs(merged)).toBe(1);
    expect(hasMeaningfulEcs(merged)).toBe(true);
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
    expect(countOptRrs(merged)).toBe(1);
    expect(hasMeaningfulEcs(merged)).toBe(true);

    // Original NSID option must still be present inside the same OPT RR.
    const sections = parseSections(merged)!;
    const opt = sections.additional.rrs.find((rr) => rr.rrType === 41)!;
    const view = toView(merged);
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
