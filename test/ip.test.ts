import { describe, expect, it } from "vitest";
import { isPrivateOrReserved, parseIp, parseIpv4, parseIpv6 } from "../src/dns/ip";

describe("parseIpv4", () => {
  it("parses valid addresses", () => {
    expect(parseIpv4("8.8.8.8")!.addressBytes).toEqual(new Uint8Array([8, 8, 8, 8]));
    expect(parseIpv4("1.2.3.4")!.addressBytes).toEqual(new Uint8Array([1, 2, 3, 4]));
    expect(parseIpv4("255.255.255.255")!.addressBytes).toEqual(new Uint8Array([255, 255, 255, 255]));
  });

  it("rejects invalid input", () => {
    for (const bad of ["", "1.2.3", "1.2.3.4.5", "1.2.3.256", "a.b.c.d", "1.2.3.4.5.6"]) {
      expect(parseIpv4(bad), bad).toBeNull();
    }
  });
});

describe("parseIpv6", () => {
  it("parses full and compressed forms", () => {
    expect(parseIpv6("::1")!.addressBytes).toEqual(
      new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
    );
    const g = parseIpv6("2001:db8::1")!.addressBytes;
    expect(g[0]).toBe(0x20);
    expect(g[1]).toBe(0x01);
    expect(g[15]).toBe(0x01);
    const fe80 = parseIpv6("fe80::1")!.addressBytes;
    expect(fe80[0]).toBe(0xfe);
    expect(fe80[1]).toBe(0x80);
  });

  it("rejects invalid input", () => {
    for (const bad of ["", ":::", "1:2:3:4:5:6:7:8:9", "zz::", "1::2::3"]) {
      expect(parseIpv6(bad), bad).toBeNull();
    }
  });
});

describe("parseIp dispatch", () => {
  it("routes by colon presence", () => {
    expect(parseIp("1.2.3.4")!.family).toBe(1);
    expect(parseIp("2001:db8::1")!.family).toBe(2);
    expect(parseIp("  ")).toBeNull();
    expect(parseIp("")).toBeNull();
  });
});

describe("isPrivateOrReserved", () => {
  it("flags private/reserved addresses", () => {
    for (const ip of ["10.0.0.1", "127.0.0.1", "169.254.1.1", "172.16.5.5", "192.168.1.1", "0.0.0.0", "224.0.0.1", "100.64.0.1"]) {
      expect(isPrivateOrReserved(parseIp(ip)!), ip).toBe(true);
    }
    for (const ip of ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"]) {
      expect(isPrivateOrReserved(parseIp(ip)!), ip).toBe(false);
    }
  });

  it("flags private/reserved IPv6", () => {
    expect(isPrivateOrReserved(parseIp("::1")!)).toBe(true);
    expect(isPrivateOrReserved(parseIp("fc00::1")!)).toBe(true);
    expect(isPrivateOrReserved(parseIp("fe80::1")!)).toBe(true);
    expect(isPrivateOrReserved(parseIp("::ffff:1.2.3.4")!)).toBe(true);
    expect(isPrivateOrReserved(parseIp("2001:db8::1")!)).toBe(true);
    expect(isPrivateOrReserved(parseIp("2001:4860:4860::8888")!)).toBe(false);
    expect(isPrivateOrReserved(parseIp("2606:4700:4700::1111")!)).toBe(false);
  });
});
