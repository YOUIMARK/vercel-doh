import { describe, expect, it } from "vitest";
import { padResponse } from "../src/dns/padding";
import { parseHeader, parseSections } from "../src/dns/wire";
import { buildOptRr, buildQuery, buildResponse } from "./helpers";

describe("padResponse", () => {
  it("pads responses that carry an OPT RR to a 128-byte boundary", () => {
    const query = buildQuery({ additional: buildOptRr(new Uint8Array(0)) });
    const resp = buildResponse(query, { ttl: 300, additional: buildOptRr(new Uint8Array(0)) });
    const padded = padResponse(resp);
    expect(padded.length % 128).toBe(0);
    expect(padded.length).toBeGreaterThan(resp.length);
    // Still exactly one OPT RR, ARCOUNT unchanged.
    const header = parseHeader(padded)!;
    expect(header.ar).toBe(1);
    const sections = parseSections(padded)!;
    expect(sections.additional.rrs.filter((rr) => rr.rrType === 41)).toHaveLength(1);
  });

  it("is idempotent on already-padded messages", () => {
    const query = buildQuery({ additional: buildOptRr(new Uint8Array(0)) });
    const resp = buildResponse(query, { ttl: 300, additional: buildOptRr(new Uint8Array(0)) });
    const once = padResponse(resp);
    const twice = padResponse(once);
    expect(twice.length % 128).toBe(0);
    expect(twice).toEqual(once);
  });

  it("leaves messages without an OPT RR unchanged", () => {
    const resp = buildResponse(buildQuery(), { ttl: 300 });
    expect(padResponse(resp)).toBe(resp);
  });

  it("leaves malformed messages unchanged", () => {
    const bad = new Uint8Array([0, 1, 2]);
    expect(padResponse(bad)).toBe(bad);
  });
});
