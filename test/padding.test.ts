import { describe, expect, it } from "vitest";
import { PADDING_BLOCKS, padResponse } from "../src/dns/padding";
import { parseHeader, parseSections } from "../src/dns/wire";
import { buildOptRr, buildQuery, buildResponse } from "./helpers";

/** A response carrying an OPT RR; unpadded length 68 (< 128). */
function fixture() {
  const query = buildQuery({ additional: buildOptRr(new Uint8Array(0)) });
  return buildResponse(query, { ttl: 300, additional: buildOptRr(new Uint8Array(0)) });
}

describe("padResponse", () => {
  it("pads responses that carry an OPT RR to a block boundary", () => {
    const resp = fixture();
    const padded = padResponse(resp, () => 0); // block 128
    expect(padded.length % 128).toBe(0);
    expect(padded.length).toBeGreaterThan(resp.length);
    // Still exactly one OPT RR, ARCOUNT unchanged.
    const header = parseHeader(padded)!;
    expect(header.ar).toBe(1);
    const sections = parseSections(padded)!;
    expect(sections.additional.rrs.filter((rr) => rr.rrType === 41)).toHaveLength(1);
  });

  it("is idempotent on already-padded messages", () => {
    const resp = fixture();
    const once = padResponse(resp, () => 0);
    const twice = padResponse(once, () => 0);
    expect(twice.length % 128).toBe(0);
    expect(twice).toEqual(once);
  });

  it("randomizes the block length (RFC 8467 §4.2.3 Random-Block-Length)", () => {
    const resp = fixture();
    // rng 0 → first block (128); 0.49 → middle (256); 0.99 → last (512).
    expect(padResponse(resp, () => 0).length).toBe(128);
    expect(padResponse(resp, () => 0.49).length).toBe(256);
    expect(padResponse(resp, () => 0.99).length).toBe(512);
    // Every output stays on a base-128 boundary regardless of the chosen block.
    for (const rng of [() => 0, () => 0.25, () => 0.5, () => 0.75, () => 0.99]) {
      expect(padResponse(resp, rng).length % 128).toBe(0);
    }
    // The same message yields several distinct sizes across draws.
    const sizes = new Set(Array.from({ length: 60 }, (_, i) => padResponse(resp, () => i / 60).length));
    expect(sizes.size).toBeGreaterThan(1);
    expect(PADDING_BLOCKS).toContain(128);
  });

  it("appends an OPT RR and pads responses that lack one", () => {
    const resp = buildResponse(buildQuery(), { ttl: 300 }); // no OPT RR
    const padded = padResponse(resp, () => 0);
    expect(padded.length % 128).toBe(0);
    expect(padded.length).toBeGreaterThan(resp.length);
    const header = parseHeader(padded)!;
    expect(header.ar).toBe(1); // OPT appended
    const sections = parseSections(padded)!;
    const opts = sections.additional.rrs.filter((rr) => rr.rrType === 41);
    expect(opts).toHaveLength(1);
    expect(opts[0]!.rdLength).toBeGreaterThan(0); // carries the padding option
  });

  it("leaves malformed messages unchanged", () => {
    const bad = new Uint8Array([0, 1, 2]);
    expect(padResponse(bad)).toBe(bad);
  });
});
