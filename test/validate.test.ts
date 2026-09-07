import { describe, expect, it } from "vitest";
import { countOptRrs } from "../src/dns/wire";
import { validateDnsResponse } from "../src/dns/validate";
import { buildOptRr, buildQuery, buildResponse, concat } from "./helpers";

describe("validateDnsResponse", () => {
  it("accepts a structurally valid response", () => {
    const query = buildQuery();
    const resp = buildResponse(query, { ttl: 300 });
    const result = validateDnsResponse(resp);
    expect(result).not.toBeNull();
    expect(result!.rcode).toBe(0);
  });

  it("accepts negative answers (NXDOMAIN with SOA)", () => {
    const resp = buildResponse(buildQuery(), { rcode: 3, answerCount: 0, authorityTtl: 900, soaMinimum: 60 });
    expect(validateDnsResponse(resp)!.rcode).toBe(3);
  });

  it("rejects messages shorter than 12 bytes", () => {
    expect(validateDnsResponse(new Uint8Array([0, 1, 2]))).toBeNull();
  });

  it("rejects messages without the QR bit set (not a response)", () => {
    const query = buildQuery(); // QR=0 query
    expect(validateDnsResponse(query)).toBeNull();
  });

  it("rejects non-standard opcodes", () => {
    const resp = buildResponse(buildQuery(), { ttl: 300 });
    const view = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);
    view.setUint16(2, view.getUint16(2) | (1 << 11)); // set OPCODE=1 (IQUERY)
    expect(validateDnsResponse(resp)).toBeNull();
  });

  it("rejects messages with trailing garbage", () => {
    const resp = buildResponse(buildQuery(), { ttl: 300 });
    const withGarbage = concat([resp, new Uint8Array([0xff, 0xfe, 0xfd])]);
    expect(validateDnsResponse(withGarbage)).toBeNull();
  });

  it("rejects truncated RR sections", () => {
    const resp = buildResponse(buildQuery(), { ttl: 300 });
    expect(validateDnsResponse(resp.subarray(0, resp.length - 2))).toBeNull();
  });
});

describe("countOptRrs (re-export sanity)", () => {
  it("counts OPT RRs", () => {
    expect(countOptRrs(buildQuery())).toBe(0);
    expect(countOptRrs(buildQuery({ additional: buildOptRr(new Uint8Array(0)) }))).toBe(1);
    expect(countOptRrs(buildQuery({ additional: concat([buildOptRr(new Uint8Array(0)), buildOptRr(new Uint8Array(0))]), ar: 2 }))).toBe(2);
  });
});
