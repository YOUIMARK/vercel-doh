import { describe, expect, it } from "vitest";
import { countOptRrs } from "../src/dns/wire";
import { validateDnsResponse } from "../src/dns/validate";
import { buildOptRr, buildOptRrWithTtl, buildQuestion, buildQuery, buildResponse, concat } from "./helpers";

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

  it("rejects duplicate OPT RRs (RFC 6891)", () => {
    const resp = buildResponse(buildQuery(), {
      ttl: 300,
      additional: concat([buildOptRr(new Uint8Array(0)), buildOptRr(new Uint8Array(0))]),
    });
    const view = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);
    view.setUint16(10, 2); // ARCOUNT = 2
    expect(validateDnsResponse(resp)).toBeNull();
  });

  it("rejects an OPT RR whose owner name is not root (RFC 6891 §6.1.2)", () => {
    const resp = buildResponse(buildQuery(), { ttl: 300 });
    // Append a non-root-owner OPT RR manually: name "x" (3 bytes) + fixed 10.
    const badOpt = new Uint8Array(3 + 10);
    badOpt[0] = 3; // label length
    badOpt[1] = 0x78; // "x"
    badOpt[2] = 0; // root terminator
    const view = new DataView(badOpt.buffer, badOpt.byteOffset, badOpt.byteLength);
    view.setUint16(3, 41); // OPT
    view.setUint16(5, 4096);
    view.setUint32(7, 0);
    view.setUint16(11, 0); // RDLENGTH
    const withBadOpt = concat([resp, badOpt]);
    new DataView(withBadOpt.buffer, withBadOpt.byteOffset, withBadOpt.byteLength).setUint16(10, 1);
    expect(validateDnsResponse(withBadOpt)).toBeNull();
  });

  it("rejects an A answer whose RDATA length is wrong", () => {
    const resp = buildResponse(buildQuery(), { ttl: 300, answerRdata: new Uint8Array([1, 2]) });
    expect(validateDnsResponse(resp)).toBeNull();
  });

  it("returns the extended RCODE (BADVERS = 16)", () => {
    const resp = buildResponse(buildQuery(), { ttl: 300, additional: buildOptRrWithTtl(0x01000000) });
    expect(validateDnsResponse(resp)!.rcode).toBe(16);
  });
});

describe("validateDnsResponse with the request message", () => {
  it("accepts a response echoing the request ID + question", () => {
    const query = buildQuery({ id: 0xbeef });
    expect(validateDnsResponse(buildResponse(query, { ttl: 300 }), query)).not.toBeNull();
  });

  it("rejects a response with a mismatched ID", () => {
    const query = buildQuery({ id: 0xbeef });
    const resp = buildResponse(buildQuery({ id: 0x1234 }), { ttl: 300 });
    expect(validateDnsResponse(resp, query)).toBeNull();
  });

  it("rejects a response with a mismatched question", () => {
    const query = buildQuery();
    const resp = buildResponse(buildQuery({ question: buildQuestion("evil.example") }), { ttl: 300 });
    expect(validateDnsResponse(resp, query)).toBeNull();
  });

  it("rejects a response for a different QTYPE", () => {
    const query = buildQuery();
    const resp = buildResponse(buildQuery({ question: buildQuestion("example.com", 28) }), { ttl: 300 });
    expect(validateDnsResponse(resp, query)).toBeNull();
  });
});

describe("countOptRrs (re-export sanity)", () => {
  it("counts OPT RRs", () => {
    expect(countOptRrs(buildQuery())).toBe(0);
    expect(countOptRrs(buildQuery({ additional: buildOptRr(new Uint8Array(0)) }))).toBe(1);
    expect(countOptRrs(buildQuery({ additional: concat([buildOptRr(new Uint8Array(0)), buildOptRr(new Uint8Array(0))]), ar: 2 }))).toBe(2);
  });
});
