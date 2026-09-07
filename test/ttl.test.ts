import { describe, expect, it } from "vitest";
import { minAnswerTtl, soaNegativeTtl } from "../src/dns/ttl";
import { parseSections } from "../src/dns/wire";
import { buildQuery, buildResponse, buildSoaRdata } from "./helpers";

describe("minAnswerTtl", () => {
  it("returns the answer TTL", () => {
    const query = buildQuery();
    const resp = buildResponse(query, { ttl: 300 });
    expect(minAnswerTtl(resp)).toBe(300);
  });

  it("returns null when there are no answers", () => {
    const resp = buildResponse(buildQuery(), { answerCount: 0 });
    expect(minAnswerTtl(resp)).toBeNull();
  });

  it("returns null for malformed messages", () => {
    expect(minAnswerTtl(new Uint8Array([1, 2, 3]))).toBeNull();
  });
});

describe("soaNegativeTtl (RFC 2308: min(SOA TTL, SOA.MINIMUM))", () => {
  it("caps by SOA.MINIMUM when the SOA TTL is larger", () => {
    const query = buildQuery();
    // SOA TTL 3600, MINIMUM 60 → negative TTL 60.
    const resp = buildResponse(query, {
      rcode: 3,
      answerCount: 0,
      authorityTtl: 3600,
      soaMinimum: 60,
    });
    expect(soaNegativeTtl(resp)).toBe(60);
  });

  it("uses the SOA TTL when it is smaller than MINIMUM", () => {
    const resp = buildResponse(buildQuery(), {
      rcode: 3,
      answerCount: 0,
      authorityTtl: 30,
      soaMinimum: 3600,
    });
    expect(soaNegativeTtl(resp)).toBe(30);
  });

  it("reads MINIMUM from an explicit SOA RDATA", () => {
    const resp = buildResponse(buildQuery(), {
      rcode: 3,
      answerCount: 0,
      authorityTtl: 900,
      authorityRdata: buildSoaRdata(
        "ns1.example.com.",
        "hostmaster.example.com.",
        1, 7200, 900, 1209600, 42,
      ),
    });
    expect(soaNegativeTtl(resp)).toBe(42);
  });

  it("returns null when there is no SOA in authority", () => {
    const resp = buildResponse(buildQuery(), { rcode: 3, answerCount: 0 });
    expect(soaNegativeTtl(resp)).toBeNull();
  });

  it("parses SOA with COMPRESSED MNAME/RNAME (realistic wire, RFC 1035 §4.1.4)", () => {
    // NXDOMAIN response whose SOA RDATA names are pointers back to the
    // question name (offset 12) — as real resolvers may emit.
    const query = buildQuery();
    const sections = parseSections(query)!;
    const question = query.subarray(12, sections.questionEnd);
    const soaRdata = new Uint8Array(2 + 2 + 20); // MNAME ptr + RNAME ptr + 5×uint32
    const rview = new DataView(soaRdata.buffer);
    soaRdata[0] = 0xc0; soaRdata[1] = 0x0c; // MNAME → question name
    soaRdata[2] = 0xc0; soaRdata[3] = 0x0c; // RNAME → question name
    rview.setUint32(4, 2024010101); // SERIAL
    rview.setUint32(8, 7200); // REFRESH
    rview.setUint32(12, 900); // RETRY
    rview.setUint32(16, 1209600); // EXPIRE
    rview.setUint32(20, 42); // MINIMUM

    const rr = new Uint8Array(2 + 10 + soaRdata.length);
    rr[0] = 0xc0; rr[1] = 0x0c; // owner name → question name
    const rrv = new DataView(rr.buffer);
    rrv.setUint16(2, 6); // SOA
    rrv.setUint16(4, 1);
    rrv.setUint32(6, 900); // SOA RR TTL
    rrv.setUint16(10, soaRdata.length);
    rr.set(soaRdata, 12);

    const resp = new Uint8Array(12 + question.length + rr.length);
    resp.set(query.subarray(0, 12), 0);
    resp.set(question, 12);
    resp.set(rr, 12 + question.length);
    const view = new DataView(resp.buffer);
    view.setUint16(2, 0x8000 | 0x0080 | 0x0003); // QR | RA | RCODE=3 (NXDOMAIN)
    view.setUint16(8, 1); // NSCOUNT = 1

    expect(soaNegativeTtl(resp)).toBe(42); // min(SOA TTL 900, MINIMUM 42)
  });
});
