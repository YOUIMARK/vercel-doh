import { describe, expect, it } from "vitest";
import {
  buildErrorResponse,
  decodeBase64Url,
  encodeBase64Url,
  parseHeader,
  parseSections,
  rcodeOf,
  skipName,
  toView,
} from "../src/dns/wire";
import { buildQuestion, buildQuery, buildResponse, dnsName } from "./helpers";

// RFC 8484 §4.1 canonical example query for www.example.com (A).
const RFC8484_EXAMPLE = "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB";

describe("base64url", () => {
  it("round-trips", () => {
    const buf = new Uint8Array([0xfb, 0xff, 0x00, 0x01, 0x7f, 0x80, 0xfe]);
    expect(decodeBase64Url(encodeBase64Url(buf))).toEqual(buf);
  });

  it("decodes the RFC 8484 example", () => {
    const decoded = decodeBase64Url(RFC8484_EXAMPLE);
    expect(decoded).not.toBeNull();
    expect(decoded!.length).toBe(33);
    const header = parseHeader(decoded!);
    expect(header).toEqual({ id: 0, flags: 0x0100, qd: 1, an: 0, ns: 0, ar: 0 });
  });

  it("rejects invalid input", () => {
    expect(decodeBase64Url("!!!not-base64!!!")).toBeNull();
  });
});

describe("header / sections", () => {
  it("parses header counts", () => {
    const q = buildQuery({ id: 0xbeef, rd: true });
    const header = parseHeader(q);
    expect(header!.id).toBe(0xbeef);
    expect(header!.qd).toBe(1);
    expect(rcodeOf(header!.flags)).toBe(0);
  });

  it("skipName walks labels", () => {
    const name = dnsName("a.b.example.com");
    const view = toView(name);
    expect(skipName(view, 0)).toBe(name.length);
  });

  it("skipName follows a compression pointer", () => {
    // header + question("www.example.com") + answer RR with name pointer 0xC00C
    const question = buildQuestion("www.example.com");
    const msg = buildQuery({ question });
    const sections = parseSections(msg);
    expect(sections).not.toBeNull();
    // The pointer target offset (12) must be skipped by a 2-byte pointer.
    const answer = new Uint8Array(2 + 10 + 4);
    answer[0] = 0xc0;
    answer[1] = 0x0c;
    const view = toView(answer);
    view.setUint16(2, 1);
    view.setUint16(4, 1);
    view.setUint32(6, 300);
    view.setUint16(10, 4);
    answer.set([1, 2, 3, 4], 12);
    expect(skipName(toView(answer), 0)).toBe(2);
  });

  it("parseSections returns -1-safe nulls on truncation", () => {
    const q = buildQuery();
    expect(parseSections(q.subarray(0, 10))).toBeNull();
  });
});

describe("buildErrorResponse", () => {
  it("echoes id + question with SERVFAIL rcode", () => {
    const query = buildQuery({ id: 0x2222 });
    const err = buildErrorResponse(query, 2);
    const header = parseHeader(err);
    expect(header!.id).toBe(0x2222);
    expect(rcodeOf(header!.flags)).toBe(2);
    expect(header!.qd).toBe(1);
    expect((header!.flags & 0x8000) !== 0).toBe(true); // QR set
    const sections = parseSections(err);
    expect(sections!.questionEnd - 12).toBeGreaterThan(0);
  });
});

describe("scanRRs", () => {
  it("extracts RR metadata across sections", () => {
    const query = buildQuery();
    const resp = buildResponse(query, { ttl: 120 });
    const sections = parseSections(resp);
    expect(sections!.answers.rrs).toHaveLength(1);
    expect(sections!.answers.rrs[0]!.ttl).toBe(120);
    expect(sections!.answers.rrs[0]!.rrType).toBe(1);
    expect(sections!.answers.rrs[0]!.rdLength).toBe(4);
  });
});
