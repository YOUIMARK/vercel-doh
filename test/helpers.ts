// Test helpers: DNS message builders for wire/ecs/ttl/routes tests.

import { parseSections, toView } from "../src/dns/wire";

/** Encodes a domain name into DNS label format (no compression). */
export function dnsName(name: string): Uint8Array<ArrayBuffer> {
  const parts = name.split(".");
  let len = 1; // terminating zero
  for (const p of parts) len += 1 + p.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out[o] = p.length;
    o += 1;
    for (let i = 0; i < p.length; i++) out[o + i] = p.charCodeAt(i);
    o += p.length;
  }
  out[o] = 0;
  return out;
}

/** Builds a question section (name + QTYPE + QCLASS). */
export function buildQuestion(name: string, qtype = 1, qclass = 1): Uint8Array<ArrayBuffer> {
  const n = dnsName(name);
  const out = new Uint8Array(n.length + 4);
  out.set(n, 0);
  const view = toView(out);
  view.setUint16(n.length, qtype);
  view.setUint16(n.length + 2, qclass);
  return out;
}

export interface QueryOptions {
  id?: number;
  rd?: boolean;
  qd?: number;
  question?: Uint8Array<ArrayBuffer>;
  additional?: Uint8Array<ArrayBuffer>;
}

/** Builds a DNS query message. */
export function buildQuery(opts: QueryOptions = {}): Uint8Array<ArrayBuffer> {
  const question = opts.question ?? buildQuestion("example.com", 1, 1);
  const additional = opts.additional ?? new Uint8Array(0);
  const ar = opts.additional ? 1 : 0;
  const out = new Uint8Array(12 + question.length + additional.length);
  const view = toView(out);
  view.setUint16(0, opts.id ?? 0x1234);
  view.setUint16(2, opts.rd === false ? 0 : 0x0100);
  view.setUint16(4, opts.qd ?? 1);
  view.setUint16(6, 0);
  view.setUint16(8, 0);
  view.setUint16(10, ar);
  out.set(question, 12);
  out.set(additional, 12 + question.length);
  return out;
}

/** Builds an OPT RR (type 41) with the given option bytes. */
export function buildOptRr(optionBytes: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(11 + optionBytes.length);
  const view = toView(out);
  out[0] = 0; // root name
  view.setUint16(1, 41); // OPT
  view.setUint16(3, 4096); // UDP payload
  view.setUint32(5, 0); // TTL
  view.setUint16(9, optionBytes.length);
  out.set(optionBytes, 11);
  return out;
}

/** Builds a minimal RR (compressed name pointer 0xC00C). */
export function buildRR(rrType: number, ttl: number, rdata: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(2 + 2 + 2 + 4 + 2 + rdata.length);
  const view = toView(out);
  out[0] = 0xc0;
  out[1] = 0x0c;
  view.setUint16(2, rrType);
  view.setUint16(4, 1); // IN
  view.setUint32(6, ttl);
  view.setUint16(10, rdata.length);
  out.set(rdata, 12);
  return out;
}

export interface ResponseOptions {
  rcode?: number;
  ttl?: number;
  authorityTtl?: number;
  answerCount?: number;
  answerRdata?: Uint8Array<ArrayBuffer>;
  authorityRdata?: Uint8Array<ArrayBuffer>;
  /** Additional section bytes (e.g. an OPT RR) appended after authority. */
  additional?: Uint8Array<ArrayBuffer>;
}

/** Builds a DNS response that echoes the query's question section. */
export function buildResponse(query: Uint8Array<ArrayBuffer>, opts: ResponseOptions = {}): Uint8Array<ArrayBuffer> {
  const sections = parseSections(query);
  if (!sections) throw new Error("query must be parseable");
  const header = sections.header;
  const question = query.subarray(12, sections.questionEnd);

  const answerCount = opts.answerCount ?? 1;
  const an: Uint8Array<ArrayBuffer>[] = [];
  for (let i = 0; i < answerCount; i++) {
    an.push(buildRR(1, opts.ttl ?? 300, opts.answerRdata ?? new Uint8Array([1, 2, 3, 4])));
  }
  const ns: Uint8Array<ArrayBuffer>[] = [];
  if (opts.authorityTtl !== undefined) {
    ns.push(buildRR(6 /* SOA */, opts.authorityTtl, opts.authorityRdata ?? new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])));
  }
  const additional = opts.additional ?? new Uint8Array(0);

  const answerBytes = concat(an);
  const authorityBytes = concat(ns);
  const out = new Uint8Array(12 + question.length + answerBytes.length + authorityBytes.length + additional.length);
  const view = toView(out);
  view.setUint16(0, header.id);
  const flags = 0x8000 | 0x0080 | (header.flags & 0x0100) | ((opts.rcode ?? 0) & 0x0f);
  view.setUint16(2, flags);
  view.setUint16(4, header.qd);
  view.setUint16(6, answerCount);
  view.setUint16(8, ns.length);
  view.setUint16(10, additional.length > 0 ? 1 : 0);
  out.set(question, 12);
  out.set(answerBytes, 12 + question.length);
  out.set(authorityBytes, 12 + question.length + answerBytes.length);
  out.set(additional, 12 + question.length + answerBytes.length + authorityBytes.length);
  return out;
}

export function concat(chunks: Uint8Array<ArrayBuffer>[]): Uint8Array<ArrayBuffer> {
  const total = chunks.reduce((acc, c) => acc + c.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return out;
}
