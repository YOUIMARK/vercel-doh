// RFC 8467 response padding. We pad by adding an EDNS Padding option (code 12)
// into the response's existing OPT RR — the only RFC-correct way for a proxy
// that must not alter the answer section. Messages without an OPT RR are left
// untouched (adding one would change semantics).
//
// Strategy: Random-Block-Length Padding (RFC 8467 §4.2.3) — pick a block
// length at random from a small set, then pad to that block's multiple.
// For a given unpadded message this produces several possible padded sizes,
// defeating size-based traffic analysis better than fixed Block-Length
// padding, while (unlike pure Random-Length padding, §4.2.2, which the RFC
// does NOT recommend) keeping each message on a block boundary so the
// original length cannot be inferred from the observed length distribution.

import { parseSections, toView } from "./wire.js";

export const PADDING_OPTION_CODE = 12;
/** Base block size; every chosen block is a multiple of this (keeps idempotency). */
export const PADDING_BLOCK_SIZE = 128;
/** Block lengths randomly chosen from per RFC 8467 §4.2.3 ("a few block values"). */
export const PADDING_BLOCKS = [128, 256, 512] as const;

export type Rng = () => number;

/**
 * Pads `msg` to a random block multiple by inserting an EDNS padding option
 * into the existing OPT RR. Returns the original message when it is already
 * aligned, has no OPT RR, or is malformed.
 *
 * `rng` is injectable for tests (defaults to Math.random).
 */
export function padResponse(
  msg: Uint8Array<ArrayBuffer>,
  rng: Rng = Math.random,
): Uint8Array<ArrayBuffer> {
  // Already aligned to the base block → assume padded; adding more would
  // break idempotency (all chosen blocks are multiples of the base).
  if (msg.length % PADDING_BLOCK_SIZE === 0) return msg;
  const parsed = parseSections(msg);
  if (!parsed) return msg;
  const opt = parsed.additional.rrs.find((rr) => rr.rrType === 41);

  // Random-Block-Length Padding: choose a block, then pad to its multiple.
  const idx = Math.min(PADDING_BLOCKS.length - 1, Math.floor(rng() * PADDING_BLOCKS.length));
  const block = PADDING_BLOCKS[idx]!;
  // Option adds 4 header bytes + padLen; when no OPT RR exists we also append
  // an 11-byte OPT RR header, so the total added overhead differs.
  const overhead = opt ? 4 : 15; // 4 = option header; 15 = OPT RR header (11) + option header (4)
  // Solve (msg.length + overhead + padLen) ≡ 0 (mod block).
  const padLen = (block - ((msg.length + overhead) % block)) % block;

  const option = new Uint8Array(4 + padLen);
  const view = toView(option);
  view.setUint16(0, PADDING_OPTION_CODE);
  view.setUint16(2, padLen);
  // remaining bytes are zero padding

  if (!opt) {
    // No OPT RR in the response: append one carrying only the padding option
    // (mirrors the ECS append path; keeps padding applicable to every
    // response, not just EDNS-aware ones).
    const out = new Uint8Array(msg.length + 11 + option.length);
    out.set(msg, 0);
    let o = msg.length;
    out[o] = 0; // root name
    o += 1;
    const outView = toView(out);
    outView.setUint16(o, 41); // OPT
    outView.setUint16(o + 2, 4096); // UDP payload size
    outView.setUint32(o + 4, 0);
    outView.setUint16(o + 8, option.length);
    out.set(option, o + 10);
    outView.setUint16(10, parsed.header.ar + 1); // ARCOUNT + 1
    return out;
  }

  const rdataEnd = opt.rdataOffset + opt.rdLength;
  const out = new Uint8Array(msg.length + option.length);
  out.set(msg.subarray(0, rdataEnd), 0);
  out.set(option, rdataEnd);
  out.set(msg.subarray(rdataEnd), rdataEnd + option.length);
  const outView = toView(out);
  outView.setUint16(opt.rdataOffset - 2, opt.rdLength + option.length);
  return out;
}
